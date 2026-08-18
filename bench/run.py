"""Benchmark runner: drive one model through a sampled slice of the graded corpus.

Reuses the `agent` CLI rather than importing the state graph, so the benchmark
exercises exactly what a demo run exercises. Each (alert, repeat) gets its own
reports directory, so the exported JSON is unambiguous without parsing stdout.

Usage:
    python -m bench.run --model gemma4:12b --stage screen
    python -m bench.run --model gemma4:12b --stage deep

See docs/superpowers/specs/2026-08-14-local-model-selection-benchmark-design.md §4, §5.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import time
from pathlib import Path

from bench.labels import Role, label_for
from bench.stage0 import CONTEXT_TOKENS, bench_variant, footprint_bytes

SNAPSHOT = Path("./data/bench_alerts.db")
RESULTS = Path("./bench/results")

#: Stage 1 screens breadth-first to kill non-viable models cheaply; stage 2 spends its
#: budget where the metrics actually separate models.
#:
#: Needles get one run each, not three. The 14 Aug control verification returned 6 of 6
#: needles correct on the incumbent — detection saturates, because the needles are built
#: to be findable, so repeating them buys precision on a metric that cannot discriminate.
#: The earlier 3-repeat allocation spent a third of the expensive stage there.
#:
#: The benign floods get that budget instead: 15 per cluster rather than 10, taking the
#: escalation-rate confidence interval from roughly ±9% to ±7%. Benign escalation is the
#: metric that separates candidates, and it is the talk's subject.
#:
#: fp_control keeps three repeats. mrahman came back `low` on both control runs after
#: PR #4's grounded correlation — it stopped being a known failure and became a real
#: discriminator, so its stability is now worth measuring.
STAGE_PLAN = {
    "screen": {"benign_per_cluster": 1, "needle_repeats": 1, "fp_repeats": 1, "benign_repeats": 1},
    "deep": {"benign_per_cluster": 15, "needle_repeats": 1, "fp_repeats": 3, "benign_repeats": 1},
}


def select_alerts(db: Path, stage: str) -> list[tuple[str, str, Role, int]]:
    """Return (alert_id, cluster, role, repeats), deterministically ordered.

    Deterministic selection matters more than representative sampling: every model
    must be handed the identical slice or the comparison is not like-for-like.
    """
    plan = STAGE_PLAN[stage]
    rows = sqlite3.connect(db).execute(
        "SELECT alert_id, rule_id, rule_description, source_ip FROM alerts ORDER BY alert_id"
    ).fetchall()

    selected: list[tuple[str, str, Role, int]] = []
    benign_taken: dict[str, int] = {}
    for alert_id, rule_id, desc, src_ip in rows:
        label = label_for(rule_id, desc, src_ip)
        if label is None:
            continue
        if label.role is Role.BENIGN:
            if benign_taken.get(label.cluster, 0) >= plan["benign_per_cluster"]:
                continue
            benign_taken[label.cluster] = benign_taken.get(label.cluster, 0) + 1
            selected.append((alert_id, label.cluster, label.role, plan["benign_repeats"]))
        elif label.role is Role.FP_CONTROL:
            selected.append((alert_id, label.cluster, label.role, plan["fp_repeats"]))
        else:
            selected.append((alert_id, label.cluster, label.role, plan["needle_repeats"]))
    return selected


def loaded_model_bytes(model: str) -> int | None:
    """Resident size of `model`, per `ollama ps`.

    Delegates to the gate's parser rather than keeping a second copy. The duplicate
    that lived here read a fixed offset back from the end of the line and landed on
    "minutes", so every run recorded a footprint of zero — caught by scoring the
    control run before the sweep rather than after it.
    """
    measured = footprint_bytes(model)
    return measured[0] if measured else None


def run_one(model: str, alert_id: str, workdir: Path, repeat: int, effort: str | None) -> dict:
    reports = workdir / "reports" / alert_id / str(repeat)
    reports.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "LLM_MODEL": model,
        "DATABASE_PATH": str(workdir / "alerts.db"),
        "REPORTS_DIR": str(reports),
        # Unset means "leave the model on its own default", which is what an
        # unconfigured deployment does — so it has to be a real absence, not "".
        **({"LLM_REASONING_EFFORT": effort} if effort else {}),
    }
    started = time.time()
    proc = subprocess.run(
        [".venv/bin/agent", "investigate-one", alert_id],
        env=env, capture_output=True, text=True,
    )
    elapsed = time.time() - started

    files = list(reports.glob("*.json"))
    return {
        "model": model,
        "reasoning_effort": effort or "default",
        "alert_id": alert_id,
        "repeat": repeat,
        "elapsed_s": round(elapsed, 1),
        "exit_code": proc.returncode,
        "report_path": str(files[0]) if files else None,
        "model_bytes": loaded_model_bytes(model),
        # A crashed investigation is a result, not a gap — record it rather than
        # dropping the row, or a model that dies on every alert scores as absent.
        "stderr_tail": proc.stderr.strip()[-400:] if proc.returncode else "",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--stage", choices=sorted(STAGE_PLAN), default="screen")
    ap.add_argument(
        "--context", type=int, default=None,
        help="num_ctx for the bounded variant. Only for testing whether the benchmark "
             "context is a binding constraint -- comparable runs must all use the default.",
    )
    ap.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    ap.add_argument(
        "--effort", default=None,
        help="reasoning effort (low|medium|high|xhigh). Omit to leave the model on its "
             "own default. Reasoning length drives wall clock more than throughput does, "
             "so a reasoning model must be swept across efforts before it is ranked.",
    )
    args = ap.parse_args()

    if not args.snapshot.exists():
        raise SystemExit(f"no snapshot at {args.snapshot} — run `agent pull-alerts` first")

    label = f"{args.model.replace(':', '_')}@{args.effort or 'default'}"
    # Any explicit --context gets its own directory, including one equal to the default:
    # a repeat run must never overwrite the block it is being compared against.
    if args.context is not None:
        label += f"+ctx{args.context // 1024}k"
    workdir = RESULTS / label / args.stage
    workdir.mkdir(parents=True, exist_ok=True)
    shutil.copy(args.snapshot, workdir / "alerts.db")

    # Run the num_ctx-bounded variant, not the base model. Ollama sizes KV from the
    # model's *default* context when the base name is used -- 128000 for lfm2.5, 262144
    # for several others -- so the base model measures a footprint the gate never
    # measured, and each model measures at a different context from every other. The
    # per-request num_ctx does not survive the OpenAI-compat path; the Modelfile
    # PARAMETER does, which is what bench_variant bakes in. Results directories stay
    # keyed on the base name, so the variant is invisible to the scorer.
    context = args.context if args.context is not None else CONTEXT_TOKENS
    model = bench_variant(args.model, context) or args.model
    if model == args.model:
        print(f"  ! no bounded variant for {args.model} — running its default context", flush=True)

    selected = select_alerts(args.snapshot, args.stage)
    total = sum(repeats for *_, repeats in selected)
    print(f"{model} @ {args.effort or 'default'} / {args.stage}: "
          f"{len(selected)} alerts, {total} runs, num_ctx {context}", flush=True)

    results_file = workdir / "runs.jsonl"
    done = 0
    with results_file.open("w") as fh:
        for alert_id, cluster, role, repeats in selected:
            for repeat in range(repeats):
                record = run_one(model, alert_id, workdir, repeat, args.effort)
                record.update(cluster=cluster, role=role.value)
                fh.write(json.dumps(record) + "\n")
                fh.flush()
                done += 1
                # flush: stdout is block-buffered when redirected to a file, so an
                # unattended multi-hour sweep would show nothing at all until it exited
                # — indistinguishable from a hang. runs.jsonl is the durable record;
                # this is the one you watch.
                print(
                    f"  [{done}/{total}] {cluster:<11} {role.value:<11} "
                    f"{record['elapsed_s']:>6}s  exit={record['exit_code']}",
                    flush=True,
                )

    print(f"wrote {results_file}", flush=True)
    # Unload here rather than in sweep.sh: only this process knows the variant name, and
    # stopping the base name leaves the variant resident alongside the next block's model.
    subprocess.run(["ollama", "stop", model], capture_output=True)


if __name__ == "__main__":
    main()
