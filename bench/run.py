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

SNAPSHOT = Path("./data/bench_alerts.db")
RESULTS = Path("./bench/results")

#: Stage 1 screens breadth-first to kill non-viable models cheaply; stage 2 spends
#: repeats only on the alerts that must be stable on stage (spec §4).
STAGE_PLAN = {
    "screen": {"benign_per_cluster": 1, "needle_repeats": 1, "benign_repeats": 1},
    "deep": {"benign_per_cluster": 10, "needle_repeats": 3, "benign_repeats": 1},
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
        else:
            selected.append((alert_id, label.cluster, label.role, plan["needle_repeats"]))
    return selected


def loaded_model_bytes() -> int | None:
    """Resident size of the currently-loaded model, per `ollama ps`.

    ponytail: sampled once after a run rather than polled for a true peak. Good
    enough for the fit gate, which asks whether a model fits ~17GB at all; swap in
    a polling sampler if a candidate lands within a gigabyte of the ceiling.
    """
    try:
        out = subprocess.run(["ollama", "ps"], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[-3].replace(".", "").isdigit():
            value, unit = float(parts[-3]), parts[-2].upper()
            return int(value * (1024**3 if unit.startswith("G") else 1024**2))
    return None


def run_one(model: str, alert_id: str, workdir: Path, repeat: int) -> dict:
    reports = workdir / "reports" / alert_id / str(repeat)
    reports.mkdir(parents=True, exist_ok=True)
    env = {
        **os.environ,
        "LLM_MODEL": model,
        "DATABASE_PATH": str(workdir / "alerts.db"),
        "REPORTS_DIR": str(reports),
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
        "alert_id": alert_id,
        "repeat": repeat,
        "elapsed_s": round(elapsed, 1),
        "exit_code": proc.returncode,
        "report_path": str(files[0]) if files else None,
        "model_bytes": loaded_model_bytes(),
        # A crashed investigation is a result, not a gap — record it rather than
        # dropping the row, or a model that dies on every alert scores as absent.
        "stderr_tail": proc.stderr.strip()[-400:] if proc.returncode else "",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--stage", choices=sorted(STAGE_PLAN), default="screen")
    ap.add_argument("--snapshot", type=Path, default=SNAPSHOT)
    args = ap.parse_args()

    if not args.snapshot.exists():
        raise SystemExit(f"no snapshot at {args.snapshot} — run `agent pull-alerts` first")

    workdir = RESULTS / args.model.replace(":", "_") / args.stage
    workdir.mkdir(parents=True, exist_ok=True)
    shutil.copy(args.snapshot, workdir / "alerts.db")

    selected = select_alerts(args.snapshot, args.stage)
    total = sum(repeats for *_, repeats in selected)
    print(f"{args.model} / {args.stage}: {len(selected)} alerts, {total} runs")

    results_file = workdir / "runs.jsonl"
    done = 0
    with results_file.open("w") as fh:
        for alert_id, cluster, role, repeats in selected:
            for repeat in range(repeats):
                record = run_one(args.model, alert_id, workdir, repeat)
                record.update(cluster=cluster, role=role.value)
                fh.write(json.dumps(record) + "\n")
                fh.flush()
                done += 1
                print(f"  [{done}/{total}] {cluster:<11} {role.value:<11} {record['elapsed_s']:>6}s")

    print(f"wrote {results_file}")


if __name__ == "__main__":
    main()
