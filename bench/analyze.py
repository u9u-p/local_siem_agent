"""Secondary analyses over completed benchmark runs — read-only, no model time.

`bench.score` answers "which model wins". This answers the questions that only
become askable once the runs exist: how bad the latency tail is, whether the
self-check and the model's own stated confidence carry any signal, and what the
closed-vocabulary action catalog is actually buying.

Reads only committed evidence (reports, run records) and writes one new file,
`bench/results/analysis.json`. It never touches an existing results file — an
earlier version of the gate truncated its own output and destroyed seventeen
models' worth of measurements, and that is not a mistake worth making twice.

    python -m bench.analyze
"""

from __future__ import annotations

import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

from bench.labels import Role, expected_for

RESULTS = Path("./bench/results")
OUT = RESULTS / "analysis.json"
ESCALATED = {"high", "critical"}

#: Verbs that would make an "action" something the agent tells a human to execute
#: against production rather than to investigate. CLAUDE.md §2.3 requires canonical
#: actions be human-actionable and never executable, and the catalog enforces it by
#: construction. Draft-B has no catalog, so this measures whether the constraint is
#: load-bearing or decorative. Deliberately crude — a keyword scan over prose, quoted
#: as indicative and never as a precise rate.
REMEDIATION = re.compile(
    r"\b(block|blacklist|quarantine|isolate|disable|revoke|terminate|kill|delete|"
    r"remove|reset the password|force.{0,10}logout|shut down|deny|drop)\b", re.I)


def load() -> list[dict]:
    """One row per run: the run record joined to its report and its ground truth."""
    rows = []
    for runs_file in RESULTS.glob("**/runs.jsonl"):
        stage = runs_file.parent.name
        for line in runs_file.read_text().splitlines():
            if not line.strip():
                continue
            run = json.loads(line)
            path = run.get("report_path")
            if not path or not Path(path).exists():
                continue
            report = json.loads(Path(path).read_text())
            # Skip the block that ran with no model loaded: its severity is the safe
            # default, not a judgement, and averaging it in would flatter nothing.
            #
            # Matched by name because no field distinguishes it. model_metadata carries
            # model_version "none" on all 624 reports — the field is never populated —
            # and model_name is never "none", because model_available() checks that the
            # model is in the registry, not that it loads. Bonsai was pulled, so the
            # check passed and every generate call then failed into a safe default.
            if "Ternary-Bonsai" in report["model_metadata"].get("model_name", ""):
                continue
            try:
                label = expected_for(run["cluster"], Role(run["role"]))
            except ValueError:
                continue
            severity = (report.get("risk_assessment") or {}).get("severity", "")
            rows.append({
                "config": f"{run['model'].split('-bench')[0]}@{run['reasoning_effort']}",
                "stage": stage, "cluster": run["cluster"], "role": run["role"],
                "elapsed_s": run["elapsed_s"], "severity": severity,
                "confidence": (report.get("risk_assessment") or {}).get("confidence", ""),
                # Correct = severity landed inside the label's allowed set. This is the
                # same primary signal bench.score grades on, not a second opinion.
                "correct": severity in label.expect_severity,
                "escalated": severity in ESCALATED,
                "should_escalate": label.role is Role.NEEDLE,
                "flagged": _flagged(report),
                "status": report["status"],
                "actions": report.get("recommended_actions") or [],
                "freeform": report.get("recommended_actions_freeform_experimental") or [],
                "alert_id": run["alert_id"],
            })
    return rows


def _flagged(report: dict) -> int:
    """Claims the self-check flagged, parsed from its timeline summary.

    The count is not persisted as a field anywhere, and the metric matters, so this
    is the one place the analysis reads generated text instead of a typed value.
    """
    step = next((s for s in report["investigation_timeline"]
                 if s["step_name"] == "self_check"), None)
    match = re.search(r"(\d+) flagged", (step or {}).get("output_summary") or "")
    return int(match.group(1)) if match else 0


def latency(rows: list[dict]) -> dict:
    """p50 against the tail. A live demo is sized by p95, never by the median."""
    out = {}
    for config, group in _by(rows, "config").items():
        v = sorted(r["elapsed_s"] for r in group)
        if len(v) < 10:
            continue
        q = lambda p: v[min(int(len(v) * p), len(v) - 1)]  # noqa: E731
        out[config] = {"n": len(v), "p50": statistics.median(v), "p90": q(.90),
                       "p95": q(.95), "max": max(v), "tail_ratio": round(q(.95) / statistics.median(v), 2)}
    return out


def self_check_signal(rows: list[dict]) -> dict:
    """Does a flagged report differ in accuracy from an unflagged one?

    If flagging carries signal, flagged reports should be *less* accurate — the
    self-check would be catching its own bad work. If accuracy is the same either
    way, flagging is a workload dial, not a quality signal, and routing 86% of
    reports to a human buys nothing.
    """
    out = {}
    for config, group in _by(rows, "config").items():
        flagged = [r for r in group if r["flagged"]]
        clean = [r for r in group if not r["flagged"]]
        if len(flagged) < 5 or len(clean) < 5:
            continue
        out[config] = {
            "flagged_n": len(flagged), "flagged_correct": _rate(flagged),
            "clean_n": len(clean), "clean_correct": _rate(clean),
            "delta": round(_rate(flagged) - _rate(clean), 3),
        }
    return out


def confidence_calibration(rows: list[dict]) -> dict:
    """Is stated confidence worth anything? Calibrated means high > medium > low."""
    out = {}
    for config, group in _by(rows, "config").items():
        levels = {}
        for level in ("low", "medium", "high"):
            at = [r for r in group if r["confidence"] == level]
            if at:
                levels[level] = {"n": len(at), "correct": _rate(at)}
        if len(levels) > 1:
            out[config] = levels
    return out


def action_analysis(rows: list[dict]) -> dict:
    """What the closed-vocabulary catalog buys against the free-form parallel call.

    Both fields answer the same question — what should the analyst do — under
    different constraints, which makes this the one clean constrained-vs-free
    comparison in the corpus. The severity-vs-triage pairing often quoted as an
    ablation is not: those come from different steps asking different questions.
    """
    vocab, out = set(), {}
    for r in rows:
        vocab.update(r["actions"])
    for config, group in _by(rows, "config").items():
        acts = [len(r["actions"]) for r in group]
        free = [len(r["freeform"]) for r in group]
        remediation_free = sum(
            1 for r in group if any(REMEDIATION.search(a) for a in r["freeform"]))
        remediation_cat = sum(
            1 for r in group if any(REMEDIATION.search(a) for a in r["actions"]))
        out[config] = {
            "n": len(group),
            "catalog_mean": round(statistics.mean(acts), 1) if acts else 0,
            "freeform_mean": round(statistics.mean(free), 1) if free else 0,
            "distinct_catalog_actions_used": len({a for r in group for a in r["actions"]}),
            "reports_with_remediation_verb_freeform": remediation_free,
            "reports_with_remediation_verb_catalog": remediation_cat,
        }
    return {"catalog_size_observed": len(vocab), "by_config": out}


def agreement(rows: list[dict]) -> dict:
    """Do different models pick the same actions for the same alert?

    High overlap means the catalog is doing the work and the model is picking from a
    narrow obvious set; low overlap means model choice reaches the analyst's page.
    """
    per_alert = defaultdict(dict)
    for r in rows:
        if r["stage"] == "deep" and r["actions"]:
            per_alert[r["alert_id"]][r["config"]] = set(r["actions"])
    scores = []
    for configs in per_alert.values():
        sets = list(configs.values())
        for i in range(len(sets)):
            for j in range(i + 1, len(sets)):
                union = sets[i] | sets[j]
                if union:
                    scores.append(len(sets[i] & sets[j]) / len(union))
    if not scores:
        return {}
    return {"pairs": len(scores), "mean_jaccard": round(statistics.mean(scores), 3),
            "median_jaccard": round(statistics.median(scores), 3)}


def _by(rows: list[dict], key: str) -> dict[str, list[dict]]:
    out = defaultdict(list)
    for r in rows:
        out[r[key]].append(r)
    return out


def _rate(rows: list[dict]) -> float:
    return round(sum(r["correct"] for r in rows) / len(rows), 3) if rows else 0.0


def main() -> None:
    rows = load()
    deep = [r for r in rows if r["stage"] == "deep"]
    result = {
        "rows_analysed": len(rows), "deep_rows": len(deep),
        "latency": latency(deep),
        "self_check_signal": self_check_signal(deep),
        "confidence_calibration": confidence_calibration(deep),
        "actions": action_analysis(deep),
        "action_agreement": agreement(rows),
    }
    OUT.write_text(json.dumps(result, indent=2) + "\n")

    print(f"{len(rows)} runs joined to reports and ground truth ({len(deep)} deep)\n")

    print("LATENCY — a demo is sized by p95, not p50")
    print(f"  {'config':<32} {'p50':>6} {'p90':>6} {'p95':>6} {'max':>6} {'tail':>6}")
    for k, v in sorted(result["latency"].items(), key=lambda x: x[1]["p50"]):
        print(f"  {k:<32} {v['p50']:>6.0f} {v['p90']:>6.0f} {v['p95']:>6.0f} "
              f"{v['max']:>6.0f} {v['tail_ratio']:>5.1f}x")

    print("\nSELF-CHECK — does flagging predict being wrong?")
    print(f"  {'config':<32} {'flagged':>16} {'clean':>16} {'delta':>7}")
    for k, v in sorted(result["self_check_signal"].items()):
        print(f"  {k:<32} {v['flagged_correct']:>8.0%} (n={v['flagged_n']:<3}) "
              f"{v['clean_correct']:>8.0%} (n={v['clean_n']:<3}) {v['delta']:>+7.1%}")

    print("\nCONFIDENCE — calibrated means high > medium > low")
    print(f"  {'config':<32} {'low':>14} {'medium':>14} {'high':>14}")
    for k, v in sorted(result["confidence_calibration"].items()):
        cells = "".join(
            f"{v[l]['correct']:>8.0%} (n={v[l]['n']:<3})" if l in v else f"{'—':>14}"
            for l in ("low", "medium", "high"))
        print(f"  {k:<32}{cells}")

    print(f"\nACTIONS — {result['actions']['catalog_size_observed']} distinct catalog "
          f"actions observed across all runs")
    print(f"  {'config':<32} {'catalog':>8} {'freeform':>9} {'used':>5} "
          f"{'remediation verb: free / catalog':>34}")
    for k, v in sorted(result["actions"]["by_config"].items()):
        print(f"  {k:<32} {v['catalog_mean']:>8.1f} {v['freeform_mean']:>9.1f} "
              f"{v['distinct_catalog_actions_used']:>5} "
              f"{v['reports_with_remediation_verb_freeform']:>22}/{v['n']:<3}"
              f" {v['reports_with_remediation_verb_catalog']:>3}/{v['n']}")

    if result["action_agreement"]:
        a = result["action_agreement"]
        print(f"\nAGREEMENT — {a['pairs']} cross-model pairs on the same alert, "
              f"mean Jaccard {a['mean_jaccard']}, median {a['median_jaccard']}")

    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
