"""Score a benchmark run and emit a per-model scoreboard.

Reads the exported report JSON, never the SQLite copy: `triage_verdict_experimental`
has no `ReportRecord` column, so it survives export and vanishes through the store.

Everything here reads *structured* fields. Two prompts and one report field are due
to change under the pending prerequisites (spec §6), and anything parsing generated
prose would break on them. The single exception is the self-check audit count, which
exists nowhere but its own summary string — see `_self_check_counts`.

Usage:
    python -m bench.score                      # every model under bench/results
    python -m bench.score --stage deep
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from bench.labels import Role, expected_for

RESULTS = Path("./bench/results")
ESCALATED = {"high", "critical"}
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_AUDIT_RE = re.compile(r"audited (\d+) claim\(s\), (\d+) flagged")


def _self_check_counts(report: dict) -> tuple[int, int] | None:
    """(audited, flagged) from the self-check step, or None if unavailable.

    ponytail: the only generated string this module parses. The counts are not
    persisted as fields anywhere, and the metric matters — a model that never flags
    a claim is rubber-stamping, which is precisely what the design claims to prevent.
    Returns None rather than guessing if the format moves, so the metric degrades to
    "unavailable" instead of silently wrong. Promote to real fields on Report if this
    becomes load-bearing.
    """
    for step in report.get("investigation_timeline", []):
        if step.get("step_name") == "self_check":
            match = _AUDIT_RE.search(step.get("output_summary") or "")
            if match:
                return int(match.group(1)), int(match.group(2))
    return None


def _step_seconds(report: dict) -> dict[str, float]:
    steps = report.get("investigation_timeline", [])
    times = [datetime.fromisoformat(s["timestamp"]) for s in steps]
    return {
        s["step_name"]: round((b - a).total_seconds(), 1)
        for s, a, b in zip(steps[1:], times, times[1:])
    }


def load_runs(model_dir: Path, stage: str) -> list[dict]:
    runs_file = model_dir / stage / "runs.jsonl"
    if not runs_file.exists():
        return []
    rows = []
    for line in runs_file.read_text().splitlines():
        record = json.loads(line)
        path = record.get("report_path")
        report = json.loads(Path(path).read_text()) if path and Path(path).exists() else None
        record["report"] = report
        rows.append(record)
    return rows


def score_model(rows: list[dict]) -> dict:
    agg: dict = {
        "runs": len(rows),
        "crashed": sum(1 for r in rows if r["exit_code"] != 0),
        "no_report": sum(1 for r in rows if r["exit_code"] == 0 and not r.get("report")),
        "degraded": 0,
        "elapsed": [],
        "audited": 0,
        "flagged": 0,
        "base64_hits": 0,
        "base64_chances": 0,
        "triage_right": 0,
        "triage_scored": 0,
        "sev_distance": [],
        "by_cluster": defaultdict(lambda: {"escalated": 0, "n": 0, "role": ""}),
        "model_bytes": max((r.get("model_bytes") or 0 for r in rows), default=0),
    }

    for record in rows:
        report = record.get("report")
        if not report:
            continue
        agg["elapsed"].append(record["elapsed_s"])
        if report.get("status") != "complete":
            agg["degraded"] += 1

        severity = (report.get("risk_assessment") or {}).get("severity", "")
        label = _label_of(record)
        if label is None:
            continue

        key = f"{record['cluster']}/{record['role']}"
        bucket = agg["by_cluster"][key]
        bucket["n"] += 1
        bucket["role"] = record["role"]
        if severity in ESCALATED:
            bucket["escalated"] += 1

        if severity in _SEVERITY_RANK:
            allowed = [_SEVERITY_RANK[s] for s in label.expect_severity]
            agg["sev_distance"].append(min(abs(_SEVERITY_RANK[severity] - a) for a in allowed))

        verdict = report.get("triage_verdict_experimental")
        if verdict:
            agg["triage_scored"] += 1
            agg["triage_right"] += int(verdict == label.expect_triage)

        counts = _self_check_counts(report)
        if counts:
            agg["audited"] += counts[0]
            agg["flagged"] += counts[1]

        # The C2 address exists only as UTF-16LE base64 inside commandLine; reaching
        # enrichment_findings as a typed indicator means the model decoded it in-head
        # and the merge gate let it through (spec §2).
        if record["cluster"] == "powershell" and record["role"] == Role.NEEDLE.value:
            agg["base64_chances"] += 1
            agg["base64_hits"] += int(any(
                f.get("indicator_type") == "ip" and f.get("indicator_value") == "45.146.164.110"
                for f in report.get("enrichment_findings", [])
            ))

    return agg


def _label_of(record: dict):
    if not record.get("report"):
        return None
    return expected_for(record["cluster"], Role(record["role"]))


def _pct(numerator: int, denominator: int) -> str:
    return f"{100 * numerator / denominator:.0f}%" if denominator else "—"


def render(model: str, agg: dict) -> str:
    benign = [(k, v) for k, v in agg["by_cluster"].items() if v["role"] != Role.NEEDLE.value]
    needle = [(k, v) for k, v in agg["by_cluster"].items() if v["role"] == Role.NEEDLE.value]
    benign_esc = sum(v["escalated"] for _, v in benign), sum(v["n"] for _, v in benign)
    needle_rec = sum(v["escalated"] for _, v in needle), sum(v["n"] for _, v in needle)

    lines = [
        f"### {model}",
        "",
        f"- runs {agg['runs']}  crashed {agg['crashed']}  no-report {agg['no_report']}  "
        f"degraded {_pct(agg['degraded'], agg['runs'])}",
        f"- **benign escalation {_pct(*benign_esc)}** ({benign_esc[0]}/{benign_esc[1]})   "
        f"**needle recall {_pct(*needle_rec)}** ({needle_rec[0]}/{needle_rec[1]})",
        f"- triage accuracy {_pct(agg['triage_right'], agg['triage_scored'])}   "
        f"mean severity distance {statistics.mean(agg['sev_distance']):.2f}"
        if agg["sev_distance"] else "- triage accuracy —",
        f"- base64 recall {_pct(agg['base64_hits'], agg['base64_chances'])}   "
        f"self-check flagged {agg['flagged']}/{agg['audited']} claims",
        f"- median {statistics.median(agg['elapsed']):.0f}s/alert   "
        f"footprint {agg['model_bytes'] / 1e9:.1f} GB" if agg["elapsed"] else "- no timings",
        "",
        "| cluster | escalated |",
        "|---|---|",
    ]
    for key, value in sorted(agg["by_cluster"].items()):
        lines.append(f"| {key} | {value['escalated']}/{value['n']} |")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", default="screen")
    ap.add_argument("--csv", type=Path, default=RESULTS / "runs.csv")
    args = ap.parse_args()

    blocks, csv_rows = [], []
    for model_dir in sorted(p for p in RESULTS.glob("*") if p.is_dir()):
        rows = load_runs(model_dir, args.stage)
        if not rows:
            continue
        model = model_dir.name.replace("_", ":", 1)  # "gemma4_12b@low" -> "gemma4:12b@low"
        blocks.append(render(model, score_model(rows)))
        for record in rows:
            report = record.get("report") or {}
            csv_rows.append({
                "model": model,
                "reasoning_effort": record.get("reasoning_effort", "default"),
                "cluster": record["cluster"],
                "role": record["role"],
                "repeat": record["repeat"],
                "severity": (report.get("risk_assessment") or {}).get("severity", ""),
                "confidence": (report.get("risk_assessment") or {}).get("confidence", ""),
                "triage": report.get("triage_verdict_experimental", ""),
                "status": report.get("status", ""),
                "elapsed_s": record["elapsed_s"],
                **_step_seconds(report),
            })

    if not blocks:
        raise SystemExit(f"no results for stage '{args.stage}' under {RESULTS}")

    fields = sorted({k for row in csv_rows for k in row})
    with args.csv.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(csv_rows)

    print("\n\n".join(blocks))
    print(f"\nper-run detail: {args.csv}")


if __name__ == "__main__":
    main()
