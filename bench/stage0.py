"""Stage 0 gate: can this model run the pipeline at all, and does it fit the laptop?

Two questions, both cheap, both able to eliminate a candidate before any expensive
sweep touches it:

1. **Footprint.** Resident size against the demo laptop's ~17-18GB ceiling (24GB
   M4 Pro, less ~3GB macOS and ~3GB presentation software). Host-independent for a
   given model and quantisation, so measuring on the Studio answers the laptop's
   question.

2. **Constrained decoding.** Ollama's MLX backend silently ignores `response_format`
   — the model just does what it would do unconstrained, which for most models means
   markdown-fenced JSON. `model_available()` cannot catch this: it confirms a model is
   *pulled*, not that its backend can honour a schema. A model that fails here would
   otherwise degrade every single report to NEEDS_HUMAN_REVIEW and score across the
   sweep as merely cautious rather than broken.

`PROGRESS.md` risk #9 asks for exactly this check, independently of the benchmark.

Usage:
    python -m bench.stage0                       # every locally pulled model
    python -m bench.stage0 --models gemma4:12b muse-glimmer:30b
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.request

from pydantic import BaseModel

from app.agent.schemas import SelfCheckResult
from app.config import Settings
from app.llm.errors import LLMClientError
from app.llm.ollama_client import OllamaClient
from app.schemas import RiskAssessment

#: Demo laptop budget: 24GB total, less ~3GB macOS and ~3GB slides/browser/mirroring.
FIT_CEILING_BYTES = 17.5 * 1024**3


class TrivialAnswer(BaseModel):
    answer: str


#: Ordered easiest to hardest. A model that clears the flat schema but fails the
#: nested list is not usable here: Self-Check returns list[ClaimAudit], and its
#: failure is the one that silently marks reports COMPLETE without an audit.
PROBES: list[tuple[str, type[BaseModel], str]] = [
    ("trivial", TrivialAnswer, "Reply with the single word ok as the answer field."),
    ("flat-enum", RiskAssessment, (
        "A host had 14 failed SSH logons from one external address in 90 seconds, "
        "then one success. Assess severity, confidence and a one-sentence rationale."
    )),
    ("nested-list", SelfCheckResult, (
        "Audit these two claims against the finding 'rule 5715, 14 failed logons "
        "then one success from 45.146.164.110'. Claim 1: 'the source address "
        "authenticated successfully'. Claim 2: 'the host was running a database "
        "server'. Return one audit entry per claim, in order."
    )),
]


def local_models() -> list[str]:
    with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=10) as response:
        return sorted(m["name"] for m in json.load(response).get("models", []))


def footprint_bytes(model: str) -> int | None:
    """Resident size of the loaded model, per `ollama ps`."""
    try:
        out = subprocess.run(["ollama", "ps"], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines()[1:]:
        if not line.startswith(model.split(":")[0]):
            continue
        parts = line.split()
        for i, token in enumerate(parts):
            if token.upper() in {"GB", "MB"} and i:
                try:
                    value = float(parts[i - 1])
                except ValueError:
                    continue
                return int(value * (1024**3 if token.upper() == "GB" else 1024**2))
    return None


def unload(model: str) -> None:
    """Free the model so the next candidate is measured without it resident."""
    subprocess.run(["ollama", "stop", model], capture_output=True, timeout=60)


def probe_model(model: str) -> dict:
    settings = Settings()
    client = OllamaClient(
        base_url=settings.llm_base_url,
        model=model,
        timeout_seconds=settings.llm_timeout_seconds,
    )
    result: dict = {"model": model, "probes": {}, "footprint_bytes": None}

    for name, schema, prompt in PROBES:
        started = time.time()
        try:
            client.generate_structured(prompt, schema)
            outcome = "pass"
        except LLMClientError as exc:
            outcome = f"FAIL:{exc.kind}"
        except Exception as exc:  # noqa: BLE001 - a gate must report, never abort the sweep
            outcome = f"FAIL:{type(exc).__name__}"
        result["probes"][name] = {"outcome": outcome, "seconds": round(time.time() - started, 1)}
        if outcome != "pass":
            break  # harder probes tell us nothing once an easier one has failed

    result["footprint_bytes"] = footprint_bytes(model)
    unload(model)
    return result


def verdict(result: dict) -> tuple[str, str]:
    outcomes = [p["outcome"] for p in result["probes"].values()]
    failed = [name for name, p in result["probes"].items() if p["outcome"] != "pass"]
    size = result["footprint_bytes"]

    if failed:
        return "REJECT", f"cannot honour schema ({result['probes'][failed[0]]['outcome']})"
    if size is None:
        return "PASS?", "schema ok, footprint unmeasured"
    if size > FIT_CEILING_BYTES:
        return "STUDY", f"schema ok but {size / 1e9:.1f} GB exceeds the laptop budget"
    return "PASS", f"{len(outcomes)} probes, {size / 1e9:.1f} GB"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", help="defaults to every locally pulled model")
    args = ap.parse_args()

    models = args.models or local_models()
    print(f"Stage 0 — {len(models)} model(s), ceiling {FIT_CEILING_BYTES / 1e9:.1f} GB\n")

    rows = []
    for model in models:
        result = probe_model(model)
        state, note = verdict(result)
        rows.append((model, state, note, result))
        timings = "  ".join(f"{n}={p['seconds']}s" for n, p in result["probes"].items())
        print(f"  {state:<7} {model:<26} {note}")
        print(f"          {timings}")

    print("\n| model | verdict | footprint | trivial | flat-enum | nested-list |")
    print("|---|---|---|---|---|---|")
    for model, state, _, result in rows:
        size = result["footprint_bytes"]
        cells = [result["probes"].get(n, {}).get("outcome", "—") for n, _, _ in PROBES]
        print(f"| `{model}` | {state} | {f'{size / 1e9:.1f} GB' if size else '—'} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
