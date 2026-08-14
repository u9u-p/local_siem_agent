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
import tempfile
import time
import urllib.request
from pathlib import Path

from pydantic import BaseModel

from app.agent.schemas import SelfCheckResult
from app.config import Settings
from app.llm.errors import LLMClientError
from app.llm.ollama_client import OllamaClient
from app.schemas import RiskAssessment

#: Demo laptop budget: 24GB total, less ~3GB macOS and ~3GB slides/browser/mirroring.
FIT_CEILING_BYTES = 17.5 * 1024**3

#: Ollama sizes the KV cache from the model's default context, which for several
#: candidates is 262144 tokens — and that allocation, not the weights, is most of the
#: resident footprint (qwen3.6:27b measured 36.5 GB by default against 16 GB here).
#: CLAUDE.md §4.2 rule 2 keeps every prompt to a few hundred to ~2k tokens of
#: structured JSON, so 8192 is roughly 4x headroom.
#:
#: Per-request num_ctx does not survive: the OpenAI-compat endpoint that OllamaClient
#: uses reloads the model at its default context, verified 14 Aug. A Modelfile
#: parameter does survive, so the gate measures a baked variant — the thing we would
#: actually deploy — rather than a number no deployment can reach.
#:
#: Ollama truncates silently past num_ctx. Re-check this margin once §6.2's
#: correlation digest lands, since it grows every downstream prompt.
CONTEXT_TOKENS = 8192
VARIANT_SUFFIX = "-bench-ctx8k"


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


def footprint_bytes(model: str) -> tuple[int, int] | None:
    """(resident_bytes, context_tokens) for `model`, per `ollama ps`.

    Matches the full name: `gemma4` as a prefix would also match `gemma4:latest`.
    """
    try:
        out = subprocess.run(["ollama", "ps"], capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines()[1:]:
        parts = line.split()
        if not parts or parts[0] not in {model, f"{model}:latest"}:
            continue
        for i, token in enumerate(parts):
            if token.upper() not in {"GB", "MB"} or not i:
                continue
            try:
                value = float(parts[i - 1])
            except ValueError:
                continue
            # PROCESSOR sits between SIZE and CONTEXT and is not a fixed token count
            # ("100% GPU" is two, a split load may be one), so find CONTEXT by shape:
            # the first bare integer after the size unit.
            context = next((int(t) for t in parts[i + 1:] if t.isdigit()), 0)
            return int(value * (1024**3 if token.upper() == "GB" else 1024**2)), context
    return None


def bench_variant(model: str) -> str | None:
    """Create a `num_ctx`-bounded variant of `model`, returning its name.

    Manifest-only — it reuses the base model's blobs, so this costs no download and
    negligible disk.
    """
    # Keep a colon in the name. Without a tag Ollama appends ":latest", which then
    # will not match what `ollama ps` prints.
    variant = f"{model}{VARIANT_SUFFIX}" if ":" in model else f"{model}:{VARIANT_SUFFIX.lstrip('-')}"
    # `ollama create -f -` does not read stdin in this version ("no Modelfile or
    # safetensors files found"), so the Modelfile has to exist on disk.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "Modelfile"
        path.write_text(f"FROM {model}\nPARAMETER num_ctx {CONTEXT_TOKENS}\n")
        proc = subprocess.run(
            ["ollama", "create", variant, "-f", str(path)],
            capture_output=True, text=True, timeout=600,
        )
    if proc.returncode != 0 or "Error:" in proc.stderr:
        print(f"    ! variant creation failed for {model}: {proc.stderr.strip()[-160:]}")
        return None
    return variant


def unload(model: str) -> None:
    """Free the model so the next candidate is measured without it resident."""
    subprocess.run(["ollama", "stop", model], capture_output=True, timeout=60)


def probe_model(model: str) -> dict:
    settings = Settings()
    # Probe the bounded variant, since that is what a deployment would run. Fall back
    # to the base model rather than skipping if creation fails — a missing footprint
    # is a weaker result than none at all.
    variant = bench_variant(model) or model
    client = OllamaClient(
        base_url=settings.llm_base_url,
        model=variant,
        timeout_seconds=settings.llm_timeout_seconds,
    )
    result: dict = {
        "model": model, "variant": variant, "probes": {},
        "footprint_bytes": None, "context_tokens": None,
    }

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

    measured = footprint_bytes(variant)
    if measured:
        result["footprint_bytes"], result["context_tokens"] = measured
    unload(variant)
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
        return "STUDY", f"schema ok but {size / 1024**3:.1f} GB exceeds the laptop budget"
    return "PASS", f"{len(outcomes)} probes, {size / 1024**3:.1f} GB @ {result['context_tokens']} ctx"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", nargs="*", help="defaults to every locally pulled model")
    args = ap.parse_args()

    models = args.models or local_models()
    print(f"Stage 0 — {len(models)} model(s), ceiling {FIT_CEILING_BYTES / 1024**3:.1f} GB, num_ctx {CONTEXT_TOKENS}\n")

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
        print(f"| `{model}` | {state} | {f'{size / 1024**3:.1f} GB' if size else '—'} | " + " | ".join(cells) + " |")


if __name__ == "__main__":
    main()
