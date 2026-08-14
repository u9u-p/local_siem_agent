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
    """Every pulled model except the bounded variants this gate creates itself."""
    with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=10) as response:
        names = (m["name"] for m in json.load(response).get("models", []))
        # Match on the bare suffix: an untagged base model yields "model:bench-ctx8k",
        # which does not contain the leading dash.
        return sorted(n for n in names if VARIANT_SUFFIX.lstrip("-") not in n)


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


def measure_throughput(model: str) -> dict | None:
    """Separate generation speed from reasoning length for one representative call.

    Wall clock alone ranks these together and gets the ordering wrong. Measured on
    the identical trivial prompt, mistral-small3.2 emits 2 completion tokens where
    qwen3.6:27b emits 104 for the same two-character answer — a 50x difference in
    work done, not in throughput. A model that generates quickly but reasons at
    length can be slower end to end than a slower one that answers tersely, and the
    two scale differently with prompt complexity.

    Reported alongside wall clock so a candidate is never picked on a number that
    conflates them. For models exposing a reasoning-budget control (Muse Glimmer has
    low/medium/high/xhigh), this is also the knob that makes the real benchmark axis
    (model x reasoning effort) rather than model alone.
    """
    _, schema, prompt = PROBES[1]  # flat-enum: mid-complexity, representative
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": schema.__name__, "schema": schema.model_json_schema(), "strict": True},
        },
    }).encode()
    request = urllib.request.Request(
        "http://localhost:11434/v1/chat/completions", data=body,
        headers={"Content-Type": "application/json"},
    )
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=900) as response:
            payload = json.load(response)
    except Exception:  # noqa: BLE001 - a measurement failure must not fail the gate
        return None
    elapsed = time.time() - started

    message = payload["choices"][0]["message"]
    completion = payload.get("usage", {}).get("completion_tokens", 0)
    reasoning_chars = len(message.get("reasoning") or "")
    answer_chars = len(message.get("content") or "")
    total_chars = reasoning_chars + answer_chars

    # chars/s is the throughput figure to trust. Ollama's completion_tokens does not
    # account for reasoning consistently across models — gemma4:12b reported 49
    # completion tokens for ~1600 characters of reasoning plus answer, which is off by
    # roughly 8x — so tok/s derived from it understates reasoning models badly.
    # Characters are observed output and need no accounting from the server.
    return {
        "seconds": round(elapsed, 1),
        "completion_tokens": completion,
        "tokens_per_second": round(completion / elapsed, 1) if elapsed else 0.0,
        "chars_per_second": round(total_chars / elapsed) if elapsed else 0,
        "reasoning_chars": reasoning_chars,
        "answer_chars": answer_chars,
        "reasoning_share": round(reasoning_chars / total_chars, 2) if total_chars else 0.0,
    }


def accepts_reasoning_effort(model: str) -> bool:
    """Whether `model` tolerates a reasoning_effort parameter without erroring.

    Verified working on gpt-oss:20b and untested elsewhere. A model that rejects it
    would fail its whole sweep block twenty minutes in, so the gate finds out first
    and the batch can leave that model on its default.

    Tolerating is not the same as honouring — a model may accept and ignore it. The
    reasoning-share figure alongside is what shows whether it actually changed
    anything.
    """
    body = json.dumps({
        "model": model,
        "reasoning_effort": "low",
        "messages": [{"role": "user", "content": "Reply with the single word ok."}],
    }).encode()
    request = urllib.request.Request(
        "http://localhost:11434/v1/chat/completions", data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            json.load(response)
        return True
    except Exception:  # noqa: BLE001 - any rejection is a "do not send it" answer
        return False


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
        "footprint_bytes": None, "context_tokens": None, "throughput": None,
        "accepts_effort": None,
    }

    # Warm up so model load time is not charged to the first probe. Unwarmed,
    # gemma4:latest read 12.2s on the trivial probe against 5.7s on the harder one.
    try:
        client.generate_structured("Reply with the single word ok.", TrivialAnswer)
    except Exception:  # noqa: BLE001 - a failed warmup is the probe's result to report
        pass

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

    result["accepts_effort"] = accepts_reasoning_effort(variant)
    result["throughput"] = measure_throughput(variant)
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
        if tp := result["throughput"]:
            print(f"          {tp['seconds']}s wall   {tp['chars_per_second']} chars/s   "
                  f"{tp['reasoning_chars']} reasoning + {tp['answer_chars']} answer chars "
                  f"({tp['reasoning_share']:.0%} reasoning)")

    print("\n| model | verdict | footprint | wall | chars/s | reasoning | effort | schema probes |")
    print("|---|---|---|---|---|---|---|---|")
    for model, state, _, result in rows:
        size = result["footprint_bytes"]
        tp = result["throughput"] or {}
        probes = "/".join("ok" if result["probes"].get(n, {}).get("outcome") == "pass" else "FAIL"
                          for n, _, _ in PROBES)
        share = f"{tp['reasoning_share']:.0%}" if tp else "—"
        print(
            f"| `{model}` | {state} | {f'{size / 1024**3:.1f} GB' if size else '—'} "
            f"| {tp.get('seconds', '—')}s | {tp.get('chars_per_second', '—')} | {share} "
            f"| {'ok' if result['accepts_effort'] else 'no'} | {probes} |"
        )


if __name__ == "__main__":
    main()
