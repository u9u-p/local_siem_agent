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
#: Ollama truncates silently past num_ctx, but not invisibly here: OllamaClient catches
#: LengthFinishReasonError, retries once, then records a degraded step, so hitting the
#: ceiling surfaces as an elevated degraded count that the scorer already tracks.
#:
#: This stays 8192 even though the ladder below measures four sizes. Raising it to
#: disambiguate "model failed" from "ran out of context" was considered and rejected:
#: prompts measure 733 tokens (9% of this window), most sweep blocks run at low effort
#: which cuts reasoning output roughly 10x, and inflating the KV allocation would push
#: muse-glimmer:30b (17.0GB) and gemma4:26b-a4b past the 17.5GB ceiling — corrupting a
#: primary criterion to solve a secondary interpretation problem. If one model shows
#: anomalous degradation, re-gate that model alone at a larger context.
CONTEXT_TOKENS = 8192

#: Footprint is measured at three context sizes, because "does it fit 24GB" has a
#: different answer at each and the cost per token varies enormously by architecture.
#: From two measured points, gemma4:12b spends ~6.6MB per 1K tokens of context against
#: qwen3.6:27b's ~84MB — a ~13x spread. Extrapolated to 32K that is 8.6GB against
#: 18.1GB, so one model barely moves and the other stops fitting the laptop.
#:
#: 8192 matches this corpus (prompts measure 733 tokens) and is what the sweep runs.
#: 32768 is a defensible production size: a real full_log — Windows XML, an EDR process
#: tree, a full header block — runs 10-50KB on its own, where the seeded corpus is one
#: syslog line. 131072 is the context several models advertise (muse-glimmer, gpt-oss
#: and mistral-small3.2 all claim 128K), so it prices that claim. 262144 is several
#: models' own default.
#:
#: Four rungs rather than three because the shape matters as much as the endpoints: a
#: linear curve means cost is predictable per token, a knee means something changes —
#: an attention scheme, a cache layout — at a specific size.
#:
#: Requesting more than a model supports is fine: the reported figure comes from
#: `ollama ps`, so a clamp shows up as a smaller context rather than a wrong number.
CONTEXT_LADDER = (8192, 32768, 131072, 262144)
VARIANT_PREFIX = "-bench-ctx"

#: The gate used to print and nothing else. A 17-model run scrolled past the terminal's
#: retained output and took the per-model context ladders and KV costs with it — the
#: summary table carries neither. Written per model rather than at the end, so a gate
#: killed halfway still keeps what it had already measured.
RESULTS_FILE = Path("bench/results/stage0.jsonl")


def upsert_result(path: Path, record: dict) -> None:
    """Replace `record`'s model row in `path`, keeping every other model's.

    Not an append and not a truncate. Truncating meant `--models qwen3.8:27b` silently
    destroyed the other seventeen rows; appending would leave two rows for a re-gated
    model with no way to tell which is current. Rewriting whole is O(n^2) over a run
    and n is the number of local models, so it does not matter.
    """
    rows: dict[str, dict] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                rows[row["model"]] = row
    rows[record["model"]] = record
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r) + "\n" for r in rows.values()))


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
        return sorted(n for n in names if VARIANT_PREFIX.lstrip("-") not in n)


def footprint_bytes(model: str) -> tuple[int, int] | None:
    """(resident_bytes, context_tokens) for `model`, from Ollama's /api/ps.

    Matches the full name: `gemma4` as a prefix would also match `gemma4:latest`.

    Reads the JSON API rather than parsing `ollama ps`. The text output is rounded
    for humans and, worse, is *decimal* GB — the parser this replaced multiplied
    "8.4 GB" by 1024^3 and overstated every footprint by 7.7%, which wrongly put
    muse-glimmer:30b over the fit ceiling. The rounding also hid real growth: at
    64 GB the text has ~1 GB of resolution, so gpt-oss:120b's KV cost read as
    exactly zero across three rungs when it is 240 MB per 122,880 tokens.
    """
    try:
        with urllib.request.urlopen("http://localhost:11434/api/ps", timeout=15) as response:
            loaded = json.load(response).get("models", [])
    except Exception:  # noqa: BLE001 - an unreachable daemon is a missing reading, not a crash
        return None
    for entry in loaded:
        if entry.get("name") not in {model, f"{model}:latest"}:
            continue
        size, context = entry.get("size"), entry.get("context_length")
        if size:
            return int(size), int(context or 0)
    return None


def bench_variant(model: str, context: int = CONTEXT_TOKENS) -> str | None:
    """Create a `num_ctx`-bounded variant of `model`, returning its name.

    Manifest-only — it reuses the base model's blobs, so this costs no download and
    negligible disk.
    """
    suffix = f"{VARIANT_PREFIX}{context // 1024}k"
    # Keep a colon in the name. Without a tag Ollama appends ":latest", which then
    # will not match what `ollama ps` prints.
    variant = f"{model}{suffix}" if ":" in model else f"{model}:{suffix.lstrip('-')}"
    # `ollama create -f -` does not read stdin in this version ("no Modelfile or
    # safetensors files found"), so the Modelfile has to exist on disk.
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "Modelfile"
        path.write_text(f"FROM {model}\nPARAMETER num_ctx {context}\n")
        proc = subprocess.run(
            ["ollama", "create", variant, "-f", str(path)],
            capture_output=True, text=True, timeout=600,
        )
    if proc.returncode != 0 or "Error:" in proc.stderr:
        print(f"    ! variant creation failed for {model}: {proc.stderr.strip()[-160:]}")
        return None
    return variant


def footprint_ladder(model: str) -> list[tuple[int, int, int]]:
    """(requested_ctx, actual_ctx, resident_bytes) at each rung of CONTEXT_LADDER.

    Only loads the model — no probes. The schema checks run once at the benchmark
    context; the extra rungs answer a different question, which is what the model
    costs when the logs are real rather than seeded.
    """
    readings: list[tuple[int, int, int]] = []
    for context in CONTEXT_LADDER:
        variant = bench_variant(model, context)
        if variant is None:
            continue
        try:
            urllib.request.urlopen(
                urllib.request.Request(
                    "http://localhost:11434/v1/chat/completions",
                    data=json.dumps({
                        "model": variant,
                        "messages": [{"role": "user", "content": "ok"}],
                        "max_tokens": 1,
                    }).encode(),
                    headers={"Content-Type": "application/json"},
                ), timeout=1800,
            ).read()
        except Exception:  # noqa: BLE001 - a rung that will not load is a blank, not a failure
            unload(variant)
            continue
        measured = footprint_bytes(variant)
        if measured:
            readings.append((context, measured[1], measured[0]))
        unload(variant)
    return readings


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


def kv_cost_per_1k(ladder: list[tuple[int, int, int]]) -> float | None:
    """MB of resident memory per 1K tokens of context, from the ladder's endpoints.

    The number that decides how much context a model can afford, and it varies by
    roughly an order of magnitude between architectures — so two models of similar
    size can differ completely in whether long context is usable. Reported from the
    widest measured span; the intermediate rungs show whether that rate is constant.

    None when fewer than two rungs loaded, or when a clamp collapsed the span.
    """
    usable = [(actual, size) for _, actual, size in ladder if actual]
    if len(usable) < 2:
        return None
    (lo_ctx, lo_size), (hi_ctx, hi_size) = min(usable), max(usable)
    if hi_ctx == lo_ctx:
        return None
    return ((hi_size - lo_size) / (1024**2)) / ((hi_ctx - lo_ctx) / 1024)


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
        "accepts_effort": None, "ladder": [],
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
    # Footprint across the context ladder, after the probes so a schema failure is
    # reported without spending load time on rungs that cannot matter.
    if not [p for p in result["probes"].values() if p["outcome"] != "pass"]:
        result["ladder"] = footprint_ladder(model)
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
    ap.add_argument(
        "--ladder-only", action="store_true",
        help="context ladder and KV cost only, skipping probes, throughput and effort. "
             "The rungs are model loads with no generation, so this is a fraction of a "
             "full gate — enough to recover ladder data without re-running everything.",
    )
    args = ap.parse_args()

    models = args.models or local_models()

    if args.ladder_only:
        out = RESULTS_FILE.with_name("stage0-ladder.jsonl")  # its own file, not the gate's
        print(f"Stage 0 ladder — {len(models)} model(s), rungs {CONTEXT_LADDER}\n")
        for model in models:
            ladder = footprint_ladder(model)
            kv = kv_cost_per_1k(ladder)
            upsert_result(out, {"model": model, "ladder": ladder, "kv_mb_per_1k": kv})
            if not ladder:
                print(f"  {model:<44} no rung loaded", flush=True)
                continue
            rungs = "  ".join(f"{a or r}:{s / 1024**3:.1f}G" for r, a, s in ladder)
            print(f"  {model:<44} {rungs}"
                  f"{f'   KV {kv:.1f} MB/1K' if kv is not None else ''}", flush=True)
        print(f"\nwrote {out}")
        return

    print(f"Stage 0 — {len(models)} model(s), ceiling {FIT_CEILING_BYTES / 1024**3:.1f} GB, num_ctx {CONTEXT_TOKENS}\n")

    rows = []
    for model in models:
        result = probe_model(model)
        state, note = verdict(result)
        rows.append((model, state, note, result))
        upsert_result(RESULTS_FILE, {"verdict": state, "note": note, **result})
        timings = "  ".join(f"{n}={p['seconds']}s" for n, p in result["probes"].items())
        print(f"  {state:<7} {model:<26} {note}")
        print(f"          {timings}")
        for requested, actual, size in result["ladder"]:
            fits = "fits" if size <= FIT_CEILING_BYTES else "OVER"
            clamp = f" (clamped from {requested})" if actual and actual < requested else ""
            print(f"          ctx {actual or requested:>7} {size / 1024**3:>6.1f} GB  {fits}{clamp}")
        if (kv := kv_cost_per_1k(result["ladder"])) is not None:
            print(f"          KV cost {kv:.1f} MB per 1K tokens of context")
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
