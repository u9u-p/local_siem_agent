# Analytics handoff — benchmark results → HITCON talk

**Purpose of this document:** the model-selection benchmark is finished and its results
are committed. What remains is turning 602 investigations into slides. This is what the
next session needs to know before touching any of it.

**The talk:** *"Your First Agentic SOC Without the GPU Bill: Local LLM Triage on Apple
Silicon"*, HITCON 2026, HACKING 101 track, **Friday 21 August 2026**, two speakers
(Tommy Wong, Ke Li Yam). Demo runs on a **MacBook Pro M4 Pro, 24 GB**; development is on
a 128 GB Mac Studio, so anything memory- or bandwidth-dependent measured here does not
transfer — footprint transfers, wall clock does not. The SIEM runs on a separate machine.
Alert classes covered: **email, logins, AI-tooling PowerShell**.

---

## 1. What was decided

**`gemma4:12b`** (Q4_K_M, GGUF, `num_ctx=8192`) — the only configuration with 100% needle
recall *and* a clean FP control at n=6, at 8.4 GiB. Confirmed at matched reasoning effort
and against the runner-up's best configuration.

**The demo cannot be live.** p50 259s, p95 462s, max 648s per alert, on the *faster*
machine. `reasoning_effort` does not rescue it — `gemma4:12b` responds at 1.34× where
`gpt-oss:20b` responds at 28×.

---

## 2. Where the data is

Everything below is committed on `main` and reproducible from a clone.

| what | where | size |
|---|---|---|
| Graded corpus (182 alerts, 130 graded, 4 clusters) | `data/bench_alerts.db` | 644 KB |
| Ground truth (derived from alert **content**, never `alert_id`) | `bench/labels.py` | — |
| 624 report JSONs | `bench/results/<config>/<stage>/reports/…` | 5 MB |
| 602 run records | `bench/results/<config>/<stage>/runs.jsonl` | — |
| Stage 0 gate, 18 models | `bench/results/stage0.jsonl` | — |
| Context ladder, 4 rungs × 17 models, exact bytes | `bench/results/stage0-ladder.jsonl` | — |
| Secondary analyses | `bench/results/analysis.json` | — |
| Per-block wall clock | `bench/results/sweep-*.log` | — |
| **All findings, written up** | `PROGRESS.md` § "Local model selection benchmark" | — |

**Tools:** `python -m bench.score --stage deep` (scoreboard),
`python -m bench.analyze` (secondary analyses), `python -m bench.stage0 [--ladder-only]`
(gate; needs model time, everything else is CPU-only).

### Fields available per report

Graded signal: `risk_assessment.severity` (4-way ordinal — **the primary metric**).
Unexplored: `risk_assessment.confidence`, `recommended_actions` (closed-vocab, 18 observed),
`recommended_actions_freeform_experimental`, `uncertainty_notes`, `alert_summary`,
`triage_rationale_experimental`. Structural: `investigation_timeline` (9 steps × step/action/
tool/timestamp/summary), `status`, `model_metadata`, `command_analysis` (PowerShell only, 156/624).

### Not recorded

**Prompts** (`input` is null on all 5,616 timeline steps — reconstructible from versioned
templates in `app/agent/prompts.py` plus the per-block corpus copy), **token counts**
(never captured, so all cost figures are estimates), **reasoning traces**.

### Dead axes — do not build on these

- `enrichment_findings`: present on all 624 but every verdict is `unknown`, provider `none`. Enrichment was off by design for the whole sweep.
- `base64 recall`: 100% for every model. Saturated.
- `model_metadata.model_version`: `'none'` on all 624. Never populated.

---

## 3. What has already been analysed

`bench.score` produces per-config: benign escalation, needle recall, fp-control escalation,
triage accuracy, mean severity distance, self-check flag counts, median latency, footprint,
and a per-cluster escalation table.

`bench.analyze` produces: latency percentiles, self-check signal, confidence calibration,
action counts and remediation-verb scan, cross-model action agreement.

**Headline findings already written into `PROGRESS.md`** — read it before re-deriving anything:

1. More reasoning is **actively harmful** on the FP control (`gpt-oss:20b` 0/6 → 6/6 wrong at default effort). Three models show `low` ≥ higher effort.
2. The self-check predicts a wrong report **only where it is selective** — `gemma4:12b` flags 28% and those are 3× more likely wrong (25% vs 74% correct); models flagging 90% discriminate barely; `lfm2:24b-a2b`'s flags are anti-correlated.
3. Stated confidence is **anti-calibrated** on both gemmas ("high" less accurate than "medium"), properly calibrated on `gpt-oss`. Confirms CLAUDE.md §4.2 rule 3 empirically.
4. KV cost spans **84×** and is uncorrelated with size; quantisation leaves KV untouched (q4 and q8_0 identical at 69.2 MB/1K).
5. Models fail **by cluster** and the clusters invert between them (15/15 vs 0/15 on the same cluster).
6. Scaling up trades detection for noise suppression — a move along a curve, not a quality difference.
7. 624/624 constrained steps completed; only `self_check` ever degraded (51×).

---

## 4. Open angles, tiered

**Tier 3 — cheap, data on disk, unexplored**
- `recommended_actions` quality and per-model variation (18 distinct actions; counts vary 2.0–9.1 per report)
- `uncertainty_notes` content — what do models actually claim they could not verify?
- Constrained vs free-form **actions** — both answer the same question under different constraints, which makes this the one *clean* ablation available

**Tier 4 — needs new runs**
- A proper harness ablation: same question asked constrained and unconstrained. **Note:** the severity-vs-`triage_verdict_experimental` pairing is *not* this — those come from different steps asking different questions, and an earlier session wrongly called it a controlled ablation.
- Frontier reference arm via the `LLMClient` Protocol (~$11 on a Sonnet-tier API for the whole sweep; would settle whether the harness or the model is the ceiling)
- Cost figures with measured tokens

**Presentation shape suggested previously:** tiers 1–2 are the spine — the benign/needle
trade-off frontier, the reasoning-effort finding, and KV/max-affordable-context; supported by
per-cluster blindness, the mrahman causal claim, the resilience result, and the small-sample
methodology slide.

---

## 5. Constraints that will bite

- **Needle recall is n=5 even at the deep stage.** A 60%-vs-100% gap is two alerts. Always quote the count.
- **Screen-stage (n=11) numbers are unreliable.** Benign escalation moved up to 28 points between n=4 and n=60; triage accuracy collapsed for 4 of 5 models. Use deep-stage figures only.
- **Effort was not held constant in Stage 1** — it was a time-budget lever. The confound was closed for the deciding comparison only. Within-effort brackets are valid; cross-effort ones are not.
- **Footprint figures in any text written before 16 Aug are 7.7% high** (decimal GB re-multiplied by 1024³). Fixed; `stage0-ladder.jsonl` and `analysis.json` are correct.
- **Wall clock is Mac Studio.** Any number that goes on a slide as "how fast the demo runs" needs a calibration pass on the M4 Pro.

## 6. Working practice for this project

**Measure before asserting.** A striking number of confident, plausible statements on this
project have been wrong when checked — including several in the benchmark track itself: a
7.7% footprint error that survived a full gate and two writeups because it reordered
nothing; a "clean ablation" that compared two different questions; a dead-model gate field
that was never populated; a benign-escalation prediction wrong by 28 points. Prefer a
30-second probe to a confident sentence, and state sample sizes rather than implying
reliability that is not there.

**Never destroy existing results.** An earlier gate truncated its own output file and lost
17 models' worth of measurements. Analysis code writes new files and upserts by key; keep
it that way.
