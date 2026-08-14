# Design Document: Local Model Selection Benchmark

**Date:** 14 Aug 2026
**Source requirements:** user brainstorm 14 Aug 2026; `ROADMAP.md` Demo Readiness (HITCON 2026); `PROGRESS.md` Mac Studio verification and Scenario E

---

## Context

`gemma4:12b` became the project default in Phase 4b on the strength of one round of short probe prompts against one alternative (`qwen3.5:9b`). Since then the real per-step prompts exist, the corpus has grown to 112 alerts across eight log sources, and the demo target has changed: the talk runs on a **MacBook Pro M4 Pro, 24GB**, not the 128GB Mac Studio every measurement to date was taken on. CLAUDE.md §7.1's memory budget, declared moot in `PROGRESS.md` because of the Studio, is back in force.

This document specifies an offline benchmark whose single output is a decision: **which one local model runs on stage.**

Decisions confirmed with the user during brainstorming:

1. **One model runs on stage; the comparison is never run live.** `gemma4:12b` is the incumbent, not locked.
2. **The demo laptop is an M4 Pro 24GB**, leaving roughly **17–18GB** for the model after macOS (~3GB) and presentation software (~3GB). This is a hard gate, not a preference.
3. **The benchmark runs entirely on the Mac Studio, one box** — Wazuh, Ollama and the agent colocated. This removes the network dependency and the second machine from a 13-hour unattended run. The demo topology (SIEM on a separate host) is deliberately *not* reproduced for the benchmark.
4. **Latency is the only metric that does not transfer between hosts**, so the winning model gets a **calibration pass on the M4 Pro** — three needles, one run each. Laptop numbers are quoted for the demo alerts, Studio numbers for the accuracy scoreboard. No scaling factors.
5. **Graded fields are `risk_assessment.severity` and `triage_verdict_experimental`.** Not prose, not recommended actions.
6. **The corpus gains benign floods for email and logins** so all three headline use cases have Scenario E's shape.
7. **No application behaviour is changed to make results better.** The `_findings_block`/Correlate defect and the domain over-extraction defect stay exactly as documented; both become graded items rather than bugs to hide.

---

## 1. Corpus — three matched scenarios

The three use cases the talk covers are the three noisiest alert classes in a real SOC: **emails, logins, AI-driven PowerShell.** Scenario E (added 14 Aug) is gradeable because of its shape — 40 benign to 1 malicious, every one matching a single parent-agnostic rule at one level, so the SIEM contributes no separation and all discrimination must come from the model. Neither of the other two has that shape today: `mimecast_sample.log` is four log lines with no benign traffic at all, and the login sources have matched `*-fp` *pairs* rather than a flood.

| Category | Benign flood | Needle | Precision counterpart |
|---|---|---|---|
| AI PowerShell | 40 — exists (`dev_ai_tools.json`) | `wscript.exe` → `45.146.164.110` — exists | — |
| Emails | **~35 new** — held newsletters, bulk mail, benign impersonation flags, DMARC softfails | `secure-invoice-updates.com` chain — exists | — |
| Logins | **~35 new** — routine logons, known users, known source IPs, business hours | `45.146.164.110` SSH success — exists | mrahman VPN — exists |

Constraints on the new seed data, inherited from Scenario E's design:

- Benign and malicious events in a category **must match the same rule at the same level**. If the SIEM separates them, the benchmark measures the ruleset, not the model.
- Base64, addresses and hostnames stay genuine and internally consistent — `45.146.164.110` is already both the PowerShell needle's C2 and the successful SSH login, and the login flood should preserve that link rather than introduce a third unrelated address.
- No application code changes. New rules follow the `100075` precedent: anything the Risk step needs must reach it through the rule description, which is the only channel carrying event fields into the prompts (`app/agent/prompts.py`).

Resulting corpus: roughly **180 alerts**, balanced three ways, with ground truth true by construction.

---

## 2. Graded items — three classes, scored separately

These are never averaged into one number. A model can be excellent at one and useless at another, and the point of the exercise is to see that.

**Discriminating set.** The three benign floods against their three needles. This is the ranking signal and the bulk of the graded items.

**Capability probe.** Does the model decode UTF-16LE base64 in-head at step 2b and surface `45.146.164.110` and `http://45.146.164.110:8080/u` as typed indicators? Neither value appears in any plaintext field of the alert; `source_ip` and `destination_ip` are both `None`. `gemma4:12b` does this on 8 of 8 runs. It is binary, objectively checkable against `Report.enrichment_findings`, and needs no rubric.

**Precision pair.** The mrahman VPN false positive. Per the 14 Aug controlled follow-up, its escalation is driven by **Correlate classifying `pattern_type=lateral_movement`**, not by `evidence_count` (which is near-inert: a benign alert at count 41 still returns `medium`, the needle at 36 returns `high`). Correlate's classification is an LLM call, so this is a live test of whether a model over-classifies a pattern from counts alone — not, as first assumed, a harness-bound constant.

---

## 3. Metrics

**Accuracy**
- `severity_distance` — expected vs actual on an ordinal scale, so `high` vs `low` counts worse than `high` vs `medium`.
- `triage_accuracy` — `triage_verdict_experimental` against the constructed label.
- **`benign_escalation_rate` per category** — share of benign alerts reaching `high` or above. This is alert fatigue, measured, and it is the talk's actual subject.
- **`needle_recall` per category** — does the one that matters come out `high` and `TRUE_POSITIVE`.

**Capability**
- `base64_recall` — binary, per run, on the PowerShell needle.
- `self_check_flag_rate` — claims flagged unsupported ÷ claims audited. `gemma4:12b` currently flags 0 of 13 and 0 of 9. A model that never flags anything is rubber-stamping, which is precisely what the design claims to prevent, so this measures the thesis directly.

**Reliability**
- `degraded_step_count` — timeline entries with `action="degraded"`, plus the share of runs ending `NEEDS_HUMAN_REVIEW`. True `generate_structured()` retry counts are internal to `OllamaClient` and not recorded in the report; instrumenting for them is deferred unless Stage 0 shows it matters, since Stage 0's smoke test already catches the catastrophic case.
- `verdict_variance` — spread across the three repeat runs on each needle. For a live demo, a model that is stable at 80% beats one averaging 85% that occasionally embarrasses you on stage. Stability is a selection criterion here, not a footnote.

**Speed and footprint**
- Wall-clock per alert and per step, derived from `investigation_timeline` timestamps — no new instrumentation.
- **Peak resident memory** via `ollama ps` for the loaded model, with `ps` polling during a live investigation for true peak including KV cache. Host-independent for a given model+quant, so the Studio measurement answers the laptop's fit question.
- Tokens/sec as a secondary signal only.

---

## 4. Staging

| Stage | Scope | Cost |
|---|---|---|
| **0 — Gate** | Per candidate: pull, measure peak RSS against the 17–18GB ceiling, and fire one `generate_structured()` call with a trivial schema | minutes |
| **1 — Screen** | Survivors × (1 benign + 1 needle per category) × 1 run | ~40 min/candidate |
| **2 — Deep** | Finalists × (10 benign/category × 1 run) + (3 needles × 3 runs) + (mrahman × 3 runs) | ~4 h/finalist |
| **3 — Calibrate** | Winner only, on the M4 Pro: 3 needles × 1 run | ~30 min |

Three finalists at Stage 2 is roughly 13 hours, unattended. Breadth for the floods (the variance that matters is across alerts) and depth only on the three alerts that must be stable on stage.

**Stage 0 is the highest-value part of this spec and is owed work regardless.** `PROGRESS.md` risk #9 already asks for exactly this — a capability check distinct from `model_available()`, which only confirms a model is *pulled*, not that its backend can do constrained decoding. Ollama's MLX backend silently ignores `response_format`; the Apple-Silicon-optimised `muse-glimmer:30b-mlx` tag is therefore expected to fail this gate despite being the tag most obviously suited to the hardware. Without Stage 0, such a model degrades every report to `NEEDS_HUMAN_REVIEW` and scores as merely cautious on every accuracy metric above.

**Candidate shortlist**

| Model | Approx. size | Note |
|---|---|---|
| `gemma4:12b` | ~8 GB | Incumbent; the baseline everything is measured against |
| `qwen3.5:9b` | ~7 GB | Already validated in this repo, already pulled |
| `gpt-oss:20b` | ~14 GB | Already pulled on the dev host |
| Mistral Small 3.2 24B | ~14 GB | Documented function-calling improvements |
| `qwen3.6:27b` | ~16 GB | Already pulled; marginal against the ceiling |
| Ternary Bonsai 27B | ~5.9 GB | Ternary quant of Qwen3.6-27B. Published ablation shows tool-calling degrades worst under aggressive quantization (−17.5% at 1-bit vs −3.8% math), which is exactly this pipeline's load-bearing capability. Informative either way |
| Muse Glimmer 30B | 18 GB GGUF / 21 GB MLX | Meta, 10 Aug 2026, Apache 2.0, agentic-tuned. Does not fit the demo laptop. Benchmarked on the Studio as the measured "what 24GB costs you" datapoint |

---

## 5. Harness

Reuses the existing CLI; no framework, no new dependency. Roughly 150 lines across a runner and a scorer, under `bench/`.

**Runner.** Snapshot `alerts.db` **once** and hand every model an identical copy. This matters: `evidence_count` varies by ingestion position, so a shared snapshot is what makes the comparison fair across models. Per run — copy the snapshot, set `LLM_MODEL`, `DATABASE_PATH` and `REPORTS_DIR`, invoke `investigate-one`, retain the exported report JSON. All three are already env-driven via `pydantic-settings`, so no wiring changes are needed.

**Labelling by content predicate, not by alert ID.** `alert_id` is `uuid5` of the Wazuh source id, which is `<epoch>.<counter>` and therefore changes whenever the stack is re-seeded. An ID-keyed labels file would silently rot on every re-seed. Labels are instead derived from stable alert content — rule id plus a discriminator (`parentImage` contains `wscript.exe`; sender is `secure-invoice-updates.com`; source address is `45.146.164.110`) — as a small deterministic function, ~30 lines, that survives re-ingestion.

**Scorer.** Reads exported report JSON against the labeller and emits a per-run CSV plus a per-model markdown scoreboard. It reads the **exported JSON, not the database**: `triage_verdict_experimental` and `triage_rationale_experimental` have no `ReportRecord` columns (Demo Readiness item 10), so they survive export and vanish through SQLite. Grading needs no DB round-trip, so the two columns stay deferred.

---

## 6. Prerequisite fix

`app/agent/state_graph.py:679` hardcodes `model_name="gemma4:12b"` in `_assemble_report`. Every exported report would misattribute its own model, making the entire benchmark unreadable. This is the Minor deferred three times across Phases 4b, 4c and 5; a model comparison is the first thing that actually breaks on it. Read it from the injected `LLMClient` or `Settings.llm_model`. Two lines plus a test.

This is the only application-code change in scope.

---

## 7. Known confounds — documented, not fixed

- **Domain over-extraction** (`_DOMAIN_RE`) pulls hostnames and dotted usernames (`victimcorp.com`, `ke.li.yam`) in as DOMAIN indicators, and with no VirusTotal key configured they resolve `unknown` and get narrated in the summary instead of the real signal. This corrupts report *prose*, not the graded fields, and hits every model equally. An optional near-free check — does `alert_summary` mention PowerShell or the parent process at all — surfaces the quality gap that severity alone cannot. `gemma4:12b` currently fails it.
- **`evidence_count` varies by ingestion position**, neutralised by the shared DB snapshot (§5).
- **Wazuh stamps ingestion time, not event time**, and every manager-side seeded alert is `agent.id 000`, so neither date-spreading nor host-spreading affects correlation. Do not attempt to control `evidence_count` by either.

---

## 8. Non-goals

- Fixing `_findings_block` or Correlate's `pattern_type` classification. It is a graded item now; changing it mid-benchmark would invalidate the mrahman comparison.
- `EnrichmentCache`, `ReportRecord` triage columns, and the `on_step` hook — all remain deferred.
- Benchmarking against public agentic-SOC benchmarks. Researched separately on 14 Aug: no reputable open benchmark scores a SIEM-alert-triage agent end to end, confirmed by the May 2026 survey (arXiv 2605.08316). CyberSOCEval (Meta/CrowdStrike) is the only reputable open defensive-SOC benchmark and grades models, not pipelines. Post-talk track.

## 9. Open items

- Whether Stage 2's benign sample of 10 per category gives enough resolution on `benign_escalation_rate`; 10 gives 10% granularity, and widening it is the first thing to spend spare compute on.
- Whether the winner justifies revisiting Correlate's `pattern_type` before the talk, or whether the honest-limitation framing stands.

## Verification

This is a design document. Verification is review, not test execution:

1. Confirm every graded item has ground truth derivable from seed-data structure alone, with no hand-labelling and no ID-keyed state that re-seeding would invalidate.
2. Confirm no step of this design changes model-visible behaviour — prompts, schemas, findings blocks and extraction all stay as they are, so the benchmark measures models rather than a moving target.
3. Confirm the Stage 0 gate would actually reject a model whose backend ignores `response_format`, which is the failure mode that scores as caution rather than as breakage.
