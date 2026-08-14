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
7. **Correlate's count-only prompt is fixed before the sweep starts, not after.** Grading models against an information-starved Correlate measures reluctance to classify rather than judgement, and rewards precisely the hedging disposition that would miss the needles — see §6.2. Beyond that, no application behaviour changes to make results better: the domain over-extraction defect stays exactly as documented.

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

**Built and verified 14 Aug.** Corpus is **182 alerts**, of which **128 sit in four gradeable clusters**, each verified through `wazuh-logtest` and then end to end through `pull-alerts`:

| Cluster | Rule / level | Benign : target | Discriminator carried in the description |
|---|---|---|---|
| AI PowerShell | `100075` / 10 | 40 : 1 | `wscript.exe` vs `node.exe`, `Cursor.exe`, … |
| Emails | `106001` / 5 | 35 : 1 | `@secure-invoice-updates.com` vs `@atlassian-notify.net`, … |
| Logins (SSH) | `100080` / 3 | 30 : 1 | `jsmith from 45.146.164.110` vs `ltan from 203.0.113.74` |
| Logins (Windows) | `100061` / 3 | 18 : 2 | `mrahman from 100.72.44.19` vs `raj.kumar from 10.20.4.73` |

One new rule was needed, `100080`. Stock rule `5715`'s description is a bare `"sshd: authentication success."` carrying neither user nor source address, and since neither `build_risk_assessment_prompt` nor `build_correlation_decision_prompt` is passed `source_ip`, all 31 SSH logons were identical from the model's point of view — the cluster would have contributed noise while looking like a real graded category. `100080` interpolates `$(dstuser)` and `$(srcip)`, inheriting level 3 and `5715`'s T1078/T1021 mapping, exactly as `100061` and `100075` already do on the Windows and Sysmon sides.

---

## 2. Graded items — three classes, scored separately

These are never averaged into one number. A model can be excellent at one and useless at another, and the point of the exercise is to see that.

**Discriminating set.** The three benign floods against their three needles. This is the ranking signal and the bulk of the graded items.

**Capability probe.** Does the model decode UTF-16LE base64 in-head at step 2b and surface `45.146.164.110` and `http://45.146.164.110:8080/u` as typed indicators? Neither value appears in any plaintext field of the alert; `source_ip` and `destination_ip` are both `None`. `gemma4:12b` does this on 8 of 8 runs. It is binary, objectively checkable against `Report.enrichment_findings`, and needs no rubric.

**Precision pair.** The mrahman VPN false positive, graded only *after* §6.2 lands. Its escalation is driven by **Correlate classifying `pattern_type=lateral_movement`**, not by `evidence_count` (near-inert: a benign alert at count 41 still returns `medium`, the needle at 36 returns `high`).

While Correlate sees only a count, this item is unusable as a discriminator and was wrongly placed here in the first draft. The eight alerts that resolve the case are retrieved and then discarded, so no model can reason to the right verdict — it can only decline to guess wrong. Scoring that rewards reluctance to classify, which is **anti-correlated with needle recall**: a hedging model wins here and misses the `wscript.exe` needle. Once Correlate receives a digest of what it actually found, the item becomes a genuine test of whether a model reads its own correlated evidence.

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
- **Throughput and reasoning length, measured separately.** These are not proportional and ranking on either alone is wrong. Measured 14 Aug: `qwen3.5:9b` has the third-highest throughput of eight candidates and the slowest wall clock by 1.8x, because it emits 19,539 characters of reasoning for a 304-character answer — 98% reasoning. `mistral-small3.2` is the mirror image: lowest throughput of all eight, second-fastest wall clock, because it reasons not at all. A model that is slow through over-reasoning may be fixable with a reasoning-budget setting; one that is slow on throughput is not, so the two must never be collapsed into a single "speed" figure.
- **Do not use `tok/s` from Ollama's OpenAI-compat `usage`.** Its `completion_tokens` does not account for reasoning consistently — `gemma4:12b` reported 49 completion tokens for roughly 1,600 characters of reasoning plus answer, off by about 8x — so any derived tok/s systematically flatters terse models and understates reasoning ones, which is precisely the bias this metric exists to expose. Characters generated are observed output and need no accounting from the server.
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
| Muse Glimmer 30B | 18 GB GGUF / 21 GB MLX | Meta, 10 Aug 2026, Apache 2.0, agentic-tuned. Expected not to fit — **wrong, see Stage 0 results below**: 17.0 GB at bounded context, marginally under the ceiling |

### Stage 0 results — measured 14 Aug, Mac Studio

Every candidate cleared all three schema probes, so **constrained decoding is now proven for this shortlist rather than assumed** — no MLX-style backend failure among them, all being GGUF. Footprints are at `num_ctx=8192`; probe seconds are Studio numbers and do **not** transfer to the M4 Pro (§ context decision 4).

One representative schema-constrained call per model, warmed first so model load is not charged to it. Studio numbers; wall clock does **not** transfer to the M4 Pro (context decision 4). Single calls, so this measures capability and shape, not reliability.

| Model | Footprint | Wall | chars/s | Reasoning share |
|---|---|---|---|---|
| `gpt-oss:20b` | 12.0 GB | 4.0s | **454** | 85% |
| `gemma4:latest` (8B) | 9.6 GB | 5.6s | 344 | 88% |
| `qwen3.5:9b` | 5.7 GB | **66.8s** | 297 | **98%** |
| `gemma4:12b` (incumbent) | 8.4 GB | 8.2s | 185 | 84% |
| `mistral-small3.2` | 15.0 GB | 2.0s | 121 | **0%** |
| `muse-glimmer:30b` | 17.0 GB | 24.9s | 117 | 91% |
| `qwen3.6:27b` | 16.0 GB | 37.2s | 99 | 93% |

**Ranking by throughput and by wall clock produces almost unrelated orderings**, and only `gpt-oss:20b` is top-two on both. `qwen3.5:9b` is the clearest illustration — third-fastest generation, slowest end to end by 1.8x, because 98% of its output is reasoning. `mistral-small3.2` inverts it: the slowest generator finishes second-fastest by not reasoning at all, which is a prediction the graded clusters can test, since terse non-reasoning may cost accuracy.

**Muse Glimmer fits after all**, at 17.0 GB against a 17.5 GB ceiling — correcting the shortlist row above, which reasoned from its 18 GB download. But that leaves about half a gigabyte before the agent process and anything else on the machine: viable-but-marginal, not safe.

Nothing was rejected, so the Stage 1 shortlist is unchanged. The gate's value was converting three assumptions into measurements, two of which were wrong.

**Consequence for the design: the axis is (model × reasoning effort), not model alone**, wherever a candidate exposes the control. `muse-glimmer:30b` ships `low`/`medium`/`high`/`xhigh`; its 24.9s at 91% reasoning is a default-configuration number, not a ceiling. A model that is slow through over-reasoning is mis-configured rather than disqualified, and Stage 1 should sweep the effort levels for any candidate offering them before that candidate is ranked.

---

## 5. Harness

Reuses the existing CLI; no framework, no new dependency. Roughly 150 lines across a runner and a scorer, under `bench/`.

**Runner.** Snapshot `alerts.db` **once** and hand every model an identical copy. This matters: `evidence_count` varies by ingestion position, so a shared snapshot is what makes the comparison fair across models. Per run — copy the snapshot, set `LLM_MODEL`, `DATABASE_PATH` and `REPORTS_DIR`, invoke `investigate-one`, retain the exported report JSON. All three are already env-driven via `pydantic-settings`, so no wiring changes are needed.

**Labelling by content predicate, not by alert ID.** `alert_id` is `uuid5` of the Wazuh source id, which is `<epoch>.<counter>` and therefore changes whenever the stack is re-seeded. An ID-keyed labels file would silently rot on every re-seed. Labels are instead derived from stable alert content — rule id plus a discriminator (`parentImage` contains `wscript.exe`; sender is `secure-invoice-updates.com`; source address is `45.146.164.110`) — as a small deterministic function, ~30 lines, that survives re-ingestion.

**Scorer.** Reads exported report JSON against the labeller and emits a per-run CSV plus a per-model markdown scoreboard. It reads the **exported JSON, not the database**: `triage_verdict_experimental` and `triage_rationale_experimental` have no `ReportRecord` columns (Demo Readiness item 10), so they survive export and vanish through SQLite. Grading needs no DB round-trip, so the two columns stay deferred.

---

## 6. Prerequisite fixes

Three fixes plus one enabling change (§6.4), all landing before the first benchmarked model runs. Nothing else under `app/` is touched.

### 6.1 — `model_name` is hardcoded

`app/agent/state_graph.py:679` sets `model_name="gemma4:12b"` in `_assemble_report`, so every exported report would misattribute its own model and the scoreboard would be unreadable. Read it from the injected `LLMClient` or `Settings.llm_model`. Two lines plus a test. This is the Minor deferred three times across Phases 4b, 4c and 5; a model comparison is the first thing that actually breaks on it.

### 6.2 — Correlate is given counts, not evidence

`build_correlation_decision_prompt` ([prompts.py:18](app/agent/prompts.py:18)) receives `canonical_results`, whose `SearchResult` carries `alerts: list[Alert]` alongside `total_count`, and renders only the count. For mrahman the eight discarded alerts **are** the answer: his own ocserv connect, the `100.72.44.19` egress assignment, the approved MFA push. From the integer `8`, no model can reason to the right verdict; it can only decline to guess wrong. Benchmarking on that measures disposition rather than judgement, and selects for hedging — see §2.

The data is present, ingested, retrieved, and thrown away one function short of the prompt. This is an implementation shortcut, not an architectural constraint: CLAUDE.md §4.2 rule 2 already permits the fix, since correlation results and rule metadata are structured findings, not raw logs.

**Confirmed blocking beyond mrahman, 14 Aug.** A sanity-check run reproduced the defect in the email category, in a near-controlled comparison — same log line, same model, same prompts, `evidence_count` the only variable:

| Benign Acme Cloud newsletter | `evidence_count` | Verdict |
|---|---|---|
| Before `data.srcip` was indexed for Mimecast | 3 | `medium` / `low` / uncertain |
| After | 10 | `high` / `high` / **`TRUE_POSITIVE`** |

The rationale named the cause itself: *"the high volume of evidence (10 indicators) strongly suggests a targeted phishing campaign."* This also corrects the 14 Aug conclusion that `evidence_count` is "close to inert" — that held for Scenario E only because its rule description names `node.exe` or `Cursor.exe`, which read as obviously benign. `106001`'s description ("Message ⟨id@domain⟩ held for review") carries no such counter-signal, so the count decides. **`evidence_count` is not inert; it is overridden when the description gives the model something better.** Since 35 of 36 email alerts sit on shared provider IPs with high counts, benign escalation approaches 100% without this fix, for reasons unrelated to model quality.

**Pass a deduplicated digest — distinct rule descriptions with counts — not the alert list.** mrahman expands to the three descriptions that matter; a Scenario E alert correlating 41 near-identical events collapses to roughly one line. That preserves §4.2 rule 2's small-prompt property and its latency, and yields more signal exactly where there is more diversity, at near-zero cost where there is not.

`pattern_type` flows into the Risk prompt for **every** alert, so this must land before the first benchmarked model and stay frozen for the rest of the sweep — changing it mid-run would shift severity across the whole graded set, not just the one false positive. Re-verify the three demo scenarios afterwards. The base64 result is unaffected: step 2b runs upstream of Correlate.

### 6.3 — Mimecast's sending IP is not mapped

`wazuh_source_to_alert` populated `Alert.source_ip` from `data.srcip` with a fallback to `data.win.eventdata.ipAddress` (added 12 Aug for Windows logons), but Mimecast puts the sending IP at `data.mimecast.IP` and never sets `data.srcip`. All 36 email alerts therefore carried `source_ip=None`, and `SAME_SRC_IP_24H` — the first pivot a real analyst reaches for on a phishing alert — was skipped for the entire email category. Fixed by adding `mimecast.get("IP")` as a third fallback, with two tests covering the fallback and its precedence against an explicit `data.srcip`. Verified: 36/36 after a fresh pull.

This is a mapper change, not a model-visible prompt change, but it alters `evidence_count` for email alerts and so is subject to the same freeze as §6.2 — it must land before the first benchmarked model, not during the sweep.

---

### 6.4 — `OllamaClient` cannot send a reasoning budget

Not a defect, an enabling change, and the only one that grew scope: Stage 0 measured reasoning length rather than throughput as the dominant driver of wall clock (§4), so ranking a reasoning model at whatever effort it happens to default to would rank a configuration, not a model. `muse-glimmer:30b` spends 91% of its output reasoning at its default and ships `low`/`medium`/`high`/`xhigh`; `qwen3.5:9b` spends 98%.

Verified that Ollama honours `reasoning_effort` on the OpenAI-compatible endpoint — `gpt-oss:20b` emits 428 characters of reasoning at `low` against 3,698 at `high` on an identical prompt. There is **no Modelfile equivalent**: both `PARAMETER think` and `PARAMETER reasoning_effort` are rejected as unknown, so unlike `num_ctx` this cannot be baked into a variant and must be sent per request. That is why it needs a client change at all.

`OllamaClient` takes an optional `reasoning_effort`, `Settings` grows `llm_reasoning_effort`, and `bench/run.py` takes `--effort`. **Default is unset and the parameter is then omitted from the request entirely** — covered by its own test — so with no configuration the pipeline behaves exactly as before. That default-off property is what keeps this outside the freeze that applies to §6.1–6.3: it changes nothing unless deliberately set.

## 7. Known confounds — documented, not fixed

- **Domain over-extraction** (`_DOMAIN_RE`) pulls hostnames and dotted usernames (`victimcorp.com`, `ke.li.yam`) in as DOMAIN indicators, and with no VirusTotal key configured they resolve `unknown` and get narrated in the summary instead of the real signal. This corrupts report *prose*, not the graded fields, and hits every model equally. An optional near-free check — does `alert_summary` mention PowerShell or the parent process at all — surfaces the quality gap that severity alone cannot. `gemma4:12b` currently fails it.
- **`evidence_count` varies by ingestion position**, neutralised by the shared DB snapshot (§5).
- **Wazuh stamps ingestion time, not event time**, and every manager-side seeded alert is `agent.id 000`, so neither date-spreading nor host-spreading affects correlation. Do not attempt to control `evidence_count` by either.
- **Enrichment runs with no providers registered, deliberately.** Neither API key is configured, so `EnrichmentRegistry` is empty and every alert degrades through the existing `no_provider_registered` path. This is a requirement, not an accident: without `EnrichmentCache` (deferred, Phase 6), a sweep of 182 alerts across several models with repeats would exhaust VirusTotal's shared 500/day partway through, and models run later would receive rate-limited `UNKNOWN` verdicts that models run earlier did not — making the ranking depend on run order. Every cluster above discriminates through the rule description alone, so nothing is lost by keeping providers off. **Do not enable keys mid-sweep.**
- **Benign email senders share provider IPs, which inverts the correlation signal — and the trap fires.** Bulk mail really does come from shared pools, so eight unrelated newsletter domains sit on one SendGrid address, seven on Mailchimp, five on Microsoft 365, four on Google Workspace, while the phishing chain has only three alerts on `185.220.101.47`. Four benign clusters out-correlate the needle. Confirmed empirically on 14 Aug: with §6.2 not yet landed, a routine Acme Cloud product newsletter came out `high`/`high`/`TRUE_POSITIVE`, its rationale stating that *"the high volume of evidence (10 indicators) strongly suggests a targeted phishing campaign"* — while the actual phish scored `evidence_count=2` and was escalated correctly, on domain plausibility. This is the mrahman defect reproduced in an independent category. Until §6.2 lands, the email cluster grades disposition rather than judgement, exactly as mrahman does.

---

## 8. Non-goals

- Fixing the domain over-extraction defect (`_DOMAIN_RE`). It corrupts report prose but not the graded fields, and hits every model equally — see §7.
- Any change under `app/` beyond §6's four, and any further change to §6.2 or §6.3 once the sweep has started.
- `EnrichmentCache`, `ReportRecord` triage columns, and the `on_step` hook — all remain deferred.
- Benchmarking against public agentic-SOC benchmarks. Researched separately on 14 Aug: no reputable open benchmark scores a SIEM-alert-triage agent end to end, confirmed by the May 2026 survey (arXiv 2605.08316). CyberSOCEval (Meta/CrowdStrike) is the only reputable open defensive-SOC benchmark and grades models, not pipelines. Post-talk track.

## 9. Open items

- Whether Stage 2's benign sample of 10 per category gives enough resolution on `benign_escalation_rate`; 10 gives 10% granularity, and widening it is the first thing to spend spare compute on.
- What replaces the talk's count-only-correlation limitation slide. The `evidence_count` diagnosis it rested on was already superseded by the 14 Aug controlled follow-up, and §6.2 removes the behaviour it described, so that narrative needs rewriting regardless of this benchmark.

## Verification

This is a design document. Verification is review, not test execution:

1. Confirm every graded item has ground truth derivable from seed-data structure alone, with no hand-labelling and no ID-keyed state that re-seeding would invalidate.
2. Confirm §6's two fixes both land before the first benchmarked model, and that nothing model-visible changes after that point — prompts, schemas and extraction stay frozen for the rest of the sweep, so the benchmark measures models rather than a moving target.
3. Confirm the Stage 0 gate would actually reject a model whose backend ignores `response_format`, which is the failure mode that scores as caution rather than as breakage.
