# Design Document: Model Benchmark Harness

**Date:** 12 Aug 2026
**Source requirements:** none in `app_requirement.md`/`CLAUDE.md` directly — this is dev tooling to make the model-choice decision CLAUDE.md §6 already treats as first-class (and `PROGRESS.md` has so far only probed ad hoc) repeatable and scored.

---

## Context

`PROGRESS.md` documents one-off probes comparing `qwen3.5:9b` and `gemma4:12b` on 3 toy-shaped schemas — useful, but explicitly flagged as leaving real gaps open: whether a model is *reliably* correct across repeated calls (risk #2), not just capable once; behavior on the real, deeper-nested `Report` schema (risk #3); and a hard GGUF-vs-MLX structured-output gate (risk #9, confirmed). This project also already has 4 GGUF models pulled locally (`gemma4:12b`, `qwen3.5:9b`, `qwen3.6:27b`, `gpt-oss:20b`) with no repeatable way to compare them against ground truth.

This is a standalone dev/benchmarking tool, not a pipeline feature — it doesn't touch `app/agent/state_graph.py`'s production code path (`investigate()` is never modified), and it isn't part of the `agent` CLI's user-facing surface.

Decisions confirmed with the user during brainstorming:

1. **Static frozen fixtures, not live Wazuh/enrichment calls.** The golden dataset is captured once from a real Wazuh stack and real enrichment providers, then frozen — the benchmark itself runs fully offline, reproducibly, and without spending AbuseIPDB/VirusTotal quota per run.
2. **Isolated per-step scoring, not cascading.** Each of the 7 LLM call sites is benchmarked with the *same* fixed golden inputs regardless of which model is under test, so an error is attributable to the exact step that caused it. One additional full `investigate()` pass per model (still against frozen upstream data) produces a top-line composite score.
3. **Pluggable, runtime-selected scoring.** Enum/set-based objective scorers always run; a deterministic proxy scorer and an LLM-judge scorer for free text are both built but opt-in via a CLI flag, decided per invocation rather than hardcoded.
4. **Multiple runs per alert per step.** Repeated calls on identical input measure both accuracy (vs. ground truth) and consistency (agreement with itself) — directly answering `PROGRESS.md` risk #2.
5. **New golden alerts authored through the real Wazuh stack**, not hand-crafted JSON — extending `wazuh_deployment/single-node/sample-logs/` and capturing genuine decoder/rule output, consistent with this project's own repeated lesson (`PROGRESS.md`, multiple phases) that a hand-authored fake can silently diverge from what the real system actually produces.
6. **Standalone script**, not an `agent` CLI subcommand — kept separate from the production investigation CLI.

---

## 1. Golden Dataset

**Location:** `benchmarks/golden/` (new top-level dir — checked into git, unlike `data/` which is gitignored runtime output).

**Composition — 11 alerts:**

| Alert slug | Source | Expected pattern | TP/FP |
|---|---|---|---|
| `auth` | existing `auth.log` | none (ordinary successful login) | — |
| `auth-fp` | existing `auth-fp.log` | none | FP |
| `windows-security` | existing `windows_security.json` | none/other | — |
| `windows-security-fp` | existing `windows_security_fp.json` | none | FP |
| `vpn` | existing `vpn.log` | none/other | — |
| `mimecast-phishing` (existing) | `mimecast_sample.log` | none/other | TP |
| `endpoint` | existing `endpoint_alerts_sample.json` | none/other | — |
| `ssh-bruteforce` (**new**) | new lines in `sample-logs/`, real Wazuh stock brute-force rule | `brute_force` | TP |
| `ssh-mistyped-fp` (**new**) | new lines in `sample-logs/`, a few ordinary failed logins | `none` | FP |
| `phishing-attachment` (**new**) | new Mimecast-style lines, existing custom decoder/rules | `none/other`, malicious | TP |
| `vendor-invoice-fp` (**new**) | new Mimecast-style lines, legitimate but surface-suspicious | `none` | FP |

The 4 new alerts are added to `sample-logs/`, wired into `config/wazuh_cluster/wazuh_manager.conf` per that directory's existing "adding new mock logs" process, and captured by running the real stack once — never hand-authored JSON.

**Per-alert directory** (`benchmarks/golden/<slug>/`):

- **`alert.json`** — the frozen `Alert` object, produced by `wazuh_source_to_alert()` against the real captured indexer document.
- **`correlation.json`** — frozen canonical `SearchResult`s for the 3 canonical searches (`same_src_ip_24h`, `same_rule_id_host`, `same_dst_host`), captured live once. This is Correlate/Risk Assessment/Draft's shared, fixed upstream evidence.
- **`enrichment.json`** — frozen `EnrichmentResult` list, captured live once against real AbuseIPDB/VirusTotal.
- **`expected.json`** — hand-authored ground truth:
  - `expected_indicators: list[{type, value}]` — for extraction precision/recall.
  - `expected_pattern_type`, `expected_severity`, `expected_confidence`, `expected_triage_verdict` — for exact-match scoring.
  - `key_facts: list[str]` — short factual statements a correct summary/rationale must not contradict (e.g. `"file_hash e4d909... verdict=clean"`), used by the proxy and judge scorers.
  - `poisoned_claim: {draft: DraftReportCanonical, wrong_claim_index: int}` — a fixed, otherwise-golden Draft-A with exactly one deliberately-false claim, for scoring Self-Check.

A fixture-validation check runs at harness startup: every `expected.json` is parsed against a small `ExpectedGroundTruth` Pydantic model, and every enum value referenced is checked against the real `app.agent.schemas` enums — a malformed or stale fixture fails loudly before any model calls are made, not silently mis-scored.

---

## 2. Harness Architecture

`scripts/benchmark_models.py`. No changes to `app/agent/state_graph.py`.

### 2.1 Isolated per-step mode (primary)

For each `(model, alert, step)`, a lightweight `AgenticAnalyst` is constructed with a real `OllamaClient(model=...)` but stub `SIEMConnector`/`AlertStore`/`EnrichmentRegistry` (never touched, since the private step method is called directly rather than `investigate()` — the same pattern `tests/test_state_graph.py` already uses, per `PROGRESS.md`'s note that tests use `_step_extract_indicators` as a fixture helper). The relevant private method is called with that alert's frozen `correlation.json`/`enrichment.json` as input, `N` times (`--runs`, default 3):

| Step | Method called | Frozen input |
|---|---|---|
| Extract Indicators | `_extract_indicators_via_llm` | `alert.json` |
| Correlate (classification) | `_classify_correlation` | `alert.json` + `correlation.json` |
| Correlate (open-value, conditional) | `_run_open_value_search` | `alert.json` + `correlation.json` |
| Risk Assessment | `_assess_risk` | `alert.json`, golden `pattern_type`/`evidence_count`, `enrichment.json` |
| Draft-A (canonical) | `_draft_canonical` | above + golden `RiskAssessment` |
| Draft-B (experimental) | `_draft_experimental` | same as Draft-A |
| Self-Check | `_run_self_check` | `poisoned_claim.draft` + golden findings |

### 2.2 End-to-end composite mode (secondary, one pass per model)

A real `AgenticAnalyst.investigate()` call per model, using a fixture-backed fake `SIEMConnector` (returns `correlation.json` verbatim instead of querying a live indexer) and a fixture-backed fake `EnrichmentRegistry`/provider (returns `enrichment.json` instead of calling AbuseIPDB/VirusTotal). Each model's own step outputs cascade into its later steps here — this produces one realistic top-line `Report` per model per alert, while keeping the Wazuh/enrichment side of the world identical and reproducible across models.

### 2.3 Raw output logging

Every call — both modes — is written to `data/benchmarks/<run-id>/raw/<model>/<alert>/<step>/<run-n>.json` (prompt, schema name, raw output, latency, whether the retry-once path was used) **before** any scoring runs, so a scoring bug never loses underlying evidence.

### 2.4 Error handling

Each `(model, alert, step, run)` call is wrapped individually — an `LLMClientError` records that run as `failed: <kind>` rather than aborting the sweep. A model that fails the structured-output smoke test (2.5) for a given step skips its remaining repetitions for that step (no point burning `N` more calls on a deterministic failure) but other models/steps continue unaffected.

### 2.5 Structured-output compatibility gate

Before running any golden-dataset calls for a model, one trivial-schema + one deeply-nested-schema (`list[ClaimAudit]`-shaped) smoke call is made, 3x each. A model that fails either is marked `INCOMPATIBLE` for every step up front (see Section 4) rather than silently scoring near-zero across the whole sweep — directly operationalizing `PROGRESS.md` risk #9.

---

## 3. Scoring Layer

Selected via `--scoring enum,proxy,judge` (comma list; `enum` always runs regardless of the flag, since it's free and fully objective):

- **`EnumExactMatchScorer`** (always on) — exact match against `expected.json` for `pattern_type`, `severity`, `confidence`, `triage_verdict`.
- **`IndicatorSetScorer`** (always on) — precision/recall of extracted `(type, value)` pairs against `expected_indicators`.
- **`SelfCheckAuditScorer`** (always on) — did the model flag `wrong_claim_index` as unsupported (recall on the injected error) and did it avoid flagging any genuinely-correct claim (false-positive rate)?
- **`DeterministicProxyScorer`** (`--scoring proxy`) — checks free text (`alert_summary`, `rationale`, Draft-B freeform actions) against `key_facts` for contradiction and coverage via keyword/substring heuristics.
- **`LLMJudgeScorer`** (`--scoring judge`, requires `--judge-model`) — a rubric call (groundedness 1-5, coverage 1-5, contradiction bool) scoring free text against `key_facts`, using a model distinct from the one being graded.

**Aggregation per `(model, step)`:** accuracy = mean score across alerts × runs; consistency = agreement rate among the `N` repeated runs on the same alert (independent of whether they're *correct* — a model that's always confidently wrong the same way is consistent but inaccurate; both numbers are reported).

---

## 4. Output & CLI

```
python scripts/benchmark_models.py \
  --models gemma4:12b,qwen3.5:9b,qwen3.6:27b,gpt-oss:20b \
  --runs 3 \
  --scoring enum \
  [--judge-model <name>] \
  [--steps extract_indicators,correlate,...] \
  [--alerts auth-fp,mimecast-phishing]
```

`--models` defaults to the 4 already-pulled GGUF models; `--steps`/`--alerts` default to all, narrowable for a fast iteration loop while developing the harness itself.

Outputs under `data/benchmarks/<run-id>/` (gitignored, like the rest of `data/`):

- `raw/...` — per Section 2.3.
- `scores.jsonl` — one row per `(model, alert, step, run, scorer)`, append-only, so an interrupted run leaves usable partial data.
- `summary.md` — one table per step (rows = models; columns = accuracy, consistency, schema-pass-rate, p50 latency), plus a "worst offenders" list of specific `(alert, run)` misses with a pointer to the matching raw file. A model marked `INCOMPATIBLE` (Section 2.5) gets its own row stating that, never a numeric 0%.

---

## 5. Testing

- `EnumExactMatchScorer`, `IndicatorSetScorer`, `SelfCheckAuditScorer`, `DeterministicProxyScorer` are pure functions over `(expected, actual)` — unit-tested with synthetic fixtures, no LLM involved, same style as the rest of `tests/`.
- Harness orchestration (fixture loading, stub `AgenticAnalyst` construction, raw-output logging) gets one integration test using a fake `LLMClient` test double, following the existing `_FakeLLMClient` pattern in `tests/test_state_graph.py`.
- `LLMJudgeScorer` is not meaningfully unit-testable (correctness depends on a real judge model's actual output) — covered by manual spot-checks only, documented as such rather than faked.
- The fixture-validation check (Section 1) is itself tested against one deliberately malformed `expected.json` to confirm it fails loudly.

---

## Open Items

- **Judge-model choice** — left as a required explicit `--judge-model` flag rather than a default, since using one of the candidate models to judge itself (or its peers) is a real methodological concern worth a deliberate choice each run, not a silent default.
- **Draft-B freeform actions / experimental triage rationale** — covered by proxy/judge scoring like other free text, but not by any exact-match scorer, consistent with CLAUDE.md's own treatment of this field as experimental/unvetted.
- **New sample-log authoring** — the 4 new alerts require Docker running once to capture real decoder/rule output; this is a one-time authoring cost, not part of the harness's runtime.
- **Future extension** — nothing here precludes adding more golden alerts later; the per-alert directory structure and fixture-validation check are the only contract new alerts need to satisfy.
