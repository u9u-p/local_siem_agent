# Design Document: Report Observability and Markdown Export

**Date:** 17 Aug 2026
**Source requirements:** User request (four tasks, see Context), CLAUDE.md §2.3 (`Report` model), §4.1 (state sequence), §4.2 rule 5 (prompt versioning)

---

## Context

Four changes to how an investigation's output is recorded and presented. Three are small; one changes the `LLMClient` Protocol, which is why this is specified rather than implemented directly.

1. **The database and the JSON file disagree.** `_step_finalize_and_persist` saves the report and *then* the caller appends the finalize step to the timeline, so every `reports` row has 8 steps while every `data/reports/*.json` has 9. Confirmed across all five committed reports.
2. **The timeline records only a one-line summary per step.** `InvestigationStep.input` exists but is `None` on every step ever written, there is no `output` field, and nothing anywhere records what the model was asked, what it answered, how long it took, or how many tokens it burned. A report that took six minutes on a timed-out self-check says only `self-check call failed`.
3. **`show-report` cannot display the experimental triage output** — partly because it does not try, and partly because `ReportRecord` has no columns for `triage_verdict_experimental` / `triage_rationale_experimental`, so the values are silently dropped on save and are `None` on every read.
4. **Reports are only machine-readable.** The JSON is for tooling; there is no artefact an analyst can paste into a ticket.

Decisions confirmed with the user during brainstorming:

1. **Verbatim capture.** Step records store the full prompt string and the raw model response, not a hash or a reference. Chosen over typed-payload-plus-prompt-reference for reproducibility and prompt debugging. See §7 for what this implies about report contents.
2. **The Protocol returns a wrapper.** `generate_structured` returns `LLMResponse[T]` carrying both the parsed value and the call record. Chosen over a stateful `last_call()` accessor and over a caller-owned collector argument: it is explicit, stateless, and cannot silently drop a call.
3. **Markdown is always written**, alongside the JSON, with no flag.
4. **`output_summary` strings are frozen.** `bench/score.py` and `bench/analyze.py` regex-parse them; new data is added in new fields.

---

## 1. Data Model Changes

### 1.1 `LLMCallRecord` (new, `app/llm/client.py`)

One record per `generate_structured` call — not per HTTP attempt. The schema retry at `ollama_client.py:46` means one logical call can be two attempts; the record aggregates them.

| Field | Type | Notes |
|---|---|---|
| `prompt_ref` | str | The builder that produced the prompt, e.g. `build_risk_assessment_prompt`. Passed by the caller; the client cannot know it |
| `prompt` | str | Verbatim, first attempt only — the retry prompt is the same text plus a fixed suffix, and storing both doubles the payload for no information |
| `retried` | bool | True when the schema retry fired; with `prompt` above this fully determines the second prompt |
| `raw_response` | str \| None | The model's unparsed text. `None` when the first attempt parsed cleanly (the parsed object is the faithful record in that case); populated whenever an attempt failed to parse, which is the case worth debugging |
| `reasoning` | str \| None | The model's reasoning trace, verbatim, last attempt. See §1.1.1 — this is the bulk of what the model generates and it is invisible in both `raw_response` and the token counts |
| `parsed_output` | dict \| None | `model_dump(mode="json")` of the validated result; `None` on failure |
| `attempts` | int | 1 or 2 |
| `prompt_tokens` | int \| None | Summed across attempts |
| `completion_tokens` | int \| None | Summed across attempts. **Counts the JSON content only, not the reasoning trace** — see §1.1.1 |
| `latency_ms` | int | Monotonic clock across all attempts, including a failed one |
| `error_kind` | str \| None | `LLMClientError.kind` when the call failed; `None` on success |

The token fields stay nullable as cheap defensiveness against a future backend or model that omits `usage`, but on the current stack it is populated — see §1.1.1.

#### 1.1.1 Measured behaviour of Ollama's `usage` (verified 17 Aug 2026, `gemma4:12b`)

Probed directly against `POST /v1/chat/completions` and again through the `openai` SDK's `beta.chat.completions.parse` — the exact path `OllamaClient` uses:

- **`usage` is populated.** `CompletionUsage(prompt_tokens=450, completion_tokens=18, total_tokens=468)`.
- **`prompt_tokens` tracks input size** and is trustworthy: 450 for a 43-character prompt, 1366 for a 6.5KB one. The ~450 floor is chat-template and schema-injection overhead, not the user prompt.
- **`completion_tokens` excludes the reasoning trace.** The same response carried 1,608 characters (~400 tokens) of `message.reasoning` while reporting `completion_tokens: 18` — the length of the JSON object alone. On this model the reported figure understates what was generated by roughly 20×.

Two consequences for this design:

1. **`completion_tokens` must never be presented as a cost or throughput figure**, and nothing in the report or the benchmark should sum it into one. It is a measure of structured output size. `latency_ms` is the honest measure of what a call cost, which is also what `ollama_client.py`'s existing `reasoning_effort` comment already concluded from a different direction.
2. **The reasoning trace is worth capturing.** It is the majority of the model's output, it explains verdicts that the parsed JSON only asserts, and it is currently discarded. The SDK exposes it as `message.reasoning` through `model_extra` (confirmed: `hasattr(message, "reasoning")` is `True`, `model_extra` keys are `['reasoning']`). It is captured verbatim, consistent with the verbatim decision for prompts and raw responses.

Reasoning is stored for the last attempt only. On a retry the first attempt's reasoning led to output that failed validation and is preserved in `raw_response`; storing two full traces per call for that is not worth the payload.

### 1.2 `LLMResponse[T]` (new, `app/llm/client.py`)

```python
class LLMResponse(BaseModel, Generic[T]):
    value: T
    call: LLMCallRecord
```

### 1.3 `LLMUsageTotals` (new, `app/schemas.py`)

Report-level rollup: `calls`, `failed_calls`, `attempts`, `prompt_tokens: int | None`, `completion_tokens: int | None`, `reasoning_chars`, `llm_latency_ms`, `wall_clock_ms`. Token totals are `None` if any contributing call reported `None`, so a partial sum is never presented as a complete one.

`reasoning_chars` is summed character length, not tokens, and is deliberately not called a token count — per §1.1.1 the reasoning trace is untokenised by `usage`, and inventing a tokens-from-characters estimate would produce a number that looks authoritative and is not. It exists so the gap between `completion_tokens` and what the model actually generated is visible at report level rather than only by reading the traces.

`wall_clock_ms` is measured across `investigate()` and is the honest end-to-end number; `llm_latency_ms` is the share of it spent waiting on the model. The difference is SIEM search and enrichment HTTP time.

### 1.4 `InvestigationStep` (modified, `app/schemas.py`)

| Field | Change |
|---|---|
| `input` | Unchanged type (`dict \| None`), now actually populated — see §2 |
| `output` | **New**, `dict \| None` — the typed result the step produced |
| `llm_calls` | **New**, `list[LLMCallRecord]`, default empty |
| `output_summary` | **Unchanged, and its exact wording is frozen** |

Both new fields default, so every existing report JSON and `reports` row still validates.

### 1.5 `Report` (modified, `app/schemas.py`)

Gains `llm_usage: LLMUsageTotals`. No other change — `triage_*_experimental` already exist on the model; they are missing from the *table*, which §4 fixes.

---

## 2. What Each Step Records

`input` is what the step consumed, `output` is what it produced. Both are typed dumps, not prose. LLM prompts live in `llm_calls[].prompt`, not in `input` — `input` is the step's own arguments.

| Step | `input` | `output` |
|---|---|---|
| `ingest_and_parse` | `{alert_id, rule_id, rule_level, model_available}` | `{}` |
| `extract_indicators` | `{full_log_chars, data_keys, extra_texts_count}` | `{regex: {candidates, validated}, llm: {candidates, validated}, decode: {segments, discarded}, indicators: [{type, value}]}` |
| `enrich` | `{indicators: [{type, value}]}` | `{results: [{type, value, provider_id, verdict, score, error}]}` |
| `gather_context` | `{agent_id, rule_id}` | `{agent_context, rule_metadata}` — the two typed objects, or `null` on degrade |
| `correlate` | `{templates_built: [...], enrichment_verdicts: [...]}` | `{canonical: {template: {total_count, distinct_counts}}, pattern_type, follow_up: {...} \| null, open_value: {...} \| null, evidence_count}` |
| `risk_assessment` | `{pattern_type, evidence_count, enrichment_verdicts, has_command_context, has_raw_log}` | The `RiskAssessment` dump |
| `draft_report` | Same shape as `risk_assessment`, plus `{severity, confidence}` | `{canonical: {...}, experimental: {...} \| null}` |
| `self_check` | `{claims: [...]}` | `{audits: [...], flagged_claims: [...], corrections_applied: bool}` |
| `finalize_and_persist` | `{report_id, alert_id}` | `{persisted: bool}` |

`gather_context` is worth calling out: `_agent_context` and `_rule_metadata` are currently fetched and then **discarded** — assigned to underscore-prefixed locals and never used. Recording them in `output` is the first time the data this step pays a round-trip for actually reaches the report. This makes visible what CLAUDE.md §4.1 step 4 always claimed the step contributes.

---

## 3. LLM Client Changes

### 3.1 `LLMClient` Protocol (`app/llm/client.py`)

```python
def generate_structured(self, prompt: str, schema: type[T], prompt_ref: str) -> LLMResponse[T]: ...
```

`prompt_ref` is a required positional argument rather than optional-with-default: a default would let a call site silently produce unlabelled records, and there are only seven call sites.

### 3.2 `OllamaClient` (`app/llm/ollama_client.py`)

- `generate_structured` starts a `time.monotonic()` timer, runs the existing attempt/retry logic unchanged, and builds the record from what `_attempt` observed.
- `_attempt` returns the parsed value *and* the `usage` object rather than just the value, so token counts survive. Its exception-ordering comments and behaviour are otherwise untouched.
- Token counts sum across attempts; `attempts` and `retried` follow from the existing control flow.

### 3.3 `LLMClientError` (`app/llm/errors.py`)

Gains `call: LLMCallRecord | None = None`. Every raise site in `ollama_client.py` populates it, so a failed call still reports its latency, attempt count and prompt.

This is the change that pays for itself immediately: report `1bc7f75a` spent roughly six minutes on a self-check that timed out, and the only trace is the string `self-check call failed; corrections not applied`. After this change that call appears in the timeline with `error_kind="timeout"` and its real `latency_ms`.

### 3.4 `state_graph.py` call sites

Seven: `_extract_indicators_via_llm`, `_classify_correlation`, `_run_open_value_search`, `_assess_risk`, `_draft_canonical`, `_draft_experimental`, `_run_self_check`. Each already has a `try/except LLMClientError` block; each gains `.value` on the success path and `exc.call` on the failure path, appending to a per-step list. The existing degrade behaviour and `_degraded_reasons` strings do not change.

---

## 4. Storage Changes

### 4.1 The missing finalize step

`_step_finalize_and_persist` is restructured to build the step *before* persisting:

1. Build the success-shaped `InvestigationStep` and append it to `report.investigation_timeline`.
2. Attempt `save_report()` + `update_alert_status()`.
3. On failure, replace that last timeline entry with the degraded one.

One write, no upsert, no second `save_report` call. The DB and the JSON file then carry the same nine steps. The failure path stays honest in both directions: nothing is in the DB (correct — the save failed), and the JSON file, which `write_report_file` produces after `investigate()` returns, records the degraded step.

The step describing its own persistence is inside the persisted payload. That is inherently self-referential but it is what makes the two artefacts agree, which is the point of the task.

**The five existing 8-step `reports` rows are left as they are.** They are historical, and the benchmark corpus reads the JSON files, not the database. No backfill script.

### 4.2 `ReportRecord` (`app/storage/models.py`)

Three new columns:

- `triage_verdict_experimental: str | None`
- `triage_rationale_experimental: str | None`
- `llm_usage: dict[str, Any]` (JSON)

`_report_to_record` and `_record_to_report` map all three. The first two are the actual blocker for §5 — without them `show-report` has nothing to display, because the values never reached the database.

There is no Alembic migration in this project (`init_db` calls `SQLModel.metadata.create_all`). New columns therefore do not appear on the existing `data/alerts.db`. Since the five stored reports are demo data, the documented step is to delete `data/alerts.db` and re-pull, not to migrate. This is stated in `PROGRESS.md` as part of the change.

---

## 5. CLI and Rendering Changes

### 5.1 `app/report_render.py` (new)

Splitting section *content* from section *rendering* is what keeps the terminal output and the Markdown file from drifting:

```python
@dataclass
class Section:
    title: str | None
    body: list[str]        # lines
    bullets: list[str]     # rendered as "  - x" / "- x"

def report_sections(report: Report) -> list[Section]: ...
def render_text(sections: list[Section]) -> str: ...
def render_markdown(sections: list[Section]) -> str: ...
```

`report_sections` is the single definition of which sections exist, in what order, and when a section is omitted. `cli._format_report_detail` becomes `render_text(report_sections(report))` and produces byte-identical output to today's format for the sections that already exist — the existing CLI tests are the guard on that.

`render_markdown` maps the same sections to `##` headings and `-` bullets, with a `# Investigation Report <id>` title and an `_Internal — Ryt Bank_` footer.

### 5.2 The experimental section

Appended after `Recommended actions`, omitted entirely when both triage fields and the freeform list are empty:

```
EXPERIMENTAL — unvetted model output. Not audited by the self-check pass.
Do not action without analyst review.

  Triage verdict: true_positive
  <rationale>

  Freeform actions:
    - ...
```

The disclaimer is part of the section body, so it cannot be rendered without it. In Markdown it becomes a `> ` blockquote under a `## Experimental (unvetted)` heading.

This section is intentionally *not* fed by `report_sections` into any machine-readable path — it stays display-only, consistent with CLAUDE.md §2.3's framing of `recommended_actions` as the sole canonical field.

### 5.3 `write_report_file` (`app/report_export.py`)

Writes both files and returns both paths:

```python
def write_report_file(report: Report, reports_dir: Path) -> tuple[Path, Path]:
```

`bench/run.py:112` globs `*.json` and takes `files[0]`, so the sibling `.md` does not affect the benchmark harness. The two CLI call sites ignore the second element or print it.

The timeline's per-step `input`/`output`/`llm_calls` are **not** rendered into the Markdown — it mirrors `show-report`, which lists step names and actions only. The verbose trace stays in the JSON, which is where tooling reads it.

---

## 6. Testing

Follows the existing suite's shape: unit tests with fakes, live tests gated on `LLM_MODEL` being reachable.

- **`tests/test_ollama_client.py`** — extend the existing `respx`-mocked tests: usage present → record populated; usage absent → `None` tokens, everything else populated; retry path → `attempts=2`, `retried=True`, `raw_response` holds the first bad response; each error kind → `LLMClientError.call` populated with a plausible `latency_ms`.
- **`tests/test_state_graph.py`** — the fake client returns `LLMResponse`. New assertions: every step has non-`None` `input`; each LLM step's `llm_calls` has the expected length (step 7 → 2 always; step 5 → 1, or 2 when the open-value search fires — the follow-up hop is a SIEM search, not an LLM call); a failing call still contributes a record with `error_kind`; `report.llm_usage.calls` equals the number of records across the timeline; **`output_summary` strings are asserted unchanged** against the current values, as the explicit guard on the benchmark's regexes.
- **`tests/test_sqlite_alert_store.py`** — round-trip the three new columns; assert a saved report's timeline length equals the in-memory report's (the regression test for §4.1).
- **`tests/test_report_export.py`** — both files written; JSON still round-trips to an equal `Report`; the `.md` contains the section headings.
- **`tests/test_report_render.py`** (new) — section omission rules; `render_text` output matches the current `_format_report_detail` format; the experimental disclaimer is present whenever the experimental body is.
- **`tests/test_cli.py`** — `show-report` prints the experimental section when populated and omits it when not.

**The Ollama usage question is resolved** — §1.1.1 records the measured answer, taken before implementation began. The remaining live check is confirmation on a real end-to-end run rather than a probe: one `investigate-one`, then confirm `prompt_tokens` is non-`None`, `reasoning` is populated on the steps that use a reasoning model, and `completion_tokens` is visibly smaller than `reasoning_chars / 4` — the signature of the accounting gap §1.1.1 describes.

---

## 7. Assumptions and Consequences

- **Verbatim prompts put unvalidated raw log text into every report file.** `_raw_log_block` feeds `full_log` to steps 6-8 for alerts with no typed fields, and the enrichment and correlation blocks carry indicator values and usernames. Storing prompts verbatim means all of that is duplicated into `data/reports/*.json` and into the `reports` table. This is acceptable while alerts are self-authored (CLAUDE.md §8) and the system is a POC on synthetic data. **Before this agent is pointed at real SIEM data, the retention and classification of report artefacts needs a decision** — the reports become a second copy of log content in a second location with a different lifecycle. Flagged here so it is not discovered later.
- **Report size roughly triples** for reports without large enrichment payloads (~4KB → ~30KB). Prompts account for ~12KB (the action-catalogue prompt alone is ~1.2KB and appears in two calls) and reasoning traces for ~11KB more, at the ~1.6KB per call measured in §1.1.1 across 6-7 calls. Still negligible against the ~100KB VirusTotal `raw_response` blobs already stored.
- **`bench/score.py::_step_seconds` is superseded but not removed.** It infers per-step latency by diffing consecutive timeline timestamps; `llm_calls[].latency_ms` now measures the model's share directly. Rewiring the benchmark to the real numbers is deliberately out of scope — it would require re-running the corpus, and the existing results were measured with the current method.
- **No Alembic migration**; the documented path is to recreate `data/alerts.db`.
- `prompt_version` in `model_metadata` moves `4d-v1` → `4e-v1`, since the recorded shape of a report changes even though no prompt text does.

---

## 8. Files Touched

| File | Change |
|---|---|
| `app/llm/client.py` | `LLMCallRecord`, `LLMResponse[T]`, Protocol signature |
| `app/llm/errors.py` | `LLMClientError.call` |
| `app/llm/ollama_client.py` | Timing, usage capture, record construction |
| `app/agent/state_graph.py` | 7 call sites, per-step `input`/`output`/`llm_calls`, `llm_usage` rollup, `_step_finalize_and_persist` reorder |
| `app/schemas.py` | `LLMUsageTotals`, `InvestigationStep.output`/`.llm_calls`, `Report.llm_usage` |
| `app/storage/models.py` | 3 new columns |
| `app/storage/sqlite_alert_store.py` | Map the 3 new columns |
| `app/report_render.py` | New |
| `app/report_export.py` | Write `.md` alongside `.json` |
| `app/cli.py` | `_format_report_detail` delegates to `report_render` |
| `tests/` | 6 files, one new |
| `PROGRESS.md`, `CLAUDE.md` §2.3 | Record the new fields and the db-recreation step |

---

## Verification

1. `pytest -q` passes with no skips (Wazuh stack up, `gemma4:12b` pulled).
2. A real `investigate-one` produces a `.json` and a `.md` with the same `report_id`; the `.md` sections match `agent show-report <id>` line for line.
3. `sqlite3 data/alerts.db "select json_array_length(investigation_timeline) from reports"` returns 9 for newly-written reports.
4. `bench/score.py` and `bench/analyze.py` still parse a freshly-generated report without modification.
5. `report.llm_usage.calls` equals the count of `llm_calls` entries across the timeline, and `wall_clock_ms >= llm_latency_ms`.
