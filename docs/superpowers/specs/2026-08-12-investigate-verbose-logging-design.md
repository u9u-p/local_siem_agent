# Design Document: Verbose Logging for `investigate-all` / `investigate-one`

**Date:** 12 Aug 2026
**Source requirements:** ad hoc feature request — see this session's brainstorming for full context.

---

## Context

The Agentic Analyst's 9-step state graph (`app/agent/state_graph.py`, Phases 4b-4d) currently gives no visibility into what each step actually saw or produced while an investigation is running — `InvestigationStep.input` is `None` in every single occurrence across the whole file (confirmed by inspection), and `output_summary` is a terse one-liner meant for the persisted report, not for debugging. This feature adds an opt-in, DEBUG-level trace of every step's real input and output to the `investigate-all`/`investigate-one` CLI commands (`app/cli.py`, Phase 5), directable to stdout or a file.

Decisions confirmed during brainstorming:

1. **Mechanism** — Python's standard `logging` module, not a new callback/hook interface. `app/agent/state_graph.py` gains a module logger; `app/cli.py` configures its level and handler based on new CLI options.
2. **Scope** — verbose mode affects only this project's own loggers (the `"app"` logger and its children), not third-party libraries (`httpx`, `openai`). Third-party request/response logging stays off regardless of `--verbose`.
3. **Detail level** — for the six LLM-calling steps, the logged input is the *exact* prompt string sent to the model, and the logged output is the *exact* structured result (`model_dump_json()`) or the fallback used and why. No truncation or summarization.

This is a standalone feature addition, not part of the original phase numbering — it's scoped narrowly enough for one spec/plan/build cycle.

---

## 1. Logging instrumentation (`app/agent/state_graph.py`)

Add near the top of the file, after the imports:

```python
import logging

logger = logging.getLogger(__name__)
```

This gives the logger name `app.agent.state_graph` — a child of the `"app"` logger the CLI configures (see §2), so it inherits `"app"`'s level and handlers without needing its own explicit configuration.

**Every one of the 9 `_step_*` methods** gets two additions:
- One `logger.debug(...)` call immediately after the method's docstring/signature, logging its actual parameters (excluding `self`) relevant to understanding what it's about to do.
- One `logger.debug(...)` call immediately before *each* `return` statement in the method, logging the values about to be returned.

**Every one of the 7 LLM-calling helper methods** (`_extract_indicators_via_llm`, `_classify_correlation`, `_run_open_value_search`, `_assess_risk`, `_draft_canonical`, `_draft_experimental`, `_run_self_check`) gets:
- One `logger.debug(...)` call logging the exact `prompt` string, immediately before the `self._llm_client.generate_structured(prompt, ...)` call.
- One `logger.debug(...)` call logging the exact result on the success path (via `result.model_dump_json()`), and a separate one on the `except LLMClientError` path logging the exception's `.kind` and what fallback is being used instead.

Concretely, per method:

| Method | Step-level input logged | Step-level output logged | LLM-call prompt/response logged? |
|---|---|---|---|
| `_step_ingest_and_parse` | `alert.alert_id`, `alert.rule_id`, `model_available` | the step's `output_summary` | no (no LLM call) |
| `_step_extract_indicators` | `alert.alert_id`, `model_available` | the merged indicator list (`[(type, value), ...]`) | via `_extract_indicators_via_llm` |
| `_extract_indicators_via_llm` | — (helper, not a `_step_*`) | — | yes — prompt, then `ExtractedIndicators.model_dump_json()` or the `LLMClientError.kind` |
| `_step_enrich` | the indicator list going in | the `EnrichmentResult` list (verdict/score/provider per indicator) | no |
| `_step_gather_context` | `alert.agent.id`, `alert.rule_id` | the `AgentContext`/`RuleMetadata` pair, or the `SIEMConnectorError.kind` | no |
| `_step_correlate` | `alert.alert_id` | `pattern_type`, `evidence_count`, and the canonical/follow-up/open-value notes | via `_classify_correlation`, `_run_open_value_search` |
| `_classify_correlation` | — | — | yes — prompt, then `CorrelationDecision.model_dump_json()` or the fallback used |
| `_run_open_value_search` | — | — | yes — prompt, then `OpenValueSearchProposal.model_dump_json()` (or "skipped: call failed") |
| `_step_risk_assessment` | `pattern_type`, `evidence_count`, enrichment count | the `RiskAssessment` (`model_dump_json()`) | via `_assess_risk` |
| `_assess_risk` | — | — | yes — prompt, then `RiskAssessment.model_dump_json()` or the fallback used |
| `_step_draft_report` | `pattern_type`, `evidence_count`, `risk_assessment.severity` | the `DraftReportCanonical` and `DraftReportExperimental` (or `None`) | via `_draft_canonical`, `_draft_experimental` |
| `_draft_canonical` | — | — | yes — prompt, then `DraftReportCanonical.model_dump_json()` or the fallback used |
| `_draft_experimental` | — | — | yes — prompt, then `DraftReportExperimental.model_dump_json()` or "failed" |
| `_step_self_check` | the incoming `draft` (`model_dump_json()`) | the corrected draft, `flagged_claims`, `uncertainty_notes` | via `_run_self_check` |
| `_run_self_check` | — | — | yes — prompt, then `SelfCheckResult.model_dump_json()` or the failure kind |
| `_step_finalize_and_persist` | `report.report_id` | the persistence outcome (`"persisted"` or the exception text) | no |

This avoids double-logging: the step-level log for an LLM-calling step covers its *surrounding* context (what fed into the call, what the step as a whole produced), while the helper-level log covers the actual prompt/response — the two are complementary, not redundant.

---

## 2. CLI options (`app/cli.py`)

`investigate_all_cmd` and `investigate_one_cmd` both gain two new options:

```python
verbose: bool = typer.Option(False, "--verbose", "-v", help="Log each pipeline stage's input/output at DEBUG level."),
log_file: Path = typer.Option(None, "--log-file", help="Write verbose logs to this file instead of stdout. Implies --verbose."),
```

A new shared function configures logging, called once at the top of each command body, before any other work:

```python
def _configure_verbose_logging(verbose: bool, log_file: Path | None) -> None:
    logger = logging.getLogger("app")
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    if not verbose and log_file is None:
        return
    logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(log_file, mode="a") if log_file is not None else logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logger.addHandler(handler)
```

Configuring the `"app"` logger specifically (not the root logger) means every module under `app.*` — including `app.agent.state_graph` — inherits this level/handler by Python logging's normal parent-propagation, without touching `httpx`'s or `openai`'s own loggers, matching decision 2 above.

**Unconditionally clearing existing handlers first** makes the function idempotent: safe to call multiple times in one process (relevant for tests, where `CliRunner.invoke()` runs commands in-process rather than as subprocesses — without this, repeated test invocations would accumulate handlers on the shared `"app"` logger across tests, causing duplicate log lines or writes to already-closed file handles from a previous test's `tmp_path`).

**`--log-file` implies verbose** — passing a file path alone (without `-v`) still enables DEBUG-level tracing, directed to that file. Passing neither leaves logging exactly as it is today (no behavior change for existing, non-verbose usage).

**Append mode** (`mode="a"`) for the file handler — repeated runs accumulate in the same file rather than clobbering earlier traces, useful when investigating one alert at a time across several invocations.

---

## 3. Testing

- `tests/test_state_graph.py` — a handful of `caplog`-based tests (pytest's built-in log-capture fixture), not one per method exhaustively. Cover: one step with no LLM call (`_step_enrich`, proving indicator/verdict data appears), one step with an LLM call (`_step_risk_assessment`/`_assess_risk`, proving the prompt and the `RiskAssessment` JSON both appear), and `_step_self_check`/`_run_self_check` (proving the claim-audit detail appears, since that's the step with the most non-obvious internal logic). Each test sets `caplog.set_level(logging.DEBUG, logger="app.agent.state_graph")` and asserts specific expected substrings appear in `caplog.text` — not exhaustive snapshot-matching, just proof the wiring fires with real content, not empty/placeholder log calls.
- `tests/test_cli.py` — tests for `_configure_verbose_logging` directly: verbose-only attaches a `StreamHandler` at DEBUG level; `log_file`-only attaches a `FileHandler` at DEBUG level pointed at the given path (and actually writes the file when the command runs); neither option leaves the logger unmodified (no handler added, level untouched); calling it twice in a row never leaves more than one handler attached (proving the idempotency fix works, not just asserting it exists).

---

## Open Items

None outstanding — all decisions confirmed during brainstorming (see Context, decisions 1-3).
