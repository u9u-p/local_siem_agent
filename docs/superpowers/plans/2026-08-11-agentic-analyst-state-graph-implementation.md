# Agentic Analyst — Deterministic Pipeline Skeleton (Phase 4b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Agentic Analyst's deterministic FSM dispatcher — the `Step` enum, the `AgenticAnalyst` class with an `investigate(alert) -> Report` entry point, every step that needs no LLM (Ingest & Parse, Gather Host/Rule Context, Finalize & Persist), the deterministic half of the partly-LLM steps (regex indicator extraction, enrichment routing), skip-condition logic, and `InvestigationStep` timeline logging for every step including the six LLM-calling ones, which are wired in as inert stubs.

**Architecture:** `AgenticAnalyst` is a plain class with one private method per step, called in a fixed, hardcoded sequence from `investigate()` — not a generic transition-table FSM (per CLAUDE.md §6's own rationale for a hand-rolled dispatcher over a framework). Every step method is defensively isolated: it returns a degraded `InvestigationStep` on failure rather than raising, so no single step aborts the whole investigation. `LLMClient` gains a `model_available()` preflight method (distinct from the existing reachability-only `health_check()`), threaded through to the six stub steps so their logged reason differs honestly between "not yet implemented" and "model unavailable."

**Tech Stack:** Python 3.11+, pydantic v2 (existing `Alert`/`Report`/`InvestigationStep` schemas), pytest, respx (for the `OllamaClient` addition only) — no new dependencies.

## Global Constraints

- No new dependencies.
- The verdict-reconciliation branch (CLAUDE.md §4.1 step 3's conditional call) is dropped entirely, not stubbed — Phase 2b's one-provider-per-indicator-type architecture means two providers can never disagree on the same indicator, so this branch can never fire. The Enrich step is a plain per-indicator loop with no reconciliation code path at all.
- LLM-calling steps (indicator candidate extraction 2b, Correlate, Risk Assessment, Draft Report, Self-Check) are thin stubs only in this plan — no `generate_structured()` calls, no per-step response schemas. That is explicitly Phase 4c/4d's scope; blurring it here would undo the reason the Agentic Analyst was split into sub-phases.
- `Step` is a plain naming enum for timeline entries, not a transition-table — `investigate()` calls step methods in a fixed, hardcoded order with no dispatch-by-enum lookup.
- Every `_step_*` method that talks to an external dependency (`SIEMConnector`, `EnrichmentRegistry`) catches its own expected error types and returns a degraded `InvestigationStep` instead of raising — a step's own failure never aborts `investigate()`.
- Host/asset-criticality lookup (CLAUDE.md's "config/inventory, never an LLM guess") is an explicit non-goal in this plan — no config/inventory concept is invented here.
- A 4b-era `Report.status` is always `NEEDS_HUMAN_REVIEW` — nothing in a stub-only run has been genuinely assessed.
- TDD: every method gets a failing test before implementation. Commit after each task.

---

### Task 1: `LLMClient.model_available()`

**Files:**
- Modify: `app/llm/client.py`
- Modify: `app/llm/ollama_client.py`
- Modify: `tests/test_llm_client_protocol.py`
- Modify: `tests/test_ollama_client.py`
- Modify: `tests/test_ollama_client_live.py`

**Interfaces:**
- Produces: `LLMClient.model_available() -> bool` (Protocol), `OllamaClient.model_available() -> bool` (implementation) — consumed by Task 3's `AgenticAnalyst.investigate()` preflight call and Task 6's stub steps.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_ollama_client.py` (after the existing `test_health_check_returns_false_on_connection_error` test):

```python
@respx.mock
def test_model_available_returns_true_when_configured_model_is_pulled():
    respx.get(f"{BASE_URL}models").mock(
        return_value=httpx.Response(
            200,
            json={
                "object": "list",
                "data": [{"id": "qwen3.5:9b", "object": "model", "created": 0, "owned_by": "library"}],
            },
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.model_available() is True


@respx.mock
def test_model_available_returns_false_when_configured_model_is_not_pulled():
    respx.get(f"{BASE_URL}models").mock(
        return_value=httpx.Response(
            200,
            json={
                "object": "list",
                "data": [{"id": "llama3:8b", "object": "model", "created": 0, "owned_by": "library"}],
            },
        )
    )
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.model_available() is False


@respx.mock
def test_model_available_returns_false_on_connection_error():
    respx.get(f"{BASE_URL}models").mock(side_effect=httpx.ConnectError("connection refused"))
    client = OllamaClient(base_url=BASE_URL, model="qwen3.5:9b")

    assert client.model_available() is False
```

Replace the `_FakeLLMClient` class and test in `tests/test_llm_client_protocol.py` with:

```python
from pydantic import BaseModel

from app.llm.client import LLMClient


class _EchoResult(BaseModel):
    text: str


class _FakeLLMClient:
    def __init__(self, available: bool = True):
        self._available = available

    def generate_structured(self, prompt, schema):
        return schema(text=prompt)

    def health_check(self) -> bool:
        return True

    def model_available(self) -> bool:
        return self._available


def test_fake_client_satisfies_llm_client_protocol():
    client: LLMClient = _FakeLLMClient()
    result = client.generate_structured("hello", _EchoResult)
    assert result.text == "hello"
    assert client.health_check() is True
    assert client.model_available() is True
    assert isinstance(client, LLMClient)
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate
pytest tests/test_ollama_client.py tests/test_llm_client_protocol.py -v
```

Expected: FAIL — `AttributeError: 'OllamaClient' object has no attribute 'model_available'` and `TypeError: Can't instantiate abstract class` or a plain `AttributeError` for `_FakeLLMClient.model_available`.

- [ ] **Step 3: Write minimal implementation**

In `app/llm/client.py`, change:

```python
@runtime_checkable
class LLMClient(Protocol):
    def generate_structured(self, prompt: str, schema: type[T]) -> T: ...
    def health_check(self) -> bool: ...
```

to:

```python
@runtime_checkable
class LLMClient(Protocol):
    def generate_structured(self, prompt: str, schema: type[T]) -> T: ...
    def health_check(self) -> bool: ...
    def model_available(self) -> bool: ...
```

In `app/llm/ollama_client.py`, add this method after `health_check`:

```python
    def model_available(self) -> bool:
        try:
            models = self._client.models.list()
        except openai.OpenAIError:
            return False
        return any(model.id == self._model for model in models.data)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_ollama_client.py tests/test_llm_client_protocol.py -v
```

Expected: PASS (all tests in both files)

- [ ] **Step 5: Simplify the live smoke test to use the new public method**

In `tests/test_ollama_client_live.py`, replace the `live_client` fixture body:

```python
@pytest.fixture
def live_client():
    settings = Settings()
    client = OllamaClient(
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        timeout_seconds=settings.llm_timeout_seconds,
    )
    if not client.health_check():
        pytest.skip(f"Ollama not reachable at {settings.llm_base_url} — skipping live LLMClient test")

    # Deliberately reaching into the private _client attribute here rather than adding new
    # public API surface to OllamaClient for this test-only check.
    available_models = {model.id for model in client._client.models.list().data}
    if settings.llm_model not in available_models:
        pytest.skip(
            f"Ollama is reachable but model {settings.llm_model!r} is not pulled "
            "— skipping live LLMClient test"
        )
    return client
```

with:

```python
@pytest.fixture
def live_client():
    settings = Settings()
    client = OllamaClient(
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        timeout_seconds=settings.llm_timeout_seconds,
    )
    if not client.health_check():
        pytest.skip(f"Ollama not reachable at {settings.llm_base_url} — skipping live LLMClient test")
    if not client.model_available():
        pytest.skip(
            f"Ollama is reachable but model {settings.llm_model!r} is not pulled "
            "— skipping live LLMClient test"
        )
    return client
```

- [ ] **Step 6: Run the full test suite to confirm no regressions**

```bash
pytest -v
```

Expected: PASS (all tests, including the now-simplified live test, which still skips without a real Ollama instance)

- [ ] **Step 7: Commit**

```bash
git add app/llm/client.py app/llm/ollama_client.py tests/test_llm_client_protocol.py tests/test_ollama_client.py tests/test_ollama_client_live.py
git commit -m "feat(llm): add LLMClient.model_available() preflight check"
```

---

### Task 2: Regex indicator extraction (`app/agent/indicator_extraction.py`)

**Files:**
- Create: `app/agent/__init__.py`
- Create: `app/agent/indicator_extraction.py`
- Test: `tests/test_indicator_extraction.py`

**Interfaces:**
- Consumes: `IPIndicator`, `HashIndicator`, `DomainIndicator`, `URLIndicator`, `Indicator` (all from `app.enrichment.indicators`, existing).
- Produces: `extract_candidates(text: str) -> list[str]`, `extract_and_validate(alert: Alert) -> tuple[list[Indicator], int, int]` (validated indicators, raw candidate count, validated count) — consumed by Task 4's `AgenticAnalyst._step_extract_indicators`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_indicator_extraction.py
from datetime import datetime, timezone
from uuid import uuid4

from app.agent.indicator_extraction import extract_and_validate, extract_candidates
from app.enrichment.indicators import DomainIndicator, HashIndicator, IPIndicator, URLIndicator
from app.schemas import AgentRef, Alert


def _make_alert(**overrides):
    defaults = dict(
        alert_id=uuid4(),
        source_alert_id="1699999999.123456",
        source_system="wazuh",
        rule_id="5710",
        rule_description="sshd: Attempt to login using a non-existent user",
        rule_level=5,
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id="001", name="web-01", ip="10.0.0.5"),
        manager_name="wazuh-manager",
        location="/var/log/auth.log",
        full_log="",
        raw_json={"rule": {"id": "5710"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


_SAMPLE_LOG = (
    "Invalid user admin from 203.0.113.5 fetched "
    "http://malicious-example.test/payload.exe with sha256 "
    + ("a" * 64)
    + " referencing evil-domain.test seen also at 999.999.999.999"
)


def test_extract_candidates_finds_ip_hash_url_and_domain():
    candidates = extract_candidates(_SAMPLE_LOG)

    assert "203.0.113.5" in candidates
    assert "http://malicious-example.test/payload.exe" in candidates
    assert "a" * 64 in candidates
    assert "evil-domain.test" in candidates
    assert "999.999.999.999" in candidates


def test_extract_and_validate_discards_invalid_candidates_and_counts_correctly():
    alert = _make_alert(full_log=_SAMPLE_LOG)

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert candidate_count == 6
    assert validated_count == 5
    values_by_type = {(type(i), i.value) for i in validated}
    assert (IPIndicator, "203.0.113.5") in values_by_type
    assert (HashIndicator, "a" * 64) in values_by_type
    assert (URLIndicator, "http://malicious-example.test/payload.exe") in values_by_type
    assert (DomainIndicator, "evil-domain.test") in values_by_type
    assert (DomainIndicator, "malicious-example.test") in values_by_type


def test_extract_and_validate_returns_empty_for_alert_with_no_indicators():
    alert = _make_alert(full_log="nothing interesting here")

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert validated == []
    assert candidate_count == 0
    assert validated_count == 0


def test_extract_and_validate_scans_string_values_in_data_field():
    alert = _make_alert(
        full_log="no indicators in the log line",
        data={"extra_ip": "198.51.100.7", "count": 3},
    )

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert candidate_count == 1
    assert validated_count == 1
    assert validated[0].value == "198.51.100.7"


def test_extract_and_validate_deduplicates_identical_indicators():
    alert = _make_alert(full_log="203.0.113.5 contacted 203.0.113.5 again")

    validated, candidate_count, validated_count = extract_and_validate(alert)

    assert candidate_count == 2
    assert validated_count == 1
    assert validated[0].value == "203.0.113.5"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_indicator_extraction.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.agent'`

- [ ] **Step 3: Write minimal implementation**

`app/agent/__init__.py` is an empty file — create it with no content, just to make `app/agent` a package.

```python
# app/agent/indicator_extraction.py
import re

from pydantic import ValidationError

from app.enrichment.indicators import DomainIndicator, HashIndicator, IPIndicator, Indicator, URLIndicator
from app.schemas import Alert

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")

_VALIDATORS = (IPIndicator, HashIndicator, DomainIndicator, URLIndicator)


def extract_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for pattern in (_URL_RE, _IPV4_RE, _HASH_RE, _DOMAIN_RE):
        candidates.extend(pattern.findall(text))
    return candidates


def extract_and_validate(alert: Alert) -> tuple[list[Indicator], int, int]:
    text_sources = [alert.full_log] + [v for v in alert.data.values() if isinstance(v, str)]
    raw_candidates: list[str] = []
    for text in text_sources:
        raw_candidates.extend(extract_candidates(text))

    seen: set[tuple[type, str]] = set()
    validated: list[Indicator] = []
    for candidate in raw_candidates:
        for indicator_cls in _VALIDATORS:
            try:
                indicator = indicator_cls(value=candidate)
            except ValidationError:
                continue
            key = (type(indicator), indicator.value)
            if key not in seen:
                seen.add(key)
                validated.append(indicator)
            break
    return validated, len(raw_candidates), len(validated)
```

**Known, accepted simplifications** (do not "fix" these — they are documented design decisions, not bugs):
- A domain substring inside an already-matched URL (e.g. `malicious-example.test` inside `http://malicious-example.test/payload.exe`) is extracted twice, as two different indicator types for the same host — over-extraction is preferred over under-extraction in this read-only, best-effort design.
- No `EmailIndicator` exists, so `EMAIL`-type candidates are never produced.
- Generic hex/dotted-decimal noise in logs may produce false-positive candidates — these get enriched like any other candidate (typically resolving to `UNKNOWN`/`CLEAN`) rather than causing harm.

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_indicator_extraction.py -v
```

Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add app/agent/__init__.py app/agent/indicator_extraction.py tests/test_indicator_extraction.py
git commit -m "feat(agent): add regex-based indicator candidate extraction"
```

---

### Task 3: `AgenticAnalyst` skeleton — `Step` enum, constructor, Ingest & Parse

**Files:**
- Create: `app/agent/state_graph.py`
- Create: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `SIEMConnector` (`app.integration.siem_connector`), `AlertStore` (`app.storage.alert_store`), `EnrichmentRegistry` (`app.enrichment.registry`), `LLMClient` (`app.llm.client`) — all existing Protocols/classes, injected via constructor.
- Produces: `Step` enum, `AgenticAnalyst.__init__(siem, alert_store, enrichment_registry, llm_client)`, `AgenticAnalyst._step_ingest_and_parse(alert, model_available) -> InvestigationStep` — consumed by every later task in this plan. This task also establishes the test file's shared fakes (`_FakeSIEMConnector`, `_FakeAlertStore`, `_FakeLLMClient`, `_make_alert`, `_make_analyst`) that Tasks 4-7 extend.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_state_graph.py
from datetime import datetime, timezone
from uuid import uuid4

from app.agent.state_graph import AgenticAnalyst, Step
from app.enrichment.registry import EnrichmentRegistry
from app.integration.models import AgentContext, RuleMetadata
from app.schemas import AgentRef, Alert


class _FakeSIEMConnector:
    def __init__(self, agent_context=None, rule_metadata=None, context_error=None):
        self._agent_context = agent_context
        self._rule_metadata = rule_metadata
        self._context_error = context_error

    def health_check(self):
        return True

    def pull_alerts(self, since, until=None, limit=500):
        return []

    def search(self, query):
        raise NotImplementedError

    def get_agent_context(self, agent_id):
        if self._context_error is not None:
            raise self._context_error
        return self._agent_context

    def get_rule_metadata(self, rule_id):
        if self._context_error is not None:
            raise self._context_error
        return self._rule_metadata


class _FakeAlertStore:
    def __init__(self):
        self.reports = []
        self.status_updates = []

    def save_raw_alert(self, alert):
        return str(alert.alert_id)

    def get_alert(self, alert_id):
        raise NotImplementedError

    def list_alerts(self, status=None, since=None, limit=100):
        return []

    def update_alert_status(self, alert_id, status):
        self.status_updates.append((alert_id, status))

    def save_report(self, report):
        self.reports.append(report)
        return str(report.report_id)

    def get_report(self, report_id):
        raise NotImplementedError

    def get_report_for_alert(self, alert_id):
        return None

    def list_reports(self, since=None, min_severity=None):
        return []


class _FakeLLMClient:
    def __init__(self, model_available=True):
        self._model_available = model_available

    def generate_structured(self, prompt, schema):
        raise NotImplementedError("not used in Phase 4b")

    def health_check(self):
        return True

    def model_available(self):
        return self._model_available


def _make_alert(**overrides):
    defaults = dict(
        alert_id=uuid4(),
        source_alert_id="1699999999.123456",
        source_system="wazuh",
        rule_id="5710",
        rule_description="sshd: Attempt to login using a non-existent user",
        rule_level=5,
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id="001", name="web-01", ip="10.0.0.5"),
        manager_name="wazuh-manager",
        location="/var/log/auth.log",
        full_log="Invalid user admin from 203.0.113.5",
        raw_json={"rule": {"id": "5710"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


def _make_analyst(**overrides):
    defaults = dict(
        siem=_FakeSIEMConnector(),
        alert_store=_FakeAlertStore(),
        enrichment_registry=EnrichmentRegistry(),
        llm_client=_FakeLLMClient(),
    )
    defaults.update(overrides)
    return AgenticAnalyst(**defaults)


def test_step_ingest_and_parse_records_model_available_true():
    analyst = _make_analyst()
    alert = _make_alert()

    step = analyst._step_ingest_and_parse(alert, model_available=True)

    assert step.step_name == Step.INGEST_AND_PARSE.value
    assert step.action == "completed"
    assert str(alert.alert_id) in step.output_summary
    assert "model available: True" in step.output_summary


def test_step_ingest_and_parse_records_model_available_false():
    analyst = _make_analyst()
    alert = _make_alert()

    step = analyst._step_ingest_and_parse(alert, model_available=False)

    assert "model available: False" in step.output_summary
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.agent.state_graph'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/agent/state_graph.py
from datetime import datetime, timezone
from enum import Enum

from app.enrichment.registry import EnrichmentRegistry
from app.integration.siem_connector import SIEMConnector
from app.llm.client import LLMClient
from app.schemas import Alert, InvestigationStep
from app.storage.alert_store import AlertStore


class Step(str, Enum):
    INGEST_AND_PARSE = "ingest_and_parse"
    EXTRACT_INDICATORS = "extract_indicators"
    ENRICH = "enrich"
    GATHER_CONTEXT = "gather_context"
    CORRELATE = "correlate"
    RISK_ASSESSMENT = "risk_assessment"
    DRAFT_REPORT = "draft_report"
    SELF_CHECK = "self_check"
    FINALIZE_AND_PERSIST = "finalize_and_persist"


class AgenticAnalyst:
    def __init__(
        self,
        siem: SIEMConnector,
        alert_store: AlertStore,
        enrichment_registry: EnrichmentRegistry,
        llm_client: LLMClient,
    ) -> None:
        self._siem = siem
        self._alert_store = alert_store
        self._enrichment_registry = enrichment_registry
        self._llm_client = llm_client

    def _step_ingest_and_parse(self, alert: Alert, model_available: bool) -> InvestigationStep:
        return InvestigationStep(
            step_name=Step.INGEST_AND_PARSE.value,
            action="completed",
            tool_used=None,
            input=None,
            output_summary=f"alert {alert.alert_id} ingested; model available: {model_available}",
            timestamp=datetime.now(timezone.utc),
        )
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): add Step enum and AgenticAnalyst skeleton with Ingest & Parse"
```

---

### Task 4: Extract Indicators + Enrich steps

**Files:**
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `extract_and_validate` (Task 2, `app.agent.indicator_extraction`), `EnrichmentRegistry.enrich()` (existing).
- Produces: `AgenticAnalyst._step_extract_indicators(alert) -> tuple[list[Indicator], InvestigationStep]`, `AgenticAnalyst._step_enrich(indicators) -> tuple[list[EnrichmentResult], InvestigationStep]` — consumed by Task 7's `investigate()`.

- [ ] **Step 1: Write the failing tests**

Add this import to the top of `tests/test_state_graph.py` (`EnrichmentRegistry` is already imported from Task 3 — only `EnrichmentVerdict`/`IndicatorType` are new):

```python
from app.schemas import EnrichmentVerdict, IndicatorType
```

Append to `tests/test_state_graph.py`:

```python
class _FakeIPProvider:
    provider_id = "abuseipdb"
    supported_types = frozenset({IndicatorType.IP})

    def __init__(self, result):
        self._result = result

    def lookup(self, indicator):
        return self._result


def _make_enrichment_result(**overrides):
    defaults = dict(
        indicator_type=IndicatorType.IP,
        indicator_value="203.0.113.5",
        provider_id="abuseipdb",
        queried_at=datetime.now(timezone.utc),
        verdict=EnrichmentVerdict.CLEAN,
        score=1.0,
        cache_expires_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return EnrichmentResult(**defaults)


def test_step_extract_indicators_finds_and_validates_ip():
    analyst = _make_analyst()
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    indicators, step = analyst._step_extract_indicators(alert)

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.5"
    assert step.step_name == Step.EXTRACT_INDICATORS.value
    assert "1 candidates, 1 validated" in step.output_summary


def test_step_extract_indicators_returns_empty_list_when_nothing_found():
    analyst = _make_analyst()
    alert = _make_alert(full_log="nothing interesting here")

    indicators, step = analyst._step_extract_indicators(alert)

    assert indicators == []
    assert step.action == "completed"


def test_step_enrich_calls_registry_for_each_indicator():
    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result()))
    analyst = _make_analyst(enrichment_registry=registry)
    indicators, _ = analyst._step_extract_indicators(
        _make_alert(full_log="Invalid user admin from 203.0.113.5")
    )

    results, step = analyst._step_enrich(indicators)

    assert len(results) == 1
    assert results[0].verdict == EnrichmentVerdict.CLEAN
    assert step.step_name == Step.ENRICH.value
    assert step.action == "completed"


def test_step_enrich_skips_when_no_indicators():
    analyst = _make_analyst()

    results, step = analyst._step_enrich([])

    assert results == []
    assert step.action == "skipped"
    assert "no validated indicators" in step.output_summary
```

Also add `EnrichmentResult` to the existing `from app.schemas import ...` line at the top of the test file (it currently imports `AgentRef, Alert` — extend it to `AgentRef, Alert, EnrichmentResult`).

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL with `AttributeError: 'AgenticAnalyst' object has no attribute '_step_extract_indicators'`

- [ ] **Step 3: Write minimal implementation**

Update the import block at the top of `app/agent/state_graph.py`:

```python
from datetime import datetime, timezone
from enum import Enum

from app.agent.indicator_extraction import extract_and_validate
from app.enrichment.indicators import Indicator
from app.enrichment.registry import EnrichmentRegistry
from app.integration.siem_connector import SIEMConnector
from app.llm.client import LLMClient
from app.schemas import Alert, EnrichmentResult, InvestigationStep
from app.storage.alert_store import AlertStore
```

Append these two methods to the `AgenticAnalyst` class (after `_step_ingest_and_parse`):

```python
    def _step_extract_indicators(self, alert: Alert) -> tuple[list[Indicator], InvestigationStep]:
        validated, candidate_count, validated_count = extract_and_validate(alert)
        step = InvestigationStep(
            step_name=Step.EXTRACT_INDICATORS.value,
            action="completed",
            tool_used="regex_extraction",
            input=None,
            output_summary=(
                f"{candidate_count} candidates, {validated_count} validated "
                "(LLM-assisted extraction: not yet implemented, Phase 4c)"
            ),
            timestamp=datetime.now(timezone.utc),
        )
        return validated, step

    def _step_enrich(self, indicators: list[Indicator]) -> tuple[list[EnrichmentResult], InvestigationStep]:
        if not indicators:
            step = InvestigationStep(
                step_name=Step.ENRICH.value,
                action="skipped",
                tool_used=None,
                input=None,
                output_summary="skipped: no validated indicators to enrich",
                timestamp=datetime.now(timezone.utc),
            )
            return [], step

        results = [self._enrichment_registry.enrich(indicator) for indicator in indicators]
        step = InvestigationStep(
            step_name=Step.ENRICH.value,
            action="completed",
            tool_used="enrichment_registry",
            input=None,
            output_summary=f"enriched {len(results)} indicator(s)",
            timestamp=datetime.now(timezone.utc),
        )
        return results, step
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): add Extract Indicators and Enrich steps"
```

---

### Task 5: Gather Host/Rule Context step

**Files:**
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `SIEMConnector.get_agent_context()`, `SIEMConnector.get_rule_metadata()`, `SIEMConnectorError` (all existing, `app.integration.errors`/`app.integration.models`).
- Produces: `AgenticAnalyst._step_gather_context(alert) -> tuple[AgentContext | None, RuleMetadata | None, InvestigationStep]` — consumed by Task 7's `investigate()`.

- [ ] **Step 1: Write the failing tests**

Add this import to the top of `tests/test_state_graph.py`:

```python
from app.integration.errors import SIEMConnectorError
```

Append to `tests/test_state_graph.py`:

```python
def test_step_gather_context_returns_context_on_success():
    siem = _FakeSIEMConnector(
        agent_context=AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active"),
        rule_metadata=RuleMetadata(rule_id="5710", description="x", level=5),
    )
    analyst = _make_analyst(siem=siem)
    alert = _make_alert()

    agent_context, rule_metadata, step = analyst._step_gather_context(alert)

    assert agent_context.id == "001"
    assert rule_metadata.rule_id == "5710"
    assert step.step_name == Step.GATHER_CONTEXT.value
    assert step.action == "completed"


def test_step_gather_context_degrades_on_siem_connector_error():
    siem = _FakeSIEMConnector(context_error=SIEMConnectorError("unreachable", "connection refused"))
    analyst = _make_analyst(siem=siem)
    alert = _make_alert()

    agent_context, rule_metadata, step = analyst._step_gather_context(alert)

    assert agent_context is None
    assert rule_metadata is None
    assert step.action == "degraded"
    assert "unreachable" in step.output_summary
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL with `AttributeError: 'AgenticAnalyst' object has no attribute '_step_gather_context'`

- [ ] **Step 3: Write minimal implementation**

Update the import block at the top of `app/agent/state_graph.py`:

```python
from datetime import datetime, timezone
from enum import Enum

from app.agent.indicator_extraction import extract_and_validate
from app.enrichment.indicators import Indicator
from app.enrichment.registry import EnrichmentRegistry
from app.integration.errors import SIEMConnectorError
from app.integration.models import AgentContext, RuleMetadata
from app.integration.siem_connector import SIEMConnector
from app.llm.client import LLMClient
from app.schemas import Alert, EnrichmentResult, InvestigationStep
from app.storage.alert_store import AlertStore
```

Append this method to the `AgenticAnalyst` class (after `_step_enrich`):

```python
    def _step_gather_context(
        self, alert: Alert
    ) -> tuple[AgentContext | None, RuleMetadata | None, InvestigationStep]:
        try:
            agent_context = self._siem.get_agent_context(alert.agent.id)
            rule_metadata = self._siem.get_rule_metadata(alert.rule_id)
        except SIEMConnectorError as exc:
            step = InvestigationStep(
                step_name=Step.GATHER_CONTEXT.value,
                action="degraded",
                tool_used="siem_connector",
                input=None,
                output_summary=f"could not gather host/rule context: {exc.kind}",
                timestamp=datetime.now(timezone.utc),
            )
            return None, None, step

        step = InvestigationStep(
            step_name=Step.GATHER_CONTEXT.value,
            action="completed",
            tool_used="siem_connector",
            input=None,
            output_summary=f"gathered context for agent {alert.agent.id}, rule {alert.rule_id}",
            timestamp=datetime.now(timezone.utc),
        )
        return agent_context, rule_metadata, step
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): add Gather Host/Rule Context step"
```

---

### Task 6: Stub steps — Correlate, Risk Assessment, Draft Report, Self-Check

**Files:**
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Produces: `AgenticAnalyst._stub_step(step, model_available) -> InvestigationStep`, `AgenticAnalyst._step_correlate(model_available)`, `_step_risk_assessment(model_available)`, `_step_draft_report(model_available)`, `_step_self_check(model_available)` (all `-> InvestigationStep`) — consumed by Task 7's `investigate()`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_state_graph.py`:

```python
def test_stub_step_logs_stub_when_model_available():
    analyst = _make_analyst()

    step = analyst._stub_step(Step.CORRELATE, model_available=True)

    assert step.step_name == Step.CORRELATE.value
    assert step.action == "stub"
    assert "Phase 4c/4d" in step.output_summary


def test_stub_step_logs_skipped_when_model_unavailable():
    analyst = _make_analyst()

    step = analyst._stub_step(Step.RISK_ASSESSMENT, model_available=False)

    assert step.step_name == Step.RISK_ASSESSMENT.value
    assert step.action == "skipped"
    assert "model unavailable" in step.output_summary


def test_step_correlate_delegates_to_stub_step():
    analyst = _make_analyst()

    step = analyst._step_correlate(model_available=True)

    assert step.step_name == Step.CORRELATE.value
    assert step.action == "stub"


def test_step_risk_assessment_delegates_to_stub_step():
    analyst = _make_analyst()

    step = analyst._step_risk_assessment(model_available=False)

    assert step.step_name == Step.RISK_ASSESSMENT.value
    assert step.action == "skipped"


def test_step_draft_report_delegates_to_stub_step():
    analyst = _make_analyst()

    step = analyst._step_draft_report(model_available=True)

    assert step.step_name == Step.DRAFT_REPORT.value
    assert step.action == "stub"


def test_step_self_check_delegates_to_stub_step():
    analyst = _make_analyst()

    step = analyst._step_self_check(model_available=True)

    assert step.step_name == Step.SELF_CHECK.value
    assert step.action == "stub"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL with `AttributeError: 'AgenticAnalyst' object has no attribute '_stub_step'`

- [ ] **Step 3: Write minimal implementation**

Append these methods to the `AgenticAnalyst` class (after `_step_gather_context`):

```python
    def _stub_step(self, step: Step, model_available: bool) -> InvestigationStep:
        if model_available:
            action, summary = "stub", f"not yet implemented — Phase 4c/4d ({step.value})"
        else:
            action, summary = "skipped", "skipped: model unavailable"
        return InvestigationStep(
            step_name=step.value,
            action=action,
            tool_used=None,
            input=None,
            output_summary=summary,
            timestamp=datetime.now(timezone.utc),
        )

    def _step_correlate(self, model_available: bool) -> InvestigationStep:
        return self._stub_step(Step.CORRELATE, model_available)

    def _step_risk_assessment(self, model_available: bool) -> InvestigationStep:
        return self._stub_step(Step.RISK_ASSESSMENT, model_available)

    def _step_draft_report(self, model_available: bool) -> InvestigationStep:
        return self._stub_step(Step.DRAFT_REPORT, model_available)

    def _step_self_check(self, model_available: bool) -> InvestigationStep:
        return self._stub_step(Step.SELF_CHECK, model_available)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (14 tests)

- [ ] **Step 5: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): add stub steps for Correlate, Risk Assessment, Draft Report, Self-Check"
```

---

### Task 7: Report assembly, Finalize & Persist, and `investigate()` wiring

**Files:**
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: every `_step_*`/`_stub_step` method from Tasks 3-6; `AlertStore.save_report()`, `AlertStore.update_alert_status()` (existing).
- Produces: `AgenticAnalyst._assemble_report(...)`, `AgenticAnalyst._step_finalize_and_persist(alert, report)`, `AgenticAnalyst.investigate(alert) -> Report` — the full pipeline entry point, the deliverable of this entire plan.

- [ ] **Step 1: Write the failing tests**

Add these imports to the top of `tests/test_state_graph.py`:

```python
from app.schemas import AlertStatus, Confidence, ReportStatus, Severity
from app.storage.db import get_engine, init_db
from app.storage.sqlite_alert_store import SQLiteAlertStore
```

Append to `tests/test_state_graph.py`:

```python
def test_investigate_runs_full_pipeline_and_persists_report(tmp_path):
    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    alert_store = SQLiteAlertStore(engine)
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")
    alert_store.save_raw_alert(alert)

    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result()))
    analyst = AgenticAnalyst(
        siem=_FakeSIEMConnector(
            agent_context=AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active"),
            rule_metadata=RuleMetadata(rule_id="5710", description="x", level=5),
        ),
        alert_store=alert_store,
        enrichment_registry=registry,
        llm_client=_FakeLLMClient(model_available=True),
    )

    report = analyst.investigate(alert)

    step_names = [s.step_name for s in report.investigation_timeline]
    assert step_names == [
        Step.INGEST_AND_PARSE.value,
        Step.EXTRACT_INDICATORS.value,
        Step.ENRICH.value,
        Step.GATHER_CONTEXT.value,
        Step.CORRELATE.value,
        Step.RISK_ASSESSMENT.value,
        Step.DRAFT_REPORT.value,
        Step.SELF_CHECK.value,
        Step.FINALIZE_AND_PERSIST.value,
    ]
    assert report.status == ReportStatus.NEEDS_HUMAN_REVIEW
    assert report.risk_assessment.severity == Severity.LOW
    assert report.risk_assessment.confidence == Confidence.LOW
    assert report.model_metadata.model_name == "qwen3.5:9b"
    assert len(report.enrichment_findings) == 1
    assert alert_store.get_report(str(report.report_id)).report_id == report.report_id
    assert alert_store.get_alert(str(alert.alert_id)).status == AlertStatus.INVESTIGATED


def test_investigate_stub_steps_skip_when_model_unavailable(tmp_path):
    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    alert_store = SQLiteAlertStore(engine)
    alert = _make_alert(full_log="nothing interesting here")
    alert_store.save_raw_alert(alert)

    analyst = AgenticAnalyst(
        siem=_FakeSIEMConnector(
            agent_context=AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active"),
            rule_metadata=RuleMetadata(rule_id="5710", description="x", level=5),
        ),
        alert_store=alert_store,
        enrichment_registry=EnrichmentRegistry(),
        llm_client=_FakeLLMClient(model_available=False),
    )

    report = analyst.investigate(alert)

    stub_step_names = {Step.CORRELATE.value, Step.RISK_ASSESSMENT.value, Step.DRAFT_REPORT.value, Step.SELF_CHECK.value}
    stub_steps = [s for s in report.investigation_timeline if s.step_name in stub_step_names]
    assert len(stub_steps) == 4
    assert all(s.action == "skipped" for s in stub_steps)
    assert report.enrichment_findings == []
    assert report.model_metadata.model_name == "none"


def test_investigate_degrades_gracefully_when_siem_context_unavailable(tmp_path):
    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    alert_store = SQLiteAlertStore(engine)
    alert = _make_alert(full_log="nothing interesting here")
    alert_store.save_raw_alert(alert)

    analyst = AgenticAnalyst(
        siem=_FakeSIEMConnector(context_error=SIEMConnectorError("unreachable", "connection refused")),
        alert_store=alert_store,
        enrichment_registry=EnrichmentRegistry(),
        llm_client=_FakeLLMClient(model_available=True),
    )

    report = analyst.investigate(alert)

    context_step = next(s for s in report.investigation_timeline if s.step_name == Step.GATHER_CONTEXT.value)
    assert context_step.action == "degraded"
    assert report.status == ReportStatus.NEEDS_HUMAN_REVIEW
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL with `AttributeError: 'AgenticAnalyst' object has no attribute 'investigate'`

- [ ] **Step 3: Write minimal implementation**

Update the import block at the top of `app/agent/state_graph.py`:

```python
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from app.agent.indicator_extraction import extract_and_validate
from app.enrichment.indicators import Indicator
from app.enrichment.registry import EnrichmentRegistry
from app.integration.errors import SIEMConnectorError
from app.integration.models import AgentContext, RuleMetadata
from app.integration.siem_connector import SIEMConnector
from app.llm.client import LLMClient
from app.schemas import (
    Alert,
    AlertStatus,
    Confidence,
    EnrichmentResult,
    InvestigationStep,
    ModelMetadata,
    Report,
    ReportStatus,
    RiskAssessment,
    Severity,
)
from app.storage.alert_store import AlertStore
```

Append these methods to the `AgenticAnalyst` class (after `_step_self_check`), and add the `investigate` method as the class's first method (conventionally placed right after `__init__`, but appending at the end of the class body works identically in Python — place it wherever is easiest to edit):

```python
    def _assemble_report(
        self,
        alert: Alert,
        timeline: list[InvestigationStep],
        enrichment_results: list[EnrichmentResult],
        model_available: bool,
    ) -> Report:
        return Report(
            report_id=uuid4(),
            alert_id=alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            alert_summary=f"Stub report for alert {alert.alert_id} — full investigation logic pending Phase 4c/4d.",
            investigation_timeline=timeline,
            enrichment_findings=enrichment_results,
            risk_assessment=RiskAssessment(
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                rationale="stub — risk assessment not yet implemented (Phase 4c)",
            ),
            recommended_actions=[],
            recommended_actions_freeform_experimental=None,
            uncertainty_notes=(
                "This report was produced by the Phase 4b pipeline skeleton — steps 5-8 "
                "(Correlate, Risk Assessment, Draft Report, Self-Check) are stubs, not real analysis."
            ),
            status=ReportStatus.NEEDS_HUMAN_REVIEW,
            model_metadata=ModelMetadata(
                model_name="qwen3.5:9b" if model_available else "none",
                model_version="none",
                prompt_version="stub-4b",
            ),
        )

    def _step_finalize_and_persist(self, alert: Alert, report: Report) -> InvestigationStep:
        self._alert_store.update_alert_status(str(alert.alert_id), AlertStatus.INVESTIGATED)
        return InvestigationStep(
            step_name=Step.FINALIZE_AND_PERSIST.value,
            action="completed",
            tool_used="alert_store",
            input=None,
            output_summary=f"report {report.report_id} persisted, alert marked investigated",
            timestamp=datetime.now(timezone.utc),
        )

    def investigate(self, alert: Alert) -> Report:
        model_available = self._llm_client.model_available()
        timeline: list[InvestigationStep] = [self._step_ingest_and_parse(alert, model_available)]

        indicators, extract_step = self._step_extract_indicators(alert)
        timeline.append(extract_step)

        enrichment_results, enrich_step = self._step_enrich(indicators)
        timeline.append(enrich_step)

        _agent_context, _rule_metadata, context_step = self._step_gather_context(alert)
        timeline.append(context_step)

        timeline.append(self._step_correlate(model_available))
        timeline.append(self._step_risk_assessment(model_available))
        timeline.append(self._step_draft_report(model_available))
        timeline.append(self._step_self_check(model_available))

        report = self._assemble_report(alert, timeline, enrichment_results, model_available)
        finalize_step = self._step_finalize_and_persist(alert, report)
        report.investigation_timeline.append(finalize_step)
        self._alert_store.save_report(report)
        return report
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (17 tests)

- [ ] **Step 5: Run the full project test suite**

```bash
pytest -v
```

Expected: PASS — every test in the repo, old and new.

- [ ] **Step 6: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): wire investigate() end-to-end and assemble stub reports"
```
