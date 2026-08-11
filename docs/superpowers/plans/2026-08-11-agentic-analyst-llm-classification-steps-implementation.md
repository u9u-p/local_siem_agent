# Agentic Analyst — LLM-Calling Classification Steps (Phase 4c) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace Phase 4b's three inert LLM-calling stubs (Extract Indicators 2b, Correlate 5, Risk Assessment 6) with real `generate_structured()` call sites, real per-step schemas, and real prompts — wired end-to-end through `AgenticAnalyst.investigate()`.

**Architecture:** `SearchQuery` is redesigned to support compound (ANDed) clauses, unblocking Correlate's canonical searches. Correlate runs deterministic canonical searches unconditionally (real signal regardless of model state), then a closed-menu LLM classification+follow-up-pick call, then a conditional second LLM call (open-value search) only when the closed menu came back inconclusive. Risk Assessment reuses the existing `RiskAssessment` schema unchanged, fed only structured findings (never raw log content again, per grounding discipline) plus `Alert.mitre` when Wazuh's own decoder already mapped it — no LLM-driven MITRE guessing.

**Tech Stack:** Python 3.11+, pydantic v2, pytest, respx — no new dependencies.

## Global Constraints

- No new dependencies.
- MITRE technique selection via LLM is out of scope. `RiskAssessment`'s schema (`severity`, `confidence`, `rationale`) is unchanged from Phase 1. `Alert.mitre` is passed into the Risk Assessment prompt as passive context when non-empty (Wazuh's own decoder-provided mapping, from Phase 3 — no LLM involved in producing it). `RuleMetadata.mitre_technique_ids` (a second, separate non-LLM source fetched by step 4) stays unused — threading it through is a distinct, deferred design problem.
- `SearchQuery` is redesigned to `clauses: list[SearchClause]` (min 1, ANDed together) — a breaking change to an already-shipped Integration model, confirmed to have zero production callers today (only test code constructs it). All 11 existing test call sites migrate to the new shape as part of this plan.
- `evidence_count` in Correlate is computed by code (sum of `SearchResult.total_count` across whichever canonical searches ran, plus any executed follow-up's `total_count`) — never returned by the LLM.
- The open-value search is a separate LLM call (not bundled into `CorrelationDecision`'s schema), triggered only when `pattern_type` is `NONE` or `OTHER`. It executes as `SearchClause(field="full_log", operator="contains", value=<llm-proposed value>)` — the model proposes a value only, never a field name. Its result is explicitly flagged `"noisier, unstructured match"` in the timeline text.
- Canonical searches in Correlate always run, `model_available` or not — only the classification call, the follow-up pick, and the open-value search are gated on `model_available`.
- The closed-menu follow-up query and the open-value search are each capped at exactly one hop — never recursive, never chained.
- Prompt versioning: one overall version string for this phase's whole prompt set (`"4c-v1"`), replacing 4b's `"stub-4b"` placeholder in `Report.model_metadata.prompt_version`.
- TDD: every method gets a failing test before implementation. Commit after each task.

---

### Task 1: `SearchQuery`/`SearchClause` redesign

**Files:**
- Modify: `app/integration/models.py`
- Modify: `app/integration/wazuh_connector.py`
- Modify: `tests/test_integration_models.py`
- Modify: `tests/test_wazuh_connector.py`
- Modify: `tests/test_siem_connector_protocol.py`

**Interfaces:**
- Produces: `SearchClause(field: str, operator: Literal["eq","contains","range","terms"], value: Any)`, `SearchQuery(clauses: list[SearchClause], time_range: tuple[datetime,datetime]|None=None)` — consumed by Task 3 (`correlation_queries.py`) and every later Correlate task.

- [ ] **Step 1: Write the failing tests**

Replace the two `SearchQuery`-specific tests in `tests/test_integration_models.py`:

```python
def test_search_query_accepts_valid_operators():
    for operator in ("eq", "contains", "range", "terms"):
        query = SearchQuery(field="rule.level", operator=operator, value=5)
        assert query.operator == operator


def test_search_query_rejects_invalid_operator():
    with pytest.raises(ValidationError):
        SearchQuery(field="rule.level", operator="fuzzy", value=5)
```

with:

```python
def test_search_clause_accepts_valid_operators():
    for operator in ("eq", "contains", "range", "terms"):
        clause = SearchClause(field="rule.level", operator=operator, value=5)
        assert clause.operator == operator


def test_search_clause_rejects_invalid_operator():
    with pytest.raises(ValidationError):
        SearchClause(field="rule.level", operator="fuzzy", value=5)


def test_search_query_holds_multiple_clauses():
    query = SearchQuery(
        clauses=[
            SearchClause(field="rule_id", operator="eq", value="5710"),
            SearchClause(field="agent.id", operator="eq", value="001"),
        ]
    )
    assert len(query.clauses) == 2


def test_search_query_rejects_empty_clause_list():
    with pytest.raises(ValidationError):
        SearchQuery(clauses=[])
```

Update the import line at the top of `tests/test_integration_models.py`:

```python
from app.integration.models import AgentContext, RuleMetadata, SearchClause, SearchQuery, SearchResult
```

In `tests/test_wazuh_connector.py`, change the mid-file import (currently `from app.integration.models import SearchQuery`, appearing just before the search-translation tests) to:

```python
from app.integration.models import SearchClause, SearchQuery
```

Then update every `SearchQuery(field=..., operator=..., value=...)` construction in that same file to wrap the single condition in a `clauses=[SearchClause(...)]` list:

- `SearchQuery(field="rule.level", operator="eq", value=5)` appears identically 5 times (in `test_search_translates_eq_operator_to_term_query`, `test_search_raises_bad_response_on_indexer_500`, `test_search_raises_unreachable_on_connection_error`, `test_pull_alerts_skips_malformed_hit_and_maps_the_rest`, `test_search_sends_an_explicit_default_size`) — replace **all 5** with `SearchQuery(clauses=[SearchClause(field="rule.level", operator="eq", value=5)])` (use a global find/replace, since all 5 occurrences are byte-identical and get the identical replacement).
- `SearchQuery(field="full_log", operator="contains", value="Invalid user")` (in `test_search_translates_contains_operator_to_match_query`) → `SearchQuery(clauses=[SearchClause(field="full_log", operator="contains", value="Invalid user")])`
- `SearchQuery(field="rule.level", operator="range", value={"gte": 3}, time_range=(since, until))` (in `test_search_translates_range_operator_and_time_range_filter`) → `SearchQuery(clauses=[SearchClause(field="rule.level", operator="range", value={"gte": 3})], time_range=(since, until))`
- `SearchQuery(field="rule.groups", operator="terms", value=["authentication_failed", "syslog"])` (in `test_search_translates_terms_operator_to_terms_query`) → `SearchQuery(clauses=[SearchClause(field="rule.groups", operator="terms", value=["authentication_failed", "syslog"])])`

In `tests/test_siem_connector_protocol.py`, update the import line:

```python
from app.integration.models import AgentContext, RuleMetadata, SearchClause, SearchQuery, SearchResult
```

and the single construction site:

```python
assert connector.search(SearchQuery(clauses=[SearchClause(field="rule.level", operator="eq", value=5)])).total_count == 0
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
source .venv/bin/activate
pytest tests/test_integration_models.py tests/test_wazuh_connector.py tests/test_siem_connector_protocol.py -v
```

Expected: FAIL — `test_integration_models.py`'s new tests fail with `ImportError: cannot import name 'SearchClause'`; the other two files' tests fail the same way once their imports are updated ahead of the implementation.

- [ ] **Step 3: Write minimal implementation**

In `app/integration/models.py`, replace:

```python
class SearchQuery(BaseModel):
    field: str
    operator: Literal["eq", "contains", "range", "terms"]
    value: Any
    time_range: tuple[datetime, datetime] | None = None
```

with:

```python
class SearchClause(BaseModel):
    field: str
    operator: Literal["eq", "contains", "range", "terms"]
    value: Any


class SearchQuery(BaseModel):
    clauses: list[SearchClause] = Field(min_length=1)
    time_range: tuple[datetime, datetime] | None = None
```

In `app/integration/wazuh_connector.py`, replace the `search()` method body:

```python
    def search(self, query: SearchQuery) -> SearchResult:
        operator_clause: dict[str, Any]
        if query.operator == "eq":
            operator_clause = {"term": {query.field: query.value}}
        elif query.operator == "contains":
            operator_clause = {"match": {query.field: query.value}}
        elif query.operator == "range":
            operator_clause = {"range": {query.field: query.value}}
        else:  # "terms"
            operator_clause = {"terms": {query.field: query.value}}

        filter_clauses: list[dict[str, Any]] = []
        if query.time_range is not None:
            since, until = query.time_range
            # UNVERIFIED against a live instance — see design spec §6; if this returns zero alerts unexpectedly, confirm the real field name first
            filter_clauses.append({"range": {"timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}})

        body = {
            "query": {"bool": {"must": [operator_clause], "filter": filter_clauses}},
            "size": _SEARCH_DEFAULT_SIZE,
        }
        payload = self._indexer_search(body)
        alerts = _map_hits(payload["hits"]["hits"])
        return SearchResult(alerts=alerts, total_count=payload["hits"]["total"]["value"])
```

with:

```python
    def search(self, query: SearchQuery) -> SearchResult:
        must_clauses: list[dict[str, Any]] = []
        for clause in query.clauses:
            if clause.operator == "eq":
                must_clauses.append({"term": {clause.field: clause.value}})
            elif clause.operator == "contains":
                must_clauses.append({"match": {clause.field: clause.value}})
            elif clause.operator == "range":
                must_clauses.append({"range": {clause.field: clause.value}})
            else:  # "terms"
                must_clauses.append({"terms": {clause.field: clause.value}})

        filter_clauses: list[dict[str, Any]] = []
        if query.time_range is not None:
            since, until = query.time_range
            # Confirmed against a live Wazuh 4.14.x instance during Phase 3 — "timestamp" is the real field name.
            filter_clauses.append({"range": {"timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}})

        body = {
            "query": {"bool": {"must": must_clauses, "filter": filter_clauses}},
            "size": _SEARCH_DEFAULT_SIZE,
        }
        payload = self._indexer_search(body)
        alerts = _map_hits(payload["hits"]["hits"])
        return SearchResult(alerts=alerts, total_count=payload["hits"]["total"]["value"])
```

(The comment update reflects that this was empirically confirmed during Phase 3's live-instance testing — not a new claim, just correcting a stale "unverified" note while this method is already being touched.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_integration_models.py tests/test_wazuh_connector.py tests/test_siem_connector_protocol.py -v
```

Expected: PASS — all tests in all three files.

- [ ] **Step 5: Run the full project test suite**

```bash
pytest -v
```

Expected: PASS — confirms no other file constructs `SearchQuery` in the old shape.

- [ ] **Step 6: Commit**

```bash
git add app/integration/models.py app/integration/wazuh_connector.py tests/test_integration_models.py tests/test_wazuh_connector.py tests/test_siem_connector_protocol.py
git commit -m "feat(integration): redesign SearchQuery to support compound ANDed clauses"
```

---

### Task 2: New Agentic Analyst schemas (`app/agent/schemas.py`)

**Files:**
- Create: `app/agent/schemas.py`
- Test: `tests/test_agent_schemas.py`

**Interfaces:**
- Consumes: `IndicatorType` (`app.schemas`, existing).
- Produces: `IndicatorCandidate`, `ExtractedIndicators`, `PatternType`, `SearchTemplate`, `CorrelationDecision`, `OpenValueSearchProposal` — consumed by Task 3 (`SearchTemplate`), Task 4 (`IndicatorCandidate`/`ExtractedIndicators`), Tasks 5-7 (`PatternType`/`SearchTemplate`/`CorrelationDecision`/`OpenValueSearchProposal`).

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_agent_schemas.py
import pytest
from pydantic import ValidationError

from app.agent.schemas import (
    CorrelationDecision,
    ExtractedIndicators,
    IndicatorCandidate,
    OpenValueSearchProposal,
    PatternType,
    SearchTemplate,
)
from app.schemas import IndicatorType


def test_indicator_candidate_holds_type_and_value():
    candidate = IndicatorCandidate(type=IndicatorType.IP, value="203.0.113.5")
    assert candidate.type == IndicatorType.IP
    assert candidate.value == "203.0.113.5"


def test_extracted_indicators_holds_a_list_of_candidates():
    result = ExtractedIndicators(
        candidates=[
            IndicatorCandidate(type=IndicatorType.IP, value="203.0.113.5"),
            IndicatorCandidate(type=IndicatorType.DOMAIN, value="evil.test"),
        ]
    )
    assert len(result.candidates) == 2


def test_extracted_indicators_defaults_to_empty_list():
    result = ExtractedIndicators(candidates=[])
    assert result.candidates == []


def test_pattern_type_has_five_members():
    assert {p.value for p in PatternType} == {
        "brute_force", "scanning", "lateral_movement", "none", "other",
    }


def test_search_template_has_four_members():
    assert {t.value for t in SearchTemplate} == {
        "same_src_ip_24h", "same_rule_id_host", "same_dst_host", "none_needed",
    }


def test_correlation_decision_requires_pattern_type_and_follow_up_query():
    decision = CorrelationDecision(pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED)
    assert decision.pattern_type == PatternType.BRUTE_FORCE
    assert decision.follow_up_query == SearchTemplate.NONE_NEEDED


def test_correlation_decision_rejects_unknown_pattern_type():
    with pytest.raises(ValidationError):
        CorrelationDecision(pattern_type="not_a_real_pattern", follow_up_query=SearchTemplate.NONE_NEEDED)


def test_open_value_search_proposal_holds_a_search_value():
    proposal = OpenValueSearchProposal(search_value="admin@evil.test")
    assert proposal.search_value == "admin@evil.test"
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_agent_schemas.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.agent.schemas'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/agent/schemas.py
from enum import Enum

from pydantic import BaseModel

from app.schemas import IndicatorType


class IndicatorCandidate(BaseModel):
    type: IndicatorType
    value: str


class ExtractedIndicators(BaseModel):
    candidates: list[IndicatorCandidate]


class PatternType(str, Enum):
    BRUTE_FORCE = "brute_force"
    SCANNING = "scanning"
    LATERAL_MOVEMENT = "lateral_movement"
    NONE = "none"
    OTHER = "other"


class SearchTemplate(str, Enum):
    SAME_SRC_IP_24H = "same_src_ip_24h"
    SAME_RULE_ID_HOST = "same_rule_id_host"
    SAME_DST_HOST = "same_dst_host"
    NONE_NEEDED = "none_needed"


class CorrelationDecision(BaseModel):
    pattern_type: PatternType
    follow_up_query: SearchTemplate


class OpenValueSearchProposal(BaseModel):
    search_value: str
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_agent_schemas.py -v
```

Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add app/agent/schemas.py tests/test_agent_schemas.py
git commit -m "feat(agent): add Phase 4c schemas for extraction, correlation, and open-value search"
```

---

### Task 3: Canonical search query builder (`app/agent/correlation_queries.py`)

**Files:**
- Create: `app/agent/correlation_queries.py`
- Test: `tests/test_correlation_queries.py`

**Interfaces:**
- Consumes: `SearchClause`/`SearchQuery` (Task 1), `SearchTemplate` (Task 2).
- Produces: `build_canonical_queries(alert: Alert) -> dict[SearchTemplate, SearchQuery | None]` — consumed by Task 5's `_step_correlate`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_correlation_queries.py
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.agent.correlation_queries import build_canonical_queries
from app.agent.schemas import SearchTemplate
from app.schemas import AgentRef, Alert


def _make_alert(**overrides):
    defaults = dict(
        alert_id=uuid4(),
        source_alert_id="1699999999.123456",
        source_system="wazuh",
        rule_id="5710",
        rule_description="sshd: Attempt to login using a non-existent user",
        rule_level=5,
        timestamp=datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id="001", name="web-01", ip="10.0.0.5"),
        manager_name="wazuh-manager",
        location="/var/log/auth.log",
        full_log="Invalid user admin from 203.0.113.5",
        raw_json={"rule": {"id": "5710"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_builds_same_src_ip_query_when_source_ip_present():
    alert = _make_alert(source_ip="203.0.113.5")

    queries = build_canonical_queries(alert)

    query = queries[SearchTemplate.SAME_SRC_IP_24H]
    assert query is not None
    assert query.clauses[0].field == "source_ip"
    assert query.clauses[0].operator == "eq"
    assert query.clauses[0].value == "203.0.113.5"
    assert query.time_range == (alert.timestamp - timedelta(hours=24), alert.timestamp)


def test_same_src_ip_query_is_none_when_source_ip_absent():
    alert = _make_alert(source_ip=None)

    queries = build_canonical_queries(alert)

    assert queries[SearchTemplate.SAME_SRC_IP_24H] is None


def test_builds_same_rule_id_host_query_with_compound_clauses():
    alert = _make_alert()

    queries = build_canonical_queries(alert)

    query = queries[SearchTemplate.SAME_RULE_ID_HOST]
    assert query is not None
    assert len(query.clauses) == 2
    assert {(c.field, c.value) for c in query.clauses} == {("rule_id", "5710"), ("agent.id", "001")}


def test_builds_same_dst_host_query_when_destination_ip_present():
    alert = _make_alert(destination_ip="198.51.100.9")

    queries = build_canonical_queries(alert)

    query = queries[SearchTemplate.SAME_DST_HOST]
    assert query is not None
    assert query.clauses[0].field == "destination_ip"
    assert query.clauses[0].value == "198.51.100.9"


def test_same_dst_host_query_is_none_when_destination_ip_absent():
    alert = _make_alert(destination_ip=None)

    queries = build_canonical_queries(alert)

    assert queries[SearchTemplate.SAME_DST_HOST] is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_correlation_queries.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.agent.correlation_queries'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/agent/correlation_queries.py
from datetime import timedelta

from app.agent.schemas import SearchTemplate
from app.integration.models import SearchClause, SearchQuery
from app.schemas import Alert

CANONICAL_SEARCH_WINDOW = timedelta(hours=24)


def build_canonical_queries(alert: Alert) -> dict[SearchTemplate, SearchQuery | None]:
    window = (alert.timestamp - CANONICAL_SEARCH_WINDOW, alert.timestamp)
    queries: dict[SearchTemplate, SearchQuery | None] = {}

    if alert.source_ip:
        queries[SearchTemplate.SAME_SRC_IP_24H] = SearchQuery(
            clauses=[SearchClause(field="source_ip", operator="eq", value=alert.source_ip)],
            time_range=window,
        )
    else:
        queries[SearchTemplate.SAME_SRC_IP_24H] = None

    queries[SearchTemplate.SAME_RULE_ID_HOST] = SearchQuery(
        clauses=[
            SearchClause(field="rule_id", operator="eq", value=alert.rule_id),
            SearchClause(field="agent.id", operator="eq", value=alert.agent.id),
        ],
        time_range=window,
    )

    if alert.destination_ip:
        queries[SearchTemplate.SAME_DST_HOST] = SearchQuery(
            clauses=[SearchClause(field="destination_ip", operator="eq", value=alert.destination_ip)],
            time_range=window,
        )
    else:
        queries[SearchTemplate.SAME_DST_HOST] = None

    return queries
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_correlation_queries.py -v
```

Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add app/agent/correlation_queries.py tests/test_correlation_queries.py
git commit -m "feat(agent): add canonical search query builder for Correlate"
```

---

### Task 4: Extract Indicators (step 2b) — real LLM-assisted extraction

**Files:**
- Create: `app/agent/prompts.py` (started here, extended in later tasks)
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `ExtractedIndicators`/`IndicatorCandidate` (Task 2), `IPIndicator`/`HashIndicator`/`DomainIndicator`/`URLIndicator` (existing, `app.enrichment.indicators`), `LLMClientError` (existing, `app.llm.errors`).
- Produces: `build_extract_indicators_prompt(alert: Alert) -> str`; `AgenticAnalyst._step_extract_indicators(alert: Alert, model_available: bool) -> tuple[list[Indicator], InvestigationStep]` (signature change from Phase 4b — now takes `model_available`) — `investigate()`'s call site is updated within this same task (see Step 3).

- [ ] **Step 1: Write the failing tests**

Add this import to the top of `tests/test_state_graph.py`:

```python
from app.agent.schemas import ExtractedIndicators, IndicatorCandidate
from app.llm.errors import LLMClientError
from app.schemas import IndicatorType
```

(`IndicatorType` is likely already imported — check the existing `from app.schemas import EnrichmentVerdict, IndicatorType` line and don't duplicate it.)

Extend `_FakeLLMClient` (defined earlier in this file) to support configurable canned responses instead of always raising `NotImplementedError`:

```python
class _FakeLLMClient:
    def __init__(self, model_available=True, responses=None, error=None):
        self._model_available = model_available
        self._responses = responses or {}  # {schema_class: return_value}
        self._error = error

    def generate_structured(self, prompt, schema):
        if self._error is not None:
            raise self._error
        if schema in self._responses:
            return self._responses[schema]
        raise NotImplementedError(f"no canned response configured for {schema}")

    def health_check(self):
        return True

    def model_available(self):
        return self._model_available
```

(This replaces the existing `_FakeLLMClient` class definition in the file — same class name, extended constructor. Existing tests that construct `_FakeLLMClient(model_available=True)`/`_FakeLLMClient(model_available=False)` with no other arguments continue to work unchanged, since `responses`/`error` default to empty/`None`.)

Replace the two existing `_step_extract_indicators` tests (they call the old 1-argument signature) with the `model_available`-aware versions, and add new LLM-assisted-path tests:

```python
def test_step_extract_indicators_finds_and_validates_ip():
    analyst = _make_analyst()
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    indicators, step = analyst._step_extract_indicators(alert, model_available=False)

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.5"
    assert step.step_name == Step.EXTRACT_INDICATORS.value
    assert "regex: 1 candidates, 1 validated" in step.output_summary


def test_step_extract_indicators_returns_empty_list_when_nothing_found():
    analyst = _make_analyst()
    alert = _make_alert(full_log="nothing interesting here")

    indicators, step = analyst._step_extract_indicators(alert, model_available=False)

    assert indicators == []
    assert step.action == "completed"


def test_step_extract_indicators_skips_llm_when_model_unavailable():
    analyst = _make_analyst()
    alert = _make_alert(full_log="nothing interesting here")

    _, step = analyst._step_extract_indicators(alert, model_available=False)

    assert "LLM-assisted extraction skipped: model unavailable" in step.output_summary


def test_step_extract_indicators_merges_llm_candidates_with_regex_results():
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            ExtractedIndicators: ExtractedIndicators(
                candidates=[IndicatorCandidate(type=IndicatorType.DOMAIN, value="evil.test")]
            )
        },
    )
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    indicators, step = analyst._step_extract_indicators(alert, model_available=True)

    values = {i.value for i in indicators}
    assert values == {"203.0.113.5", "evil.test"}
    assert "LLM: 1 candidates, 1 validated" in step.output_summary


def test_step_extract_indicators_discards_invalid_llm_candidates():
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            ExtractedIndicators: ExtractedIndicators(
                candidates=[IndicatorCandidate(type=IndicatorType.IP, value="not-an-ip")]
            )
        },
    )
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert(full_log="nothing interesting here")

    indicators, step = analyst._step_extract_indicators(alert, model_available=True)

    assert indicators == []
    assert "LLM: 1 candidates, 0 validated" in step.output_summary


def test_step_extract_indicators_keeps_regex_results_when_llm_call_fails():
    llm_client = _FakeLLMClient(model_available=True, error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    indicators, step = analyst._step_extract_indicators(alert, model_available=True)

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.5"
    assert "LLM-assisted extraction failed: timeout" in step.output_summary
```

**This task also changes `_step_extract_indicators`'s signature, which `investigate()` already calls** (from Phase 4b) as `self._step_extract_indicators(alert)` — one argument short of the new signature. Three existing end-to-end tests exercise `investigate()` with `model_available=True` and will break the moment this signature changes, unless their `_FakeLLMClient` is given something to return for `ExtractedIndicators`. Update these three tests' `_FakeLLMClient(model_available=True)` constructor calls — `test_investigate_runs_full_pipeline_and_persists_report`, `test_investigate_degrades_gracefully_when_siem_context_unavailable`, `test_investigate_degrades_gracefully_when_alert_not_yet_saved` — to:

```python
llm_client=_FakeLLMClient(
    model_available=True,
    responses={ExtractedIndicators: ExtractedIndicators(candidates=[])},
),
```

(An empty candidate list is the simplest safe response — none of these three tests are testing LLM-assisted extraction itself, they're testing other degrade paths, so the LLM call just needs to succeed harmlessly. `CorrelationDecision`/`RiskAssessment` responses aren't needed yet — `_step_correlate`/`_step_risk_assessment` are still Phase 4b stubs at this point in the plan and don't call the LLM. Tasks 6 and 8 will each add one more entry to this same `responses` dict when those steps start making real calls.)

Every other later task in this plan that calls `_step_extract_indicators` directly in a test must pass `model_available` as the second positional argument.

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL — `TypeError: _step_extract_indicators() takes 2 positional arguments but 3 were given` (old signature), plus `ImportError`/`AttributeError` for the new schema imports until Task 2 is merged (already complete by this point in the plan).

- [ ] **Step 3: Write minimal implementation**

Create `app/agent/prompts.py`:

```python
# app/agent/prompts.py
from app.schemas import Alert


def build_extract_indicators_prompt(alert: Alert) -> str:
    return (
        "You are extracting security indicators (IP addresses, file hashes, domains, URLs) "
        "from a SIEM alert's raw log text. Some indicators may be obfuscated or defanged "
        "(e.g. '185[.]220[.]101[.]1' instead of '185.220.101.1', 'hxxp://' instead of 'http://').\n\n"
        f"Raw log: {alert.full_log}\n"
        f"Additional decoded fields: {alert.data}\n\n"
        "List every candidate indicator you find, with its type (ip, file_hash, domain, or url) "
        "and its value in normal (de-obfuscated) form."
    )
```

Update the import block at the top of `app/agent/state_graph.py`:

```python
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import ValidationError

from app.agent.indicator_extraction import extract_and_validate
from app.agent.prompts import build_extract_indicators_prompt
from app.agent.schemas import ExtractedIndicators
from app.enrichment.indicators import DomainIndicator, HashIndicator, IPIndicator, Indicator, URLIndicator
from app.enrichment.registry import EnrichmentRegistry
from app.integration.errors import SIEMConnectorError
from app.integration.models import AgentContext, RuleMetadata
from app.integration.siem_connector import SIEMConnector
from app.llm.client import LLMClient
from app.llm.errors import LLMClientError
from app.schemas import (
    Alert,
    AlertStatus,
    Confidence,
    EnrichmentResult,
    EnrichmentVerdict,
    IndicatorType,
    InvestigationStep,
    ModelMetadata,
    Report,
    ReportStatus,
    RiskAssessment,
    Severity,
)
from app.storage.alert_store import AlertStore

_INDICATOR_TYPE_TO_VALIDATOR: dict[IndicatorType, type] = {
    IndicatorType.IP: IPIndicator,
    IndicatorType.FILE_HASH: HashIndicator,
    IndicatorType.DOMAIN: DomainIndicator,
    IndicatorType.URL: URLIndicator,
}


def _merge_indicators(regex_validated: list[Indicator], llm_validated: list[Indicator]) -> list[Indicator]:
    seen = {(type(i), i.value) for i in regex_validated}
    merged = list(regex_validated)
    for indicator in llm_validated:
        key = (type(indicator), indicator.value)
        if key not in seen:
            seen.add(key)
            merged.append(indicator)
    return merged
```

Replace the `_step_extract_indicators` method:

```python
    def _step_extract_indicators(
        self, alert: Alert, model_available: bool
    ) -> tuple[list[Indicator], InvestigationStep]:
        validated, candidate_count, validated_count = extract_and_validate(alert)

        if not model_available:
            step = InvestigationStep(
                step_name=Step.EXTRACT_INDICATORS.value,
                action="completed",
                tool_used="regex_extraction",
                input=None,
                output_summary=(
                    f"regex: {candidate_count} candidates, {validated_count} validated "
                    "(LLM-assisted extraction skipped: model unavailable)"
                ),
                timestamp=datetime.now(timezone.utc),
            )
            return validated, step

        llm_validated, llm_candidate_count, llm_validated_count, llm_error = self._extract_indicators_via_llm(alert)
        merged = _merge_indicators(validated, llm_validated)

        if llm_error is not None:
            summary = (
                f"regex: {candidate_count} candidates, {validated_count} validated; "
                f"LLM-assisted extraction failed: {llm_error}"
            )
        else:
            summary = (
                f"regex: {candidate_count} candidates, {validated_count} validated; "
                f"LLM: {llm_candidate_count} candidates, {llm_validated_count} validated"
            )

        step = InvestigationStep(
            step_name=Step.EXTRACT_INDICATORS.value,
            action="completed",
            tool_used="regex_extraction+llm_extraction",
            input=None,
            output_summary=summary,
            timestamp=datetime.now(timezone.utc),
        )
        return merged, step

    def _extract_indicators_via_llm(self, alert: Alert) -> tuple[list[Indicator], int, int, str | None]:
        prompt = build_extract_indicators_prompt(alert)
        try:
            result = self._llm_client.generate_structured(prompt, ExtractedIndicators)
        except LLMClientError as exc:
            return [], 0, 0, exc.kind

        validated: list[Indicator] = []
        for candidate in result.candidates:
            validator_cls = _INDICATOR_TYPE_TO_VALIDATOR.get(candidate.type)
            if validator_cls is None:
                continue
            try:
                validated.append(validator_cls(value=candidate.value))
            except ValidationError:
                continue
        return validated, len(result.candidates), len(validated), None
```

Finally, update `investigate()`'s call to this method — change:

```python
        indicators, extract_step = self._step_extract_indicators(alert)
```

to:

```python
        indicators, extract_step = self._step_extract_indicators(alert, model_available)
```

(`investigate()`'s other lines are untouched in this task — `_step_correlate`/`_step_risk_assessment` still get called the old, pre-4c way until Tasks 5 and 8 update those lines in turn.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (all tests up through this task)

- [ ] **Step 5: Run the full project test suite**

```bash
pytest -v
```

Expected: PASS — confirms the three updated end-to-end tests still work with `investigate()`'s new call site.

- [ ] **Step 6: Commit**

```bash
git add app/agent/prompts.py app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): add real LLM-assisted indicator extraction (step 2b)"
```

---

### Task 5: Correlate — canonical searches and deterministic evidence count

**Files:**
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `build_canonical_queries` (Task 3), `SearchTemplate` (Task 2).
- Produces: `AgenticAnalyst._run_canonical_searches(alert: Alert) -> tuple[dict[SearchTemplate, SearchResult], int]` (results keyed by template, only for templates that had a non-`None` query; the `int` is the summed `evidence_count`) — consumed by Task 6.

- [ ] **Step 1: Write the failing tests**

Remove the existing `test_step_correlate_delegates_to_stub_step` test — it asserts `_step_correlate(model_available=True)`'s old single-argument stub behavior (`step.action == "stub"`), which this task's signature change (`_step_correlate(alert, model_available)`, returning real findings instead of delegating to `_stub_step`) makes obsolete. Leave `test_stub_step_logs_stub_when_model_available`/`test_stub_step_logs_skipped_when_model_unavailable` in place — those test `_stub_step` directly, which is unchanged in this phase (still used by `_step_draft_report`/`_step_self_check`, Phase 4d's stubs).

Add this import to the top of `tests/test_state_graph.py`:

```python
from app.agent.schemas import PatternType, SearchTemplate
from app.integration.models import SearchResult
```

Extend `_FakeSIEMConnector` (defined earlier in this file) so its `search()` method is configurable instead of always raising `NotImplementedError`:

```python
class _FakeSIEMConnector:
    def __init__(self, agent_context=None, rule_metadata=None, context_error=None, search_results=None):
        self._agent_context = agent_context
        self._rule_metadata = rule_metadata
        self._context_error = context_error
        self._search_results = search_results or {}  # {field_name: SearchResult}
        self.search_calls = []

    def health_check(self):
        return True

    def pull_alerts(self, since, until=None, limit=500):
        return []

    def search(self, query):
        self.search_calls.append(query)
        # Keyed by the first clause's field — sufficient for these tests, since each
        # canonical/follow-up query in this phase has a distinguishable primary field.
        field = query.clauses[0].field
        return self._search_results.get(field, SearchResult(alerts=[], total_count=0))

    def get_agent_context(self, agent_id):
        if self._context_error is not None:
            raise self._context_error
        return self._agent_context

    def get_rule_metadata(self, rule_id):
        if self._context_error is not None:
            raise self._context_error
        return self._rule_metadata
```

(This replaces the existing `_FakeSIEMConnector` definition — same class name, extended. Existing tests constructing it with `agent_context=`/`rule_metadata=`/`context_error=` only continue to work unchanged.)

```python
def test_run_canonical_searches_sums_evidence_count_across_all_three():
    siem = _FakeSIEMConnector(
        search_results={
            "source_ip": SearchResult(alerts=[], total_count=3),
            "rule_id": SearchResult(alerts=[], total_count=5),
            "destination_ip": SearchResult(alerts=[], total_count=2),
        }
    )
    analyst = _make_analyst(siem=siem)
    alert = _make_alert(source_ip="203.0.113.5", destination_ip="198.51.100.9")

    results, evidence_count = analyst._run_canonical_searches(alert)

    assert evidence_count == 10
    assert len(results) == 3


def test_run_canonical_searches_skips_missing_fields():
    siem = _FakeSIEMConnector(search_results={"rule_id": SearchResult(alerts=[], total_count=4)})
    analyst = _make_analyst(siem=siem)
    alert = _make_alert(source_ip=None, destination_ip=None)

    results, evidence_count = analyst._run_canonical_searches(alert)

    assert evidence_count == 4
    assert SearchTemplate.SAME_SRC_IP_24H not in results
    assert SearchTemplate.SAME_DST_HOST not in results
    assert SearchTemplate.SAME_RULE_ID_HOST in results


def test_step_correlate_runs_searches_and_skips_classification_when_model_unavailable():
    siem = _FakeSIEMConnector(search_results={"rule_id": SearchResult(alerts=[], total_count=7)})
    analyst = _make_analyst(siem=siem)
    alert = _make_alert(source_ip=None, destination_ip=None)

    pattern_type, evidence_count, step = analyst._step_correlate(alert, model_available=False)

    assert pattern_type == PatternType.OTHER
    assert evidence_count == 7
    assert step.step_name == Step.CORRELATE.value
    assert "classification skipped: model unavailable" in step.output_summary
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL — `AttributeError: 'AgenticAnalyst' object has no attribute '_run_canonical_searches'`

- [ ] **Step 3: Write minimal implementation**

Add this import to the top of `app/agent/state_graph.py`:

```python
from app.agent.correlation_queries import build_canonical_queries
from app.agent.schemas import PatternType, SearchTemplate
from app.integration.models import SearchResult
```

Add these methods (after `_step_gather_context`, before `_stub_step`):

```python
    def _run_canonical_searches(self, alert: Alert) -> tuple[dict[SearchTemplate, SearchResult], int]:
        queries = build_canonical_queries(alert)
        results: dict[SearchTemplate, SearchResult] = {}
        for template, query in queries.items():
            if query is not None:
                results[template] = self._siem.search(query)
        evidence_count = sum(r.total_count for r in results.values())
        return results, evidence_count

    def _step_correlate(
        self, alert: Alert, model_available: bool
    ) -> tuple[PatternType, int, InvestigationStep]:
        results, evidence_count = self._run_canonical_searches(alert)

        if not model_available:
            step = InvestigationStep(
                step_name=Step.CORRELATE.value,
                action="completed",
                tool_used="siem_connector",
                input=None,
                output_summary=(
                    f"ran {len(results)} canonical search(es), {evidence_count} total evidence "
                    "(classification skipped: model unavailable)"
                ),
                timestamp=datetime.now(timezone.utc),
            )
            return PatternType.OTHER, evidence_count, step

        step = InvestigationStep(
            step_name=Step.CORRELATE.value,
            action="completed",
            tool_used="siem_connector",
            input=None,
            output_summary=f"ran {len(results)} canonical search(es), {evidence_count} total evidence",
            timestamp=datetime.now(timezone.utc),
        )
        return PatternType.OTHER, evidence_count, step
```

(The `model_available=True` branch is deliberately minimal here — Task 6 replaces it with the real classification call. This task's own scope is only the deterministic canonical-search plumbing and the `model_available=False` degrade path.)

`_step_correlate`'s signature changes from Phase 4b's `(model_available)` (returning one `InvestigationStep`) to `(alert, model_available)` (returning a 3-tuple) — `investigate()` needs its call site updated to match. Change:

```python
        timeline.append(self._step_correlate(model_available))
```

to:

```python
        pattern_type, evidence_count, correlate_step = self._step_correlate(alert, model_available)
        timeline.append(correlate_step)
```

`pattern_type`/`evidence_count` aren't consumed by anything yet at this point in the plan (`_step_risk_assessment` is still Phase 4b's stub, taking only `model_available`) — that's expected; Task 8 threads them through once Risk Assessment can use them. The three end-to-end tests touched in Task 4 need no further changes here: `_step_correlate`'s `model_available=True` branch still doesn't call the LLM (that's Task 6), so nothing new needs to be added to their `_FakeLLMClient` configuration yet.

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (all tests up through this task)

- [ ] **Step 5: Run the full project test suite**

```bash
pytest -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): run canonical searches deterministically in Correlate"
```

---

### Task 6: Correlate — classification call and closed-menu follow-up

**Files:**
- Modify: `app/agent/prompts.py`
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `CorrelationDecision` (Task 2), `_run_canonical_searches` (Task 5).
- Produces: `build_correlation_decision_prompt(alert, canonical_results, evidence_count) -> str`; `AgenticAnalyst._classify_correlation(alert, canonical_results, evidence_count) -> CorrelationDecision` — consumed by Task 7 (open-value search's trigger condition).

- [ ] **Step 1: Write the failing tests**

```python
def test_step_correlate_classifies_pattern_and_runs_follow_up_query():
    siem = _FakeSIEMConnector(
        search_results={
            "source_ip": SearchResult(alerts=[], total_count=14),
            "rule_id": SearchResult(alerts=[], total_count=14),
        }
    )
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.SAME_SRC_IP_24H
            )
        },
    )
    analyst = _make_analyst(siem=siem, llm_client=llm_client)
    alert = _make_alert(source_ip="203.0.113.5", destination_ip=None)

    pattern_type, evidence_count, step = analyst._step_correlate(alert, model_available=True)

    assert pattern_type == PatternType.BRUTE_FORCE
    # base evidence (14 from rule_id canonical search, source_ip canonical search also 14) + the
    # follow-up re-running the same same_src_ip_24h query, adding another 14
    assert evidence_count == 14 + 14 + 14
    assert "pattern_type=brute_force" in step.output_summary
    assert "same_src_ip_24h" in step.output_summary


def test_step_correlate_skips_follow_up_when_none_needed():
    siem = _FakeSIEMConnector(search_results={"rule_id": SearchResult(alerts=[], total_count=1)})
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.NONE, follow_up_query=SearchTemplate.NONE_NEEDED
            )
        },
    )
    analyst = _make_analyst(siem=siem, llm_client=llm_client)
    alert = _make_alert(source_ip=None, destination_ip=None)

    pattern_type, evidence_count, step = analyst._step_correlate(alert, model_available=True)

    assert pattern_type == PatternType.NONE
    assert evidence_count == 1
    assert len(siem.search_calls) == 1  # only the one canonical search — no follow-up executed


def test_step_correlate_falls_back_to_other_when_classification_call_fails():
    siem = _FakeSIEMConnector(search_results={"rule_id": SearchResult(alerts=[], total_count=2)})
    llm_client = _FakeLLMClient(model_available=True, error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(siem=siem, llm_client=llm_client)
    alert = _make_alert(source_ip=None, destination_ip=None)

    pattern_type, evidence_count, step = analyst._step_correlate(alert, model_available=True)

    assert pattern_type == PatternType.OTHER
    assert evidence_count == 2
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL — the `model_available=True` branch still returns the Task 5 placeholder (`PatternType.OTHER` unconditionally, no follow-up execution), so `test_step_correlate_classifies_pattern_and_runs_follow_up_query` fails on `pattern_type == PatternType.BRUTE_FORCE`.

- [ ] **Step 3: Write minimal implementation**

Append to `app/agent/prompts.py`:

```python
def build_correlation_decision_prompt(alert, canonical_results, evidence_count) -> str:
    findings_summary = "\n".join(
        f"- {template.value}: {result.total_count} matching alert(s)"
        for template, result in canonical_results.items()
    )
    return (
        "You are analyzing correlation search results for a security alert.\n\n"
        f"Alert: rule {alert.rule_id} ({alert.rule_description}), level {alert.rule_level}.\n\n"
        f"Canonical search results:\n{findings_summary}\n\n"
        f"Total evidence count: {evidence_count}\n\n"
        "Classify the pattern_type (brute_force, scanning, lateral_movement, none, or other), "
        "and pick at most one follow_up_query from the closed menu "
        "(same_src_ip_24h, same_rule_id_host, same_dst_host, or none_needed) if further investigation "
        "of one of the canonical searches would help confirm the pattern."
    )
```

Task 4 added `from app.agent.prompts import build_extract_indicators_prompt` and `from app.agent.schemas import ExtractedIndicators` to `app/agent/state_graph.py`. Replace those two lines with the following (same two modules, extended to also import this task's new names — one import statement per module, not two separate ones per module):

```python
from app.agent.prompts import build_correlation_decision_prompt, build_extract_indicators_prompt
from app.agent.schemas import CorrelationDecision, ExtractedIndicators, PatternType, SearchTemplate
```

Replace the `model_available=True` branch of `_step_correlate` (and add `_classify_correlation`):

```python
    def _step_correlate(
        self, alert: Alert, model_available: bool
    ) -> tuple[PatternType, int, InvestigationStep]:
        results, evidence_count = self._run_canonical_searches(alert)
        queries = build_canonical_queries(alert)

        if not model_available:
            step = InvestigationStep(
                step_name=Step.CORRELATE.value,
                action="completed",
                tool_used="siem_connector",
                input=None,
                output_summary=(
                    f"ran {len(results)} canonical search(es), {evidence_count} total evidence "
                    "(classification skipped: model unavailable)"
                ),
                timestamp=datetime.now(timezone.utc),
            )
            return PatternType.OTHER, evidence_count, step

        decision = self._classify_correlation(alert, results, evidence_count)

        follow_up_note = ""
        if decision.follow_up_query != SearchTemplate.NONE_NEEDED:
            follow_up_query = queries.get(decision.follow_up_query)
            if follow_up_query is not None:
                follow_up_result = self._siem.search(follow_up_query)
                evidence_count += follow_up_result.total_count
                follow_up_note = f"; follow-up {decision.follow_up_query.value} added {follow_up_result.total_count}"

        step = InvestigationStep(
            step_name=Step.CORRELATE.value,
            action="completed",
            tool_used="siem_connector+llm",
            input=None,
            output_summary=f"pattern_type={decision.pattern_type.value}, evidence_count={evidence_count}{follow_up_note}",
            timestamp=datetime.now(timezone.utc),
        )
        return decision.pattern_type, evidence_count, step

    def _classify_correlation(
        self, alert: Alert, canonical_results: dict[SearchTemplate, SearchResult], evidence_count: int
    ) -> CorrelationDecision:
        prompt = build_correlation_decision_prompt(alert, canonical_results, evidence_count)
        try:
            return self._llm_client.generate_structured(prompt, CorrelationDecision)
        except LLMClientError:
            return CorrelationDecision(pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED)
```

**This task makes Correlate's `model_available=True` branch call the LLM for the first time** — the three end-to-end tests updated in Task 4 (`test_investigate_runs_full_pipeline_and_persists_report`, `test_investigate_degrades_gracefully_when_siem_context_unavailable`, `test_investigate_degrades_gracefully_when_alert_not_yet_saved`) will now reach `_classify_correlation`'s `generate_structured` call. Their `_FakeLLMClient` doesn't have a `CorrelationDecision` response configured yet, so it raises `NotImplementedError` — which is **not** an `LLMClientError`, so `_classify_correlation`'s `except LLMClientError` won't catch it, and the test would crash rather than degrade. Add one entry to the same `responses` dict Task 4 created in all three tests:

```python
llm_client=_FakeLLMClient(
    model_available=True,
    responses={
        ExtractedIndicators: ExtractedIndicators(candidates=[]),
        CorrelationDecision: CorrelationDecision(
            pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
        ),
    },
),
```

(`PatternType.BRUTE_FORCE` is deliberately not `NONE`/`OTHER` — Task 7 makes the open-value search trigger for either of those, and these three tests aren't testing that path, so picking a pattern that doesn't trigger it keeps them from needing yet another canned response.) No `investigate()` wiring change is needed in this task — `_step_correlate`'s external signature/return shape hasn't changed since Task 5, only its internal behavior.

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (all tests up through this task)

- [ ] **Step 5: Run the full project test suite**

```bash
pytest -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/agent/prompts.py app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): add Correlate's classification call and closed-menu follow-up execution"
```

---

### Task 7: Correlate — conditional open-value search

**Files:**
- Modify: `app/agent/prompts.py`
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `OpenValueSearchProposal` (Task 2), `_classify_correlation` (Task 6).
- Produces: `build_open_value_search_prompt(alert, canonical_results) -> str`; `AgenticAnalyst._run_open_value_search(alert, canonical_results) -> str` (empty string if skipped/failed, else a note fragment) — consumed by `_step_correlate`'s own `output_summary`.

- [ ] **Step 1: Write the failing tests**

```python
def test_step_correlate_runs_open_value_search_when_pattern_is_none():
    siem = _FakeSIEMConnector(
        search_results={
            "rule_id": SearchResult(alerts=[], total_count=1),
            "full_log": SearchResult(alerts=[], total_count=3),
        }
    )
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.NONE, follow_up_query=SearchTemplate.NONE_NEEDED
            ),
            OpenValueSearchProposal: OpenValueSearchProposal(search_value="admin@evil.test"),
        },
    )
    analyst = _make_analyst(siem=siem, llm_client=llm_client)
    alert = _make_alert(source_ip=None, destination_ip=None)

    pattern_type, evidence_count, step = analyst._step_correlate(alert, model_available=True)

    assert pattern_type == PatternType.NONE
    assert "noisier, unstructured match" in step.output_summary
    assert "admin@evil.test" in step.output_summary
    full_log_calls = [c for c in siem.search_calls if c.clauses[0].field == "full_log"]
    assert len(full_log_calls) == 1
    assert full_log_calls[0].clauses[0].operator == "contains"


def test_step_correlate_skips_open_value_search_when_pattern_is_identified():
    siem = _FakeSIEMConnector(search_results={"rule_id": SearchResult(alerts=[], total_count=1)})
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
            )
        },
    )
    analyst = _make_analyst(siem=siem, llm_client=llm_client)
    alert = _make_alert(source_ip=None, destination_ip=None)

    _, _, step = analyst._step_correlate(alert, model_available=True)

    assert "noisier" not in step.output_summary
    assert all(c.clauses[0].field != "full_log" for c in siem.search_calls)


def test_step_correlate_skips_open_value_search_when_proposal_call_fails():
    class _SequencedLLMClient:
        def __init__(self):
            self.calls = 0

        def generate_structured(self, prompt, schema):
            self.calls += 1
            if schema is CorrelationDecision:
                return CorrelationDecision(pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED)
            raise LLMClientError("timeout", "took too long")

        def health_check(self):
            return True

        def model_available(self):
            return True

    siem = _FakeSIEMConnector(search_results={"rule_id": SearchResult(alerts=[], total_count=1)})
    analyst = _make_analyst(siem=siem, llm_client=_SequencedLLMClient())
    alert = _make_alert(source_ip=None, destination_ip=None)

    _, _, step = analyst._step_correlate(alert, model_available=True)

    assert "noisier" not in step.output_summary
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL — `AttributeError: 'AgenticAnalyst' object has no attribute '_run_open_value_search'`

- [ ] **Step 3: Write minimal implementation**

Append to `app/agent/prompts.py`:

```python
def build_open_value_search_prompt(alert, canonical_results) -> str:
    findings_summary = "\n".join(
        f"- {template.value}: {result.total_count} matching alert(s)"
        for template, result in canonical_results.items()
    )
    return (
        "The closed-menu correlation searches below did not find or explain a clear pattern for "
        "this security alert. Propose ONE additional free-text search value (not a field name) "
        "that might surface related evidence in the alert log text.\n\n"
        f"Alert: rule {alert.rule_id} ({alert.rule_description}), level {alert.rule_level}.\n\n"
        f"Canonical search results:\n{findings_summary}\n\n"
        "Respond with a single search_value string."
    )
```

Replace `app/agent/state_graph.py`'s `from app.agent.prompts import ...` and `from app.agent.schemas import ...` lines (currently importing `build_correlation_decision_prompt, build_extract_indicators_prompt` and `CorrelationDecision, ExtractedIndicators, PatternType, SearchTemplate`, from Task 6) with these extended versions — same two modules, adding this task's new names:

```python
from app.agent.prompts import (
    build_correlation_decision_prompt,
    build_extract_indicators_prompt,
    build_open_value_search_prompt,
)
from app.agent.schemas import (
    CorrelationDecision,
    ExtractedIndicators,
    OpenValueSearchProposal,
    PatternType,
    SearchTemplate,
)
```

Update `_step_correlate` to call the new open-value-search helper, and add the helper methods:

```python
    def _step_correlate(
        self, alert: Alert, model_available: bool
    ) -> tuple[PatternType, int, InvestigationStep]:
        results, evidence_count = self._run_canonical_searches(alert)
        queries = build_canonical_queries(alert)

        if not model_available:
            step = InvestigationStep(
                step_name=Step.CORRELATE.value,
                action="completed",
                tool_used="siem_connector",
                input=None,
                output_summary=(
                    f"ran {len(results)} canonical search(es), {evidence_count} total evidence "
                    "(classification skipped: model unavailable)"
                ),
                timestamp=datetime.now(timezone.utc),
            )
            return PatternType.OTHER, evidence_count, step

        decision = self._classify_correlation(alert, results, evidence_count)

        follow_up_note = ""
        if decision.follow_up_query != SearchTemplate.NONE_NEEDED:
            follow_up_query = queries.get(decision.follow_up_query)
            if follow_up_query is not None:
                follow_up_result = self._siem.search(follow_up_query)
                evidence_count += follow_up_result.total_count
                follow_up_note = f"; follow-up {decision.follow_up_query.value} added {follow_up_result.total_count}"

        open_value_note = ""
        if decision.pattern_type in (PatternType.NONE, PatternType.OTHER):
            open_value_note = self._run_open_value_search(alert, results)

        step = InvestigationStep(
            step_name=Step.CORRELATE.value,
            action="completed",
            tool_used="siem_connector+llm",
            input=None,
            output_summary=(
                f"pattern_type={decision.pattern_type.value}, evidence_count={evidence_count}"
                f"{follow_up_note}{open_value_note}"
            ),
            timestamp=datetime.now(timezone.utc),
        )
        return decision.pattern_type, evidence_count, step

    def _classify_correlation(
        self, alert: Alert, canonical_results: dict[SearchTemplate, SearchResult], evidence_count: int
    ) -> CorrelationDecision:
        prompt = build_correlation_decision_prompt(alert, canonical_results, evidence_count)
        try:
            return self._llm_client.generate_structured(prompt, CorrelationDecision)
        except LLMClientError:
            return CorrelationDecision(pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED)

    def _run_open_value_search(
        self, alert: Alert, canonical_results: dict[SearchTemplate, SearchResult]
    ) -> str:
        prompt = build_open_value_search_prompt(alert, canonical_results)
        try:
            proposal = self._llm_client.generate_structured(prompt, OpenValueSearchProposal)
        except LLMClientError:
            return ""

        query = SearchQuery(
            clauses=[SearchClause(field="full_log", operator="contains", value=proposal.search_value)],
            time_range=(alert.timestamp - CANONICAL_SEARCH_WINDOW, alert.timestamp),
        )
        result = self._siem.search(query)
        return (
            f"; open-value search for {proposal.search_value!r} found {result.total_count} "
            "(noisier, unstructured match)"
        )
```

`_run_open_value_search` needs `CANONICAL_SEARCH_WINDOW` (Task 3's search-window constant) and `SearchClause`/`SearchQuery` (Task 1). Replace `app/agent/state_graph.py`'s `from app.agent.correlation_queries import build_canonical_queries` (Task 5) and `from app.integration.models import AgentContext, RuleMetadata` (Phase 4b) lines with these extended versions:

```python
from app.agent.correlation_queries import CANONICAL_SEARCH_WINDOW, build_canonical_queries
from app.integration.models import AgentContext, RuleMetadata, SearchClause, SearchQuery
```

No changes are needed to the three shared end-to-end tests from Task 4/6 — their `CorrelationDecision` response uses `PatternType.BRUTE_FORCE`, which never triggers this task's open-value search (only `NONE`/`OTHER` do), so their `_FakeLLMClient` doesn't need an `OpenValueSearchProposal` entry.

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (all tests up through this task)

- [ ] **Step 5: Run the full project test suite**

```bash
pytest -v
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add app/agent/prompts.py app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): add conditional open-value search to Correlate"
```

---

### Task 8: Risk Assessment (step 6) — real LLM call

**Files:**
- Modify: `app/agent/prompts.py`
- Modify: `app/agent/state_graph.py`
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: `RiskAssessment` (existing, `app.schemas`), `PatternType` (Task 2).
- Produces: `build_risk_assessment_prompt(alert, pattern_type, evidence_count, enrichment_results) -> str`; `AgenticAnalyst._step_risk_assessment(alert, pattern_type, evidence_count, enrichment_results, model_available) -> tuple[RiskAssessment, InvestigationStep]` (signature change from Phase 4b — no longer a stub delegate); updated `_assemble_report(alert, timeline, enrichment_results, risk_assessment, model_available) -> Report` and `investigate()` — this task finishes the phase's full wiring (see Step 3).

- [ ] **Step 1: Write the failing tests**

Remove the old stub-delegate test `test_step_risk_assessment_delegates_to_stub_step` (it tests behavior this task removes) and replace with:

```python
def test_step_risk_assessment_returns_real_assessment():
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            RiskAssessment: RiskAssessment(
                severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="matches known malicious IP"
            )
        },
    )
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()

    assessment, step = analyst._step_risk_assessment(
        alert, PatternType.BRUTE_FORCE, 14, [], model_available=True
    )

    assert assessment.severity == Severity.HIGH
    assert assessment.confidence == Confidence.HIGH
    assert step.step_name == Step.RISK_ASSESSMENT.value
    assert step.action == "completed"
    assert "severity=high" in step.output_summary


def test_step_risk_assessment_skips_when_model_unavailable():
    analyst = _make_analyst()
    alert = _make_alert()

    assessment, step = analyst._step_risk_assessment(
        alert, PatternType.OTHER, 0, [], model_available=False
    )

    assert assessment.severity == Severity.LOW
    assert assessment.confidence == Confidence.LOW
    assert step.action == "skipped"


def test_step_risk_assessment_falls_back_on_llm_error():
    llm_client = _FakeLLMClient(model_available=True, error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()

    assessment, step = analyst._step_risk_assessment(
        alert, PatternType.OTHER, 0, [], model_available=True
    )

    assert assessment.severity == Severity.LOW
    assert assessment.confidence == Confidence.LOW
    assert "risk assessment failed: timeout" in assessment.rationale
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_state_graph.py -v
```

Expected: FAIL — `TypeError: _step_risk_assessment() takes 2 positional arguments but 6 were given` (old stub signature only takes `model_available`)

- [ ] **Step 3: Write minimal implementation**

Append to `app/agent/prompts.py`:

```python
def build_risk_assessment_prompt(alert, pattern_type, evidence_count, enrichment_results) -> str:
    enrichment_summary = "\n".join(
        f"- {e.indicator_type.value} {e.indicator_value}: {e.verdict.value} (provider {e.provider_id})"
        for e in enrichment_results
    ) or "none"
    mitre_summary = (
        ", ".join(f"{m.technique_id} ({m.technique_name})" for m in alert.mitre) if alert.mitre else "none mapped"
    )
    return (
        "You are assessing the risk of a security alert for a human analyst to review.\n\n"
        f"Rule: {alert.rule_id} - {alert.rule_description} (level {alert.rule_level}, "
        f"groups: {', '.join(alert.rule_groups)}).\n"
        f"Known MITRE ATT&CK mapping: {mitre_summary}.\n"
        f"Correlation findings: pattern_type={pattern_type.value}, evidence_count={evidence_count}.\n"
        f"Enrichment findings:\n{enrichment_summary}\n\n"
        "Assess the severity (low/medium/high/critical), your confidence in this assessment "
        "(low/medium/high), and a one-to-two-sentence rationale."
    )
```

Replace `app/agent/state_graph.py`'s `from app.agent.prompts import (...)` line (currently the 3-name version from Task 7) with this extended version, adding `build_risk_assessment_prompt`:

```python
from app.agent.prompts import (
    build_correlation_decision_prompt,
    build_extract_indicators_prompt,
    build_open_value_search_prompt,
    build_risk_assessment_prompt,
)
```

Replace `_step_risk_assessment` (previously `return self._stub_step(Step.RISK_ASSESSMENT, model_available)`) with:

```python
    def _step_risk_assessment(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], model_available: bool,
    ) -> tuple[RiskAssessment, InvestigationStep]:
        if not model_available:
            assessment = RiskAssessment(
                severity=Severity.LOW, confidence=Confidence.LOW,
                rationale="risk assessment skipped: model unavailable",
            )
            step = InvestigationStep(
                step_name=Step.RISK_ASSESSMENT.value, action="skipped", tool_used=None, input=None,
                output_summary="skipped: model unavailable", timestamp=datetime.now(timezone.utc),
            )
            return assessment, step

        assessment = self._assess_risk(alert, pattern_type, evidence_count, enrichment_results)
        step = InvestigationStep(
            step_name=Step.RISK_ASSESSMENT.value, action="completed", tool_used="llm", input=None,
            output_summary=f"severity={assessment.severity.value}, confidence={assessment.confidence.value}",
            timestamp=datetime.now(timezone.utc),
        )
        return assessment, step

    def _assess_risk(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult],
    ) -> RiskAssessment:
        prompt = build_risk_assessment_prompt(alert, pattern_type, evidence_count, enrichment_results)
        try:
            return self._llm_client.generate_structured(prompt, RiskAssessment)
        except LLMClientError as exc:
            return RiskAssessment(
                severity=Severity.LOW, confidence=Confidence.LOW,
                rationale=f"risk assessment failed: {exc.kind}",
            )
```

Remove `_step_risk_assessment`'s old one-line stub-delegate body (shown above as the replacement) — `Step.RISK_ASSESSMENT` is no longer passed to `_stub_step` anywhere; `_stub_step` remains used only by `_step_draft_report`/`_step_self_check` (still Phase 4d stubs).

**This task makes Risk Assessment call the LLM for the first time, and is also where `_assemble_report`/`investigate()` need their final rewiring for this phase** — Risk Assessment is the last of the three real steps, and its output (`RiskAssessment`) is what `_assemble_report` needs to stop hardcoding a stub value for.

First, the same three shared end-to-end tests (Task 4/6) need one more `responses` entry, since their `_FakeLLMClient` will now reach `_assess_risk`'s `generate_structured` call too:

```python
llm_client=_FakeLLMClient(
    model_available=True,
    responses={
        ExtractedIndicators: ExtractedIndicators(candidates=[]),
        CorrelationDecision: CorrelationDecision(
            pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
        ),
        RiskAssessment: RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x"),
    },
),
```

Second, replace `_assemble_report` (it currently always builds its own `RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="stub — risk assessment not yet implemented (Phase 4c)")` and hardcodes `model_name="qwen3.5:9b"`/`prompt_version="stub-4b"`) with:

```python
    def _assemble_report(
        self,
        alert: Alert,
        timeline: list[InvestigationStep],
        enrichment_results: list[EnrichmentResult],
        risk_assessment: RiskAssessment,
        model_available: bool,
    ) -> Report:
        return Report(
            report_id=uuid4(),
            alert_id=alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            alert_summary=f"Stub report for alert {alert.alert_id} — full investigation logic pending Phase 4d.",
            investigation_timeline=timeline,
            enrichment_findings=enrichment_results,
            risk_assessment=risk_assessment,
            recommended_actions=[],
            recommended_actions_freeform_experimental=None,
            uncertainty_notes=(
                "This report was produced by the Phase 4c pipeline — steps 7-8 "
                "(Draft Report, Self-Check) are still stubs, not real analysis."
            ),
            status=ReportStatus.NEEDS_HUMAN_REVIEW,
            model_metadata=ModelMetadata(
                model_name="gemma4:12b" if model_available else "none",
                model_version="none",
                prompt_version="4c-v1",
            ),
        )
```

(`model_name="gemma4:12b"` is a trivial literal update matching the config default change from earlier in this phase's work — it does NOT resolve the separately-deferred Minor about reading the model name dynamically from `Settings`/`LLMClient` rather than hardcoding it; that stays out of scope for this plan.)

Third, update `investigate()`'s risk-assessment and report-assembly lines. Change:

```python
        timeline.append(self._step_risk_assessment(model_available))
```

```python
        report = self._assemble_report(alert, timeline, enrichment_results, model_available)
```

to:

```python
        risk_assessment, risk_step = self._step_risk_assessment(
            alert, pattern_type, evidence_count, enrichment_results, model_available
        )
        timeline.append(risk_step)
```

```python
        report = self._assemble_report(alert, timeline, enrichment_results, risk_assessment, model_available)
```

(`pattern_type`/`evidence_count` are already available as local variables in `investigate()` from Task 5's `_step_correlate` call — no further plumbing needed to reach them.)

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS (all tests up through this task)

- [ ] **Step 5: Run the full project test suite**

```bash
pytest -v
```

Expected: PASS — confirms `investigate()`'s full rewiring (all three real steps, real `_assemble_report`) works end-to-end for the three shared tests.

- [ ] **Step 6: Commit**

```bash
git add app/agent/prompts.py app/agent/state_graph.py tests/test_state_graph.py
git commit -m "feat(agent): add real Risk Assessment LLM call and finish investigate() rewiring"
```

---

### Task 9: End-to-end test coverage for the fully-wired pipeline

**Files:**
- Modify: `tests/test_state_graph.py`

**Interfaces:**
- Consumes: the fully-wired `investigate()`/`_assemble_report` from Task 8 — no production code changes in this task, only test coverage.

By Task 8, `investigate()` and `_assemble_report` are already fully rewired for this phase (real `_step_correlate`/`_step_risk_assessment` calls, real `risk_assessment` threading, `"gemma4:12b"`/`"4c-v1"` metadata). This task's job is to give the fully-wired pipeline a dedicated, thorough end-to-end test — replacing the two remaining tests whose *assertions* (not signatures — those were already fixed incrementally in Tasks 4-8) still describe Phase 4b's stub-era behavior.

- [ ] **Step 1: Write/update the tests**

Replace `test_investigate_runs_full_pipeline_and_persists_report`'s body with a fuller version that exercises real Correlate evidence (via `search_results`) and asserts the new model metadata:

```python
def test_investigate_runs_full_pipeline_and_persists_report(tmp_path):
    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    alert_store = SQLiteAlertStore(engine)
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5", source_ip="203.0.113.5")
    alert_store.save_raw_alert(alert)

    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result()))
    siem = _FakeSIEMConnector(
        agent_context=AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active"),
        rule_metadata=RuleMetadata(rule_id="5710", description="x", level=5),
        search_results={"source_ip": SearchResult(alerts=[], total_count=1), "rule_id": SearchResult(alerts=[], total_count=1)},
    )
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            ExtractedIndicators: ExtractedIndicators(candidates=[]),
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
            ),
            RiskAssessment: RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x"),
        },
    )
    analyst = AgenticAnalyst(
        siem=siem, alert_store=alert_store, enrichment_registry=registry, llm_client=llm_client,
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
    assert report.risk_assessment.severity == Severity.HIGH
    assert report.risk_assessment.confidence == Confidence.HIGH
    assert report.model_metadata.model_name == "gemma4:12b"
    assert report.model_metadata.prompt_version == "4c-v1"
    assert len(report.enrichment_findings) == 1
    assert alert_store.get_report(str(report.report_id)).report_id == report.report_id
    assert alert_store.get_alert(str(alert.alert_id)).status == AlertStatus.INVESTIGATED
```

Replace `test_investigate_stub_steps_skip_when_model_unavailable` (its assertions describe Phase 4b's stub-era behavior — all four of Correlate/Risk-Assessment/Draft-Report/Self-Check reported as `"skipped"` — which is no longer accurate: Correlate's canonical searches run and `"complete"` even with the model unavailable, only its classification is skipped):

```python
def test_investigate_degrades_gracefully_when_model_unavailable(tmp_path):
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

    correlate_step = next(s for s in report.investigation_timeline if s.step_name == Step.CORRELATE.value)
    assert correlate_step.action == "completed"  # canonical searches still ran
    assert "classification skipped" in correlate_step.output_summary

    risk_step = next(s for s in report.investigation_timeline if s.step_name == Step.RISK_ASSESSMENT.value)
    assert risk_step.action == "skipped"

    stub_step_names = {Step.DRAFT_REPORT.value, Step.SELF_CHECK.value}
    stub_steps = [s for s in report.investigation_timeline if s.step_name in stub_step_names]
    assert all(s.action == "skipped" for s in stub_steps)
    assert report.enrichment_findings == []
    assert report.model_metadata.model_name == "none"
```

Update `test_investigate_handles_multiple_simultaneous_degradations` — it currently constructs `_FakeLLMClient(model_available=False)` with no responses configured, which still works fine (the `model_available=False` branches never call `generate_structured`), so this test needs no changes to its setup — only re-verify its final assertion still holds:

```python
def test_investigate_handles_multiple_simultaneous_degradations(tmp_path):
    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    alert_store = SQLiteAlertStore(engine)
    alert = _make_alert(full_log="nothing interesting here")
    alert_store.save_raw_alert(alert)

    analyst = AgenticAnalyst(
        siem=_FakeSIEMConnector(context_error=SIEMConnectorError("unreachable", "connection refused")),
        alert_store=alert_store,
        enrichment_registry=EnrichmentRegistry(),
        llm_client=_FakeLLMClient(model_available=False),
    )

    report = analyst.investigate(alert)

    assert len(report.investigation_timeline) == 9
    assert report.risk_assessment is not None
    assert report.model_metadata is not None
    context_step = next(s for s in report.investigation_timeline if s.step_name == Step.GATHER_CONTEXT.value)
    assert context_step.action == "degraded"
    finalize_step = report.investigation_timeline[-1]
    assert finalize_step.action == "completed"
```

(No changes needed to this test's setup — included here only to confirm it still passes unmodified; `_FakeSIEMConnector(context_error=...)` raises on `get_agent_context`/`get_rule_metadata`, not on `search()`, so Correlate's canonical searches still run fine even in this scenario, and `model_available=False` means none of the three real LLM calls are attempted.)

Remove the old body of `test_investigate_stub_steps_skip_when_model_unavailable` entirely — it's replaced above by `test_investigate_degrades_gracefully_when_model_unavailable`.

- [ ] **Step 2: Run the tests**

```bash
pytest tests/test_state_graph.py -v
```

Expected: PASS — these are test-only changes; `investigate()`/`_assemble_report` were already fully wired for this phase's behavior in Task 8, so no production code change is needed here, and no red step is expected.

- [ ] **Step 3: Run the full project test suite**

```bash
pytest -v
```

Expected: PASS — every test in the repo, old and new.

- [ ] **Step 4: Commit**

```bash
git add tests/test_state_graph.py
git commit -m "test: add thorough end-to-end coverage for the fully-wired Phase 4c pipeline"
```

---

### Task 10: Skippable live test for Correlate against the real model

**Files:**
- Create: `tests/test_correlate_live.py`

**Interfaces:**
- Consumes: `AgenticAnalyst`, `OllamaClient`, `Settings` (all existing), real `_FakeSIEMConnector`-shaped test double for the SIEM side (no real Wazuh needed — this test is about validating the LLM calls, not the SIEM integration, which already has its own live tests).

- [ ] **Step 1: Write the test**

```python
# tests/test_correlate_live.py
from uuid import uuid4

import pytest

from app.agent.state_graph import AgenticAnalyst
from app.config import Settings
from app.enrichment.registry import EnrichmentRegistry
from app.integration.models import SearchResult
from app.llm.ollama_client import OllamaClient
from app.schemas import AgentRef, Alert


class _FakeSIEMConnector:
    def health_check(self):
        return True

    def pull_alerts(self, since, until=None, limit=500):
        return []

    def search(self, query):
        return SearchResult(alerts=[], total_count=14)

    def get_agent_context(self, agent_id):
        raise NotImplementedError

    def get_rule_metadata(self, rule_id):
        raise NotImplementedError


class _FakeAlertStore:
    def save_raw_alert(self, alert):
        return str(alert.alert_id)

    def get_alert(self, alert_id):
        raise NotImplementedError

    def list_alerts(self, status=None, since=None, limit=100):
        return []

    def update_alert_status(self, alert_id, status):
        pass

    def save_report(self, report):
        return str(report.report_id)

    def get_report(self, report_id):
        raise NotImplementedError

    def get_report_for_alert(self, alert_id):
        return None

    def list_reports(self, since=None, min_severity=None):
        return []


@pytest.fixture
def live_analyst():
    settings = Settings()
    llm_client = OllamaClient(
        base_url=settings.llm_base_url, model=settings.llm_model, timeout_seconds=settings.llm_timeout_seconds,
    )
    if not llm_client.health_check():
        pytest.skip(f"Ollama not reachable at {settings.llm_base_url} — skipping live Correlate test")
    if not llm_client.model_available():
        pytest.skip(f"model {settings.llm_model!r} is not pulled — skipping live Correlate test")
    return AgenticAnalyst(
        siem=_FakeSIEMConnector(),
        alert_store=_FakeAlertStore(),
        enrichment_registry=EnrichmentRegistry(),
        llm_client=llm_client,
    )


def test_live_correlate_produces_a_valid_pattern_classification(live_analyst):
    alert = Alert(
        alert_id=uuid4(),
        source_alert_id="1699999999.123456",
        source_system="wazuh",
        rule_id="5710",
        rule_description="sshd: Attempt to login using a non-existent user",
        rule_level=5,
        timestamp=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        ingested_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        agent=AgentRef(id="001", name="web-01", ip="10.0.0.5"),
        manager_name="wazuh-manager",
        location="/var/log/auth.log",
        full_log="Invalid user admin from 203.0.113.5",
        source_ip="203.0.113.5",
        raw_json={"rule": {"id": "5710"}},
    )

    pattern_type, evidence_count, step = live_analyst._step_correlate(alert, model_available=True)

    assert step.action == "completed"
    assert evidence_count >= 14  # at least the fake SIEM's canned canonical-search total
```

- [ ] **Step 2: Run the test**

```bash
pytest tests/test_correlate_live.py -v
```

Expected: PASS if Ollama is reachable with the configured model pulled; SKIP with a clear reason otherwise. Either outcome is acceptable — this is a real-model regression check, not a required-every-run test.

- [ ] **Step 3: Run the full project test suite**

```bash
pytest -v
```

Expected: PASS (all tests, including this new skippable one).

- [ ] **Step 4: Commit**

```bash
git add tests/test_correlate_live.py
git commit -m "test: add skippable live Correlate test against the real configured model"
```
