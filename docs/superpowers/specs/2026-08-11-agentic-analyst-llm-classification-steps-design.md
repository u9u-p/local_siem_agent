# Agentic Analyst — LLM-Calling Classification Steps (Phase 4c) Design

**Date:** 11 Aug 2026
**Parent design:** `CLAUDE.md` §4.1 (steps 2b, 5, 6), §4.2 (hallucination-mitigation rules), §1.1 (`SearchQuery`)
**Roadmap:** Phase 4c of the Agentic Analyst subsystem — the third of four sub-phases. Fills in the three real LLM-calling steps Phase 4b left as inert stubs: indicator candidate extraction (2b), Correlate (5), Risk Assessment (6).
**Depends on:** Phase 4a (`LLMClient`), Phase 4b (`AgenticAnalyst`, `app/agent/indicator_extraction.py`), Phase 3 (`SIEMConnector`, `SearchQuery`), Phase 2/2b (`EnrichmentRegistry`).

---

## Context

Phase 4b built the deterministic skeleton with all six LLM-calling steps as inert stubs. This phase replaces three of them (step 3's reconciliation call was dropped entirely in 4b, not deferred here) with real `generate_structured()` call sites, real per-step response schemas, and real prompts. Draft Report and Self-Check (steps 7-8) remain stubbed — that's Phase 4d.

Model default is now `gemma4:12b` (GGUF) — chosen over `qwen3.5:9b` after Phase 4b's real-model probes showed matching correctness at roughly 4x the speed (see `PROGRESS.md`). Only GGUF-format Ollama models are usable at all — MLX-format builds silently ignore `response_format` regardless of the underlying weights (also `PROGRESS.md`).

Decisions confirmed in brainstorming:

1. **One plan, not further sub-phased.** Correlate is disproportionately larger than the other two steps (new deterministic search infrastructure plus two LLM calls), but stays inside this single plan as a bigger task cluster rather than becoming its own 4c-1/4c-2/4c-3 split.
2. **MITRE technique selection via LLM is tabled for a future feature.** Risk Assessment's schema is the existing `RiskAssessment` (`severity`, `confidence`, `rationale`) unchanged — no MITRE catalog, no `rule_groups`-keyed lookup. `RuleMetadata.mitre_technique_ids` (fetched by step 4 since Phase 4b, currently discarded) stays discarded for now — threading it through is a separate, small, still-non-LLM design problem (reconciling `list[MitreRef]` vs. bare `list[str]` shapes) left for later.
3. **`SearchQuery` is redesigned to support compound (ANDed) clauses.** The existing single-field/operator/value shape can't express "same `rule_id` AND same host," which Correlate's canonical searches need. Confirmed zero production callers exist yet (only test code constructs `SearchQuery` today, since Correlate was a stub) — this is a contained, well-scoped breaking change to an already-shipped Integration model, not a design compromise.
4. **`evidence_count` is computed by code, not returned by the LLM.** The canonical searches already produce `SearchResult.total_count`; summing them is exact, whereas asking the model to count is unnecessary risk. Only `pattern_type` and the follow-up-query pick come from the model.
5. **The open-value search is a separate, conditionally-triggered LLM call.** It only runs when the main `CorrelationDecision` call classifies `pattern_type` as `NONE` or `OTHER` (the closed templates found nothing) — not a fixed cost on every investigation. It's a distinct call (not bundled into `CorrelationDecision`'s schema) so a free-text generation task never shares a schema with the closed-enum decision. Its results are explicitly flagged as noisier/lower-confidence.
6. **The open-value search has no "fieldless" query mechanism of its own.** It reuses the same `SearchQuery`/`SearchClause` infrastructure from decision 3, fixed to `field="full_log", operator="contains"` — the model only ever proposes the search *value*, never a field name, closing the field-hallucination risk while still giving broader/noisier matching than the closed templates' exact-match searches.

---

## 1. File Structure

```
app/agent/
  schemas.py           # new: IndicatorCandidate, ExtractedIndicators, PatternType,
                        #      SearchTemplate, CorrelationDecision, OpenValueSearchProposal
  prompts.py            # new: one prompt-building function per LLM call site
  correlation_queries.py # new: pure canonical-search-query builders (no I/O, easily unit-testable)
  state_graph.py         # modified: real logic for steps 2b/5/6, replacing 4b's stubs
  indicator_extraction.py # unchanged (2a stays as-is; 2b's results merge with it)
app/integration/
  models.py             # SearchQuery/SearchClause redesign
  wazuh_connector.py     # search() updated for compound clauses
tests/
  test_agent_schemas.py           # new
  test_correlation_queries.py     # new
  test_state_graph.py             # extended (steps 2b/5/6 replace their stub tests)
  test_wazuh_connector.py         # 8 call sites migrated to the new SearchQuery shape
  test_siem_connector_protocol.py # 1 call site migrated
  test_integration_models.py      # migrated + extended for compound clauses
```

No new dependencies.

---

## 2. `SearchQuery` Redesign

```python
# app/integration/models.py
class SearchClause(BaseModel):
    field: str
    operator: Literal["eq", "contains", "range", "terms"]
    value: Any


class SearchQuery(BaseModel):
    clauses: list[SearchClause] = Field(min_length=1)
    time_range: tuple[datetime, datetime] | None = None
```

```python
# app/integration/wazuh_connector.py — search() method body
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
        filter_clauses.append({"range": {"timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}})

    body = {
        "query": {"bool": {"must": must_clauses, "filter": filter_clauses}},
        "size": _SEARCH_DEFAULT_SIZE,
    }
    payload = self._indexer_search(body)
    alerts = _map_hits(payload["hits"]["hits"])
    return SearchResult(alerts=alerts, total_count=payload["hits"]["total"]["value"])
```

All 11 existing test call sites (`tests/test_wazuh_connector.py` ×8, `tests/test_siem_connector_protocol.py` ×1, `tests/test_integration_models.py` ×2) move from `SearchQuery(field=..., operator=..., value=...)` to `SearchQuery(clauses=[SearchClause(field=..., operator=..., value=...)])` — mechanical, single-clause behavior is unchanged.

---

## 3. New Schemas (`app/agent/schemas.py`)

```python
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

`IndicatorCandidate`/`ExtractedIndicators` deliberately mirror `app.enrichment.indicators`' `IndicatorType` enum rather than inventing a parallel one — a candidate whose `type` doesn't map to one of the four validator classes (`IPIndicator`/`HashIndicator`/`DomainIndicator`/`URLIndicator`) is simply discarded at the merge gate, same as any other validation failure.

---

## 4. Extract Indicators (step 2b)

```python
# app/agent/state_graph.py — replaces the deterministic-only step from 4b
def _step_extract_indicators(self, alert: Alert, model_available: bool) -> tuple[list[Indicator], InvestigationStep]:
    validated, candidate_count, validated_count = extract_and_validate(alert)  # 2a, unchanged

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

    llm_validated, llm_candidate_count, llm_validated_count = self._extract_indicators_via_llm(alert)
    merged = _merge_indicators(validated, llm_validated)  # same (type, value) dedup key as 2a's own merge

    step = InvestigationStep(
        step_name=Step.EXTRACT_INDICATORS.value,
        action="completed",
        tool_used="regex_extraction+llm_extraction",
        input=None,
        output_summary=(
            f"regex: {candidate_count} candidates, {validated_count} validated; "
            f"LLM: {llm_candidate_count} candidates, {llm_validated_count} validated"
        ),
        timestamp=datetime.now(timezone.utc),
    )
    return merged, step
```

`_extract_indicators_via_llm` builds the prompt (shows `full_log`/`data` — the one call in the whole pipeline allowed to, per §4.2 rule 2), calls `generate_structured(prompt, ExtractedIndicators)`, and runs every returned candidate through the same four validator classes 2a already uses — anything that fails validation (wrong type, malformed value) is discarded, not corrected. On `LLMClientError` (both attempts failed), it returns `([], 0, 0)` and the step logs `"LLM-assisted extraction failed: <kind>"` instead of counts — 2a's results are always kept regardless.

---

## 5. Correlate (step 5)

### 5.1 Canonical search construction (pure, no I/O)

```python
# app/agent/correlation_queries.py
from datetime import timedelta

from app.agent.schemas import SearchTemplate
from app.integration.models import SearchClause, SearchQuery
from app.schemas import Alert

_CANONICAL_SEARCH_WINDOW = timedelta(hours=24)


def build_canonical_queries(alert: Alert) -> dict[SearchTemplate, SearchQuery | None]:
    window = (alert.timestamp - _CANONICAL_SEARCH_WINDOW, alert.timestamp)
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

`SAME_RULE_ID_HOST` is always buildable (`rule_id`/`agent.id` always exist on `Alert`); `SAME_SRC_IP_24H`/`SAME_DST_HOST` map to `None` when the alert has no `source_ip`/`destination_ip` — the step skips executing that one search rather than sending a query with a `None` value.

### 5.2 Step orchestration

```python
# app/agent/state_graph.py
def _step_correlate(
    self, alert: Alert, model_available: bool
) -> tuple[PatternType, int, InvestigationStep]:
    queries = build_canonical_queries(alert)
    results: dict[SearchTemplate, SearchResult] = {}
    for template, query in queries.items():
        if query is not None:
            results[template] = self._siem.search(query)
    evidence_count = sum(r.total_count for r in results.values())

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

    decision = self._classify_correlation(alert, results, evidence_count)  # CorrelationDecision, or a safe
                                                                             # PatternType.OTHER/NONE_NEEDED
                                                                             # fallback on LLMClientError

    follow_up_note = ""
    if decision.follow_up_query != SearchTemplate.NONE_NEEDED:
        follow_up_query = queries.get(decision.follow_up_query)
        if follow_up_query is not None:
            follow_up_result = self._siem.search(follow_up_query)
            evidence_count += follow_up_result.total_count
            follow_up_note = f"; follow-up {decision.follow_up_query.value} added {follow_up_result.total_count}"

    open_value_note = ""
    if decision.pattern_type in (PatternType.NONE, PatternType.OTHER):
        open_value_note = self._run_open_value_search(alert, results)  # "" if skipped/failed, else a note
                                                                         # including the noisier-evidence flag

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
```

Canonical searches and their `evidence_count` always run, model available or not — they're deterministic and produce real signal for a human reading the report regardless of the LLM's state. Only the classification call, the closed-menu follow-up pick, and the open-value search are gated on `model_available`, matching 4b's established distinction between "deterministic infrastructure" and "LLM decision."

The follow-up query, when picked, reuses the *already-built* `SearchQuery` from `queries` rather than rebuilding it — the model only ever picks a `SearchTemplate` enum member, never touches query construction. Capped at exactly one extra hop, per CLAUDE.md's "never recursive" rule (the open-value search does not itself trigger a further follow-up).

### 5.3 Open-value search

```python
# app/agent/state_graph.py
def _run_open_value_search(self, alert: Alert, canonical_results: dict) -> str:
    proposal = self._propose_open_value_search(alert, canonical_results)  # OpenValueSearchProposal,
                                                                            # or None on LLMClientError
    if proposal is None:
        return ""
    query = SearchQuery(
        clauses=[SearchClause(field="full_log", operator="contains", value=proposal.search_value)],
        time_range=(alert.timestamp - _CANONICAL_SEARCH_WINDOW, alert.timestamp),
    )
    result = self._siem.search(query)
    return f"; open-value search for {proposal.search_value!r} found {result.total_count} (noisier, unstructured match)"
```

The `"noisier, unstructured match"` label is deliberately part of the persisted `output_summary` text itself, not a separate field — so a human reading the timeline (or Phase 4d's Self-Check, which audits claims against structural gaps) can tell this evidence came from a broader match than the closed templates' exact-field searches.

---

## 6. Risk Assessment (step 6)

```python
# app/agent/state_graph.py
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
```

Reuses the existing `RiskAssessment` schema (`app/schemas.py`) unchanged — `severity`, `confidence`, `rationale` only, no MITRE. The prompt shows only structured findings gathered so far: `Alert.rule_level`/`rule_groups`/`rule_description` (already on the alert itself — no separate `RuleMetadata` fetch needed once MITRE is out of scope, since `RuleMetadata`'s only field not already duplicated on `Alert` is `mitre_technique_ids`), enrichment verdicts, and Correlate's `pattern_type`/`evidence_count` — never `full_log` again, per §4.2 rule 2. This is also why step 4's `AgentContext`/`RuleMetadata` stay unused in this phase too (consistent with decision #2 above) — nothing in 4c's scope actually needs them once MITRE is deferred. On `LLMClientError` after both attempts, `_assess_risk` returns `RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="risk assessment failed: <kind>")`.

`_step_finalize_and_persist`'s eventual `Report.status` continues to be forced to a safe value on any degraded path — this phase adds: if Risk Assessment itself degraded (model unavailable or `LLMClientError`), `Report.status` is `NEEDS_HUMAN_REVIEW` rather than whatever a later phase's Draft-Report/Self-Check steps might otherwise compute (still stubs in this phase, so this is largely forward-looking).

### 6.1 Updated `investigate()` orchestration

Three of 4b's step calls change shape (new parameters, richer return values) — `investigate()` itself needs updating to thread the new data through, not just the step methods in isolation:

```python
# app/agent/state_graph.py — investigate(), the parts that change from 4b
def investigate(self, alert: Alert) -> Report:
    model_available = self._llm_client.model_available()
    timeline: list[InvestigationStep] = [self._step_ingest_and_parse(alert, model_available)]

    indicators, extract_step = self._step_extract_indicators(alert, model_available)  # now takes model_available
    timeline.append(extract_step)

    enrichment_results, enrich_step = self._step_enrich(indicators)  # unchanged from 4b
    timeline.append(enrich_step)

    _agent_context, _rule_metadata, context_step = self._step_gather_context(alert)  # unchanged, still discarded
    timeline.append(context_step)

    pattern_type, evidence_count, correlate_step = self._step_correlate(alert, model_available)  # now takes alert,
    timeline.append(correlate_step)                                                               # returns findings

    risk_assessment, risk_step = self._step_risk_assessment(
        alert, pattern_type, evidence_count, enrichment_results, model_available
    )
    timeline.append(risk_step)

    timeline.append(self._step_draft_report(model_available))  # still a 4b stub — Phase 4d
    timeline.append(self._step_self_check(model_available))    # still a 4b stub — Phase 4d

    report = self._assemble_report(alert, timeline, enrichment_results, risk_assessment, model_available)
    finalize_step = self._step_finalize_and_persist(alert, report)
    report.investigation_timeline.append(finalize_step)
    return report
```

`_assemble_report` also changes — it now takes the real `risk_assessment` computed above instead of always constructing the `Severity.LOW`/`Confidence.LOW` stub placeholder from 4b (that placeholder construction moves into `_step_risk_assessment`'s own degraded-path branches, shown in §6, so it still gets used when the model is unavailable or the call fails — just from the step itself rather than unconditionally from `_assemble_report`).

---

## 7. Prompts (`app/agent/prompts.py`)

One function per call site: `build_extract_indicators_prompt(alert)`, `build_correlation_decision_prompt(alert, canonical_results, evidence_count)`, `build_open_value_search_prompt(alert, canonical_results)`, `build_risk_assessment_prompt(pattern_type, evidence_count, enrichment_results, rule_metadata)`. Exact wording is explicitly **not fixed by this spec** — same precedent as Phase 4a's `_RETRY_NOTE`, refined during implementation against the real model rather than guessed here. Each function's *inputs* are fixed (what data it's allowed to see, per §4.2 rule 2's grounding discipline) — that's the part this spec locks in; the wording is an implementation-time, empirically-tuned detail.

Prompt versioning: one overall version string for this phase's whole prompt set, e.g. `"4c-v1"`, recorded in `Report.model_metadata.prompt_version` (replacing 4b's `"stub-4b"` placeholder) — bumped as a whole unit whenever any of this phase's prompts change. Per-step version granularity is not built now; revisit if/when prompts start changing independently often enough to need it.

---

## 8. Testing

- **`app/agent/correlation_queries.py`**: pure unit tests, no mocking — feed various `Alert` fixtures (with/without `source_ip`/`destination_ip`) and assert the right `SearchQuery`/`None` shape comes back.
- **`app/agent/schemas.py`**: straightforward Pydantic validation tests (enum membership, required fields).
- **Step-level tests** (`tests/test_state_graph.py`): extend the existing fake-`LLMClient` pattern — configure it to return canned `ExtractedIndicators`/`CorrelationDecision`/`OpenValueSearchProposal`/`RiskAssessment` objects, and assert the step's degrade-on-`LLMClientError` and degrade-on-`model_available=False` paths for all three steps, plus the open-value search's conditional trigger (only fires when `pattern_type` is `NONE`/`OTHER`).
- **Integration test migration**: all 11 existing `SearchQuery` call sites updated to the new `clauses=[...]` shape (mechanical).
- **Skippable live test**: one new test (mirroring `tests/test_ollama_client_live.py`'s pattern) exercising Correlate's real LLM calls against the real configured model — the novel mechanism in this phase, worth a real-model regression check same as Wazuh/Ollama's existing live tests.

---

## Open Items for the Implementation Plan

1. Exact prompt wording for all four new prompt-building functions is not fixed here — tune empirically against `gemma4:12b` during implementation, same precedent as Phase 4a's retry-note wording.
2. The uniform 24h window for all three canonical searches (only `src_ip` was explicitly specified in CLAUDE.md) is a proposed default, not mandated — revisit if empirical testing shows the other two need a different window.
3. `_extract_indicators_via_llm`/`_classify_correlation`/`_propose_open_value_search`/`_assess_risk`'s exact internal shape (where exactly the `generate_structured()` call and its retry/fallback logic live) is left to the implementation plan's task breakdown, not fixed by this spec beyond the input/output contracts already shown above.
