# Agentic Analyst — Deterministic Pipeline Skeleton (Phase 4b) Design

**Date:** 11 Aug 2026
**Parent design:** `CLAUDE.md` §1.4 (Agentic Analyst — fixed `StateGraph` of `Step`s), §4 (full 9-step FSM and prompting rules), §4.2 (hallucination-mitigation rules), §6 (custom FSM over LangGraph rationale)
**Roadmap:** Phase 4b of the Agentic Analyst subsystem (see `ROADMAP.md`) — the second of four sub-phases. Builds the FSM dispatcher and every step that needs no LLM call; LLM-calling steps are wired in as inert stubs, real prompts/schemas land in Phase 4c/4d.
**Depends on:** Phase 1 (`app/schemas.py`, `AlertStore`), Phase 2/2b (`EnrichmentRegistry`, indicator validators), Phase 3 (`SIEMConnector`), Phase 4a (`LLMClient` Protocol).

---

## Context

CLAUDE.md §4.1 specifies a linear 9-step FSM for alert investigation, with exactly 6 fixed LLM calls plus at most 1 conditional call. This phase builds the skeleton around that FSM — the dispatcher itself, every step that needs no LLM (1, 4, 9), the deterministic half of steps that are partly LLM-driven (2's regex sub-step, 3's enrichment routing), skip-condition logic, and `InvestigationStep` timeline logging. The six real LLM calls (indicator candidate extraction, correlation decision, risk assessment, draft report ×2, self-check) are wired in as inert stubs against a fake `LLMClient` — no prompts, no per-step response schemas yet. That is deliberately Phase 4c/4d's job; this phase's own name is "deterministic pipeline skeleton," and blurring that boundary would undo the reason the Agentic Analyst was split into four sub-phases in the first place.

Three decisions were confirmed in brainstorming, each resolving a concrete tension between CLAUDE.md's original §4.1 design and what Phase 2b actually built:

1. **Verdict-reconciliation branch (§4.1 step 3's conditional call) is dropped, not stubbed.** CLAUDE.md's step 3 describes a reconciliation call triggered when "2+ providers return conflicting verdicts for the same indicator." Phase 2b deliberately settled on one provider per indicator type (`IP → AbuseIPDB`, `DOMAIN/FILE_HASH/URL → VirusTotal`) — two providers can never disagree on the same indicator under this architecture, so the branch can never fire. Building an always-skipped stub for a branch that is structurally dead would misrepresent the design as "not yet implemented" when it is actually "not reachable by this architecture." This is a documented CLAUDE.md/architecture divergence, tracked in `PROGRESS.md`, not silently absorbed.
2. **`LLMClient` gains `model_available() -> bool`.** `health_check()` (Phase 4a) is reachability-only — it returns `True` even when the daemon is reachable but the configured model isn't pulled (confirmed empirically on this dev host in Phase 4a). This phase adds a model-aware check, promoting the pattern already used ad hoc in `tests/test_ollama_client_live.py`'s fixture (reaching into `client._client.models.list()`) to a proper public Protocol method.
3. **LLM-calling steps are thin stubs, not real plumbing.** All six real LLM call sites (2b, 5, 6, 7×2, 8) log a placeholder `InvestigationStep` and return a safe default — no `generate_structured()` call, no per-step response schema defined yet. This phase's value is entirely in the deterministic control flow; Phase 4c owns call-site plumbing, response schemas, and prompts together, as one coherent unit of work.

---

## 1. File Structure

```
app/agent/
  __init__.py
  state_graph.py            # Step enum, AgenticAnalyst dispatcher, investigate() entry point
  indicator_extraction.py   # regex candidate extraction (step 2a) + validation-gate merge
```

`app/llm/client.py` (Protocol) and `app/llm/ollama_client.py` (implementation) each gain one new method: `model_available() -> bool`. No changes to `app/schemas.py` — the stub `Report` reuses existing `RiskAssessment`/`ModelMetadata`/`ReportStatus` shapes with placeholder values (§6 below).

No new dependencies.

---

## 2. `LLMClient.model_available()`

```python
# app/llm/client.py — Protocol addition
class LLMClient(Protocol):
    def generate_structured(self, prompt: str, schema: type[T]) -> T: ...
    def health_check(self) -> bool: ...
    def model_available(self) -> bool: ...
```

```python
# app/llm/ollama_client.py — OllamaClient addition
def model_available(self) -> bool:
    try:
        models = self._client.models.list()
    except openai.OpenAIError:
        return False
    return any(m.id == self._model for m in models.data)
```

Distinct from `health_check()`: `health_check()` answers "is the Ollama daemon reachable at all," `model_available()` answers "is the specific configured model (`self._model`, e.g. `qwen3.5:9b`) actually present." Both can be independently true/false — a reachable daemon without the model pulled is exactly the state discovered on this dev host during Phase 4a. `model_available()` does not attempt generation; it is a preflight check, not a smoke test.

---

## 3. The `Step` Enum and Dispatcher

Per CLAUDE.md §6's explicit rationale for choosing a hand-rolled FSM over a general agent-graph framework ("more auditable... every allowed transition and action-set visible in one place"), this is a plain Python class with one method per step called in a fixed sequence — not a generic transition-table abstraction. `Step` exists purely to name timeline entries consistently; it does not drive runtime dispatch logic (there is no `step: Step -> next_step` lookup — the sequence is just nine ordered method calls).

```python
# app/agent/state_graph.py
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
```

```python
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

    def investigate(self, alert: Alert) -> Report:
        timeline: list[InvestigationStep] = []
        model_available = self._llm_client.model_available()

        timeline.append(self._step_ingest_and_parse(alert, model_available))
        indicators, extract_step = self._step_extract_indicators(alert)
        timeline.append(extract_step)
        enrichment_results, enrich_step = self._step_enrich(indicators)
        timeline.append(enrich_step)
        agent_context, rule_metadata, context_step = self._step_gather_context(alert)
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

(Exact private-method signatures are finalized in the implementation plan; this sketch fixes the call order and the shape of what threads through — indicators, enrichment results, agent/rule context, and the running `model_available` flag.)

**Defensive isolation, per step:** every `_step_*` method catches its own exceptions internally and returns a degraded `InvestigationStep` (action reflecting the failure) rather than raising — no single step's failure aborts `investigate()`. This mirrors the "a provider outage must never abort the investigation" pattern already established in Enrichment (Phase 2) and flagged in `ROADMAP.md` as the standard every Agentic Analyst sub-phase should carry forward.

---

## 4. Step 1 — Ingest & Parse

No LLM. The `Alert` argument is already a validated Pydantic model by the time it reaches `investigate()` — this step's job is to open the timeline and record the `model_available()` preflight result as its `output_summary`, e.g. `"model available: true"` / `"model available: false — LLM-calling steps will log as skipped"`.

```python
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

---

## 5. Step 2 — Extract Indicators (regex sub-step only)

`app/agent/indicator_extraction.py` is a new, focused module: regex patterns cast a deliberately wide net over `Alert.full_log` (and any string values in `Alert.data`), and every candidate string is validated through the **existing** Phase 2/2b Pydantic indicator classes — nothing new is invented for validation, this module only produces candidate strings and hands them to the established gate.

```python
# app/agent/indicator_extraction.py
import re

from app.enrichment.indicators import DomainIndicator, HashIndicator, Indicator, IPIndicator, URLIndicator

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")


def extract_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for pattern in (_URL_RE, _IPV4_RE, _HASH_RE, _DOMAIN_RE):
        candidates.extend(pattern.findall(text))
    return candidates


def extract_and_validate(alert: Alert) -> tuple[list[Indicator], int, int]:
    """Returns (validated indicators, candidate count, validated count)."""
    text_sources = [alert.full_log] + [str(v) for v in alert.data.values() if isinstance(v, str)]
    raw_candidates: list[str] = []
    for text in text_sources:
        raw_candidates.extend(extract_candidates(text))

    seen: set[tuple[type, str]] = set()
    validated: list[Indicator] = []
    for candidate in raw_candidates:
        for indicator_cls in (IPIndicator, HashIndicator, DomainIndicator, URLIndicator):
            try:
                indicator = indicator_cls(value=candidate)
            except ValidationError:
                continue
            key = (type(indicator), indicator.value)
            if key not in seen:
                seen.add(key)
                validated.append(indicator)
            break  # first validator to accept the candidate wins; don't also test the rest
    return validated, len(raw_candidates), len(validated)
```

**Known, accepted simplifications** (explicitly not fixed in this phase — YAGNI, matching this project's stated engineering discipline):
- **Over-extraction over under-extraction.** A domain substring inside an already-matched URL (e.g. `example.com` inside `https://example.com/path`) may be extracted twice, as two different indicator types (`URLIndicator` and `DomainIndicator`) for the same underlying host. This means one redundant enrichment lookup, not a correctness bug — the read-only, best-effort design tolerates redundant lookups far better than missed ones.
- **No `EmailIndicator` exists**, so `EMAIL`-type candidates are never produced by this extractor — consistent with Phase 2b's documented "EMAIL stays unenriched" note. Nothing in this module needs to special-case email.
- **False positives from generic hex/dotted-decimal noise in logs** (e.g. a 32-character session ID that happens to be valid hex, or a version string that happens to parse as an IP) are expected and accepted — they get enriched like any other candidate (typically resolving to `UNKNOWN`/`CLEAN`), consistent with CLAUDE.md §4.1.1's own framing: "a hallucinated or malformed indicator... can add recall but can never inject bad data, because it never bypasses the same validator."

The step method wraps this and logs discard counts per CLAUDE.md §4.1.1's spec (`"N candidates, M validated"`):

```python
def _step_extract_indicators(self, alert: Alert) -> tuple[list[Indicator], InvestigationStep]:
    validated, candidate_count, validated_count = extract_and_validate(alert)
    return validated, InvestigationStep(
        step_name=Step.EXTRACT_INDICATORS.value,
        action="completed",
        tool_used="regex_extraction",
        input=None,
        output_summary=f"{candidate_count} candidates, {validated_count} validated (LLM-assisted extraction: not yet implemented, Phase 4c)",
        timestamp=datetime.now(timezone.utc),
    )
```

---

## 6. Step 3 — Enrich

Loops validated indicators through the existing `EnrichmentRegistry.enrich()` (Phase 2/2b, zero changes needed — confirmed by re-reading `app/enrichment/registry.py` during this design phase). Skipped entirely (logged `action: "skipped"`) if the validated indicator set from step 2 is empty — the one skip-condition CLAUDE.md §4.1 names explicitly and the only one this phase implements (the reconciliation conditional is dropped per Decision 1, not merely unimplemented).

```python
def _step_enrich(self, indicators: list[Indicator]) -> tuple[list[EnrichmentResult], InvestigationStep]:
    if not indicators:
        return [], InvestigationStep(
            step_name=Step.ENRICH.value,
            action="skipped",
            tool_used=None,
            input=None,
            output_summary="skipped: no validated indicators to enrich",
            timestamp=datetime.now(timezone.utc),
        )
    results = [self._enrichment_registry.enrich(indicator) for indicator in indicators]
    return results, InvestigationStep(
        step_name=Step.ENRICH.value,
        action="completed",
        tool_used="enrichment_registry",
        input=None,
        output_summary=f"enriched {len(results)} indicator(s)",
        timestamp=datetime.now(timezone.utc),
    )
```

`EnrichmentRegistry.enrich()` already never raises past its own boundary (confirmed: catches `EnrichmentError` and generic `Exception` alike, always returns a `verdict=UNKNOWN` result on failure) — no additional defensive wrapping needed here beyond what Phase 2 already built.

---

## 7. Step 4 — Gather Host/Rule Context

```python
def _step_gather_context(self, alert: Alert) -> tuple[AgentContext | None, RuleMetadata | None, InvestigationStep]:
    try:
        agent_context = self._siem.get_agent_context(alert.agent.id)
        rule_metadata = self._siem.get_rule_metadata(alert.rule_id)
    except SIEMConnectorError as exc:
        return None, None, InvestigationStep(
            step_name=Step.GATHER_CONTEXT.value,
            action="degraded",
            tool_used="siem_connector",
            input=None,
            output_summary=f"could not gather host/rule context: {exc.kind}",
            timestamp=datetime.now(timezone.utc),
        )
    return agent_context, rule_metadata, InvestigationStep(
        step_name=Step.GATHER_CONTEXT.value,
        action="completed",
        tool_used="siem_connector",
        input=None,
        output_summary=f"gathered context for agent {alert.agent.id}, rule {alert.rule_id}",
        timestamp=datetime.now(timezone.utc),
    )
```

**Explicit non-goal:** host/asset criticality (CLAUDE.md's "config/inventory lookup, never an LLM guess") has no config/inventory concept anywhere in this codebase yet. Inventing one ad hoc here, with no other consumer and no real requirements gathered, would be speculative design — deferred until a concrete need for it surfaces (likely alongside Phase 4c's Risk Assessment step, which is the actual consumer CLAUDE.md names).

---

## 8. Steps 5–8 — Stubs

Each of these four steps produces exactly one `InvestigationStep` and nothing else — no `generate_structured()` call, no response schema, no retry logic (all of that is Phase 4c/4d's job). The stub's logged action differs based on the `model_available` flag threaded in from `investigate()`'s single preflight check, establishing now the exact branching contract Phase 4c's real implementations will need:

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
```

`_step_correlate`, `_step_risk_assessment`, `_step_draft_report`, `_step_self_check` each call `self._stub_step(Step.<NAME>, model_available)`. `_step_draft_report` logs one `InvestigationStep` covering both Draft-A and Draft-B per CLAUDE.md §4.1's step 7 (they are one timeline entry with two LLM calls in the real implementation; in this phase's stub, one entry covers the whole step).

This has no behavioral effect on the *output* yet in either branch (no step calls the LLM in 4b regardless), but it does mean a human reading a 4b-era report can tell, honestly, whether steps 5–8 were skipped because the model wasn't there or are simply not built yet — and Phase 4c inherits a dispatcher that already threads `model_available` to exactly the steps that will need it.

---

## 9. Report Assembly for a Fully-Stubbed Run

`Report.risk_assessment` and `Report.model_metadata` are non-optional fields (Phase 1's schema). A 4b-era run — where no real risk assessment or model call ever happens — populates them with explicit, clearly-labeled placeholders rather than fabricating a plausible-looking real assessment:

```python
def _assemble_report(
    self, alert: Alert, timeline: list[InvestigationStep],
    enrichment_results: list[EnrichmentResult], model_available: bool,
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
        uncertainty_notes="This report was produced by the Phase 4b pipeline skeleton — steps 5-8 (Correlate, Risk Assessment, Draft Report, Self-Check) are stubs, not real analysis.",
        status=ReportStatus.NEEDS_HUMAN_REVIEW,
        model_metadata=ModelMetadata(
            model_name="none" if not model_available else "qwen3.5:9b",
            model_version="none",
            prompt_version="stub-4b",
        ),
    )
```

`status` is always `NEEDS_HUMAN_REVIEW` for a 4b-era report — nothing in it has been genuinely assessed, so `DRAFT`/`COMPLETE` would be misleading regardless of `model_available`.

---

## 10. Step 9 — Finalize & Persist

```python
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
```

(`investigate()` itself calls `alert_store.save_report(report)` after appending this step's entry to `report.investigation_timeline` — see the sketch in §3. The finalize step's own summary is generated before the save call completes, describing what is about to happen; this ordering is finalized in the implementation plan.)

---

## 11. Testing

- **Hand-written fakes** for `SIEMConnector` and `LLMClient`, matching this codebase's established fake-double pattern (e.g. `_FakeProvider` in `tests/test_enrichment_registry.py`) — not a mocking framework.
- **Real `EnrichmentRegistry`** with fake `EnrichmentProvider` doubles registered (same reasoning: the registry's own dispatch logic is exactly what step 3 depends on, so it should be exercised for real).
- **Real `SQLiteAlertStore`** against a temp/in-memory SQLite DB, matching Foundation's own test pattern — not faked, since step 9's persistence behavior is part of what this phase must prove works.
- **Coverage:** step ordering (all nine `InvestigationStep` entries present, in order, for a full run); step 2/3 skip logic (empty vs. non-empty indicator sets); step 4 degraded-not-aborted behavior on a raised `SIEMConnectorError`; both `model_available()` branches propagating correctly into steps 5–8's stub actions; `model_available()` itself (`OllamaClient`, respx-mocked at the `httpx` transport layer, matching Phase 4a's testing pattern) — model present vs. absent vs. daemon unreachable.

---

## Open Items for the Implementation Plan

1. Exact `input`/`tool_used` field population per `InvestigationStep` (e.g. whether `input` should carry structured data like the query used, or stay `None` for steps with no meaningful "input" to record) is a plan-level detail, not fixed here.
2. Whether `investigate()` lives as a bare class method or gets a thin module-level convenience function wrapping it (`investigate(alert, siem=..., ...)`) is left to the implementation plan — CLAUDE.md doesn't specify a calling convention, and Phase 5 (deployment glue) is the actual consumer that will decide what's ergonomic.
3. `model_available()`'s exact Ollama SDK call (`self._client.models.list()`, matching the existing test fixture's reach-in) should be verified against the real `openai` SDK response shape early in the implementation plan, the same "verify before coding" discipline applied to every prior external-API integration this session.
