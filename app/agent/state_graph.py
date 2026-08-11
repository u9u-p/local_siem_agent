from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import ValidationError

from app.agent.correlation_queries import build_canonical_queries
from app.agent.indicator_extraction import extract_and_validate
from app.agent.prompts import build_correlation_decision_prompt, build_extract_indicators_prompt
from app.agent.schemas import CorrelationDecision, ExtractedIndicators, PatternType, SearchTemplate
from app.enrichment.indicators import DomainIndicator, HashIndicator, IPIndicator, Indicator, URLIndicator
from app.enrichment.registry import EnrichmentRegistry
from app.integration.errors import SIEMConnectorError
from app.integration.models import AgentContext, RuleMetadata, SearchResult
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

        results: list[EnrichmentResult] = []
        for indicator in indicators:
            try:
                results.append(self._enrichment_registry.enrich(indicator))
            except ValueError:
                queried_at = datetime.now(timezone.utc)
                results.append(
                    EnrichmentResult(
                        indicator_type=indicator.indicator_type,
                        indicator_value=indicator.value,
                        provider_id="none",
                        queried_at=queried_at,
                        verdict=EnrichmentVerdict.UNKNOWN,
                        score=0.0,
                        cache_expires_at=queried_at,
                        error="no_provider_registered",
                    )
                )
        step = InvestigationStep(
            step_name=Step.ENRICH.value,
            action="completed",
            tool_used="enrichment_registry",
            input=None,
            output_summary=f"enriched {len(results)} indicator(s)",
            timestamp=datetime.now(timezone.utc),
        )
        return results, step

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

    def _step_risk_assessment(self, model_available: bool) -> InvestigationStep:
        return self._stub_step(Step.RISK_ASSESSMENT, model_available)

    def _step_draft_report(self, model_available: bool) -> InvestigationStep:
        return self._stub_step(Step.DRAFT_REPORT, model_available)

    def _step_self_check(self, model_available: bool) -> InvestigationStep:
        return self._stub_step(Step.SELF_CHECK, model_available)

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
        try:
            self._alert_store.save_report(report)
            self._alert_store.update_alert_status(str(alert.alert_id), AlertStatus.INVESTIGATED)
        except Exception as exc:
            return InvestigationStep(
                step_name=Step.FINALIZE_AND_PERSIST.value,
                action="degraded",
                tool_used="alert_store",
                input=None,
                output_summary=f"could not persist report or update alert status: {exc}",
                timestamp=datetime.now(timezone.utc),
            )
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

        indicators, extract_step = self._step_extract_indicators(alert, model_available)
        timeline.append(extract_step)

        enrichment_results, enrich_step = self._step_enrich(indicators)
        timeline.append(enrich_step)

        _agent_context, _rule_metadata, context_step = self._step_gather_context(alert)
        timeline.append(context_step)

        pattern_type, evidence_count, correlate_step = self._step_correlate(alert, model_available)
        timeline.append(correlate_step)
        timeline.append(self._step_risk_assessment(model_available))
        timeline.append(self._step_draft_report(model_available))
        timeline.append(self._step_self_check(model_available))

        report = self._assemble_report(alert, timeline, enrichment_results, model_available)
        finalize_step = self._step_finalize_and_persist(alert, report)
        report.investigation_timeline.append(finalize_step)
        return report
