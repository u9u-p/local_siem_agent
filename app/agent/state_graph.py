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
    EnrichmentVerdict,
    InvestigationStep,
    ModelMetadata,
    Report,
    ReportStatus,
    RiskAssessment,
    Severity,
)
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
        return report
