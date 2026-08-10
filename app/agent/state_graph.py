from datetime import datetime, timezone
from enum import Enum

from app.agent.indicator_extraction import extract_and_validate
from app.enrichment.indicators import Indicator
from app.enrichment.registry import EnrichmentRegistry
from app.integration.siem_connector import SIEMConnector
from app.llm.client import LLMClient
from app.schemas import Alert, EnrichmentResult, InvestigationStep
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
