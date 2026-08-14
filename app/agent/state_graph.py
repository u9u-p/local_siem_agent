import logging
from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import ValidationError

from app.agent.command_decode import decode_command_segments
from app.agent.correlation_queries import CANONICAL_SEARCH_WINDOW, build_canonical_queries
from app.agent.indicator_extraction import extract_and_validate
from app.agent.prompts import (
    build_correlation_decision_prompt,
    build_draft_canonical_prompt,
    build_draft_experimental_prompt,
    build_extract_indicators_prompt,
    build_open_value_search_prompt,
    build_risk_assessment_prompt,
    build_self_check_prompt,
)
from app.agent.schemas import (
    CorrelationDecision,
    DraftReportCanonical,
    DraftReportExperimental,
    ExtractedIndicators,
    OpenValueSearchProposal,
    PatternType,
    RecommendedAction,
    SearchTemplate,
    SelfCheckResult,
)
from app.enrichment.indicators import DomainIndicator, HashIndicator, IPIndicator, Indicator, URLIndicator
from app.enrichment.registry import EnrichmentRegistry
from app.integration.errors import SIEMConnectorError
from app.integration.models import AgentContext, RuleMetadata, SearchClause, SearchQuery, SearchResult
from app.integration.siem_connector import SIEMConnector
from app.llm.client import LLMClient
from app.llm.errors import LLMClientError
from app.schemas import (
    Alert,
    AlertStatus,
    CommandDecodeResult,
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

logger = logging.getLogger(__name__)

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


def _lacks_typed_context(alert: Alert) -> bool:
    """True when nothing but the raw log describes this alert.

    `alert.process` is None for every non-Sysmon alert, so it cannot gate alone — the
    typed-field conjunction is what narrows this to decoders whose fields nobody has
    mapped yet (mail today). Those alerts reach the model through no channel at all,
    because step 2's indicator vocabulary cannot express a sender, a subject, or a
    gateway verdict.
    """
    return alert.process is None and not any(
        (alert.source_ip, alert.destination_ip, alert.src_user, alert.dst_user)
    )


def _context_raw_log(alert: Alert) -> str | None:
    """The raw log line, but only for alerts that have no other way to be described.

    Measured: always-on costs ~23% latency per call (longer generated rationale, not
    prefill) and moved zero verdicts across six golden scenarios — so it is spent only
    where there is genuinely nothing else. Superseded by alert-class context selection.
    """
    return alert.full_log if _lacks_typed_context(alert) else None


def _decode_command(alert: Alert) -> tuple[CommandDecodeResult | None, int, int]:
    if alert.process is None:
        return None, 0, 0
    segments, attempted, discarded = decode_command_segments(alert.process)
    return (
        CommandDecodeResult(
            command_line=alert.process.command_line,
            parent_command_line=alert.process.parent_command_line,
            decoded_segments=segments,
        ),
        attempted,
        discarded,
    )


def _command_extra_texts(alert: Alert, command_decode_result: CommandDecodeResult | None) -> list[str]:
    if alert.process is None:
        return []
    texts = [alert.process.command_line, alert.process.parent_command_line, alert.process.process_hashes]
    if command_decode_result is not None:
        texts.extend(segment.decoded for segment in command_decode_result.decoded_segments)
    return [t for t in texts if t]


def _compute_uncertainty_notes(
    alert: Alert, enrichment_results: list[EnrichmentResult],
    correlate_step: InvestigationStep, flagged_claims: list[str],
) -> str:
    gaps: list[str] = [f"unsupported claim: {claim!r}" for claim in flagged_claims]

    errored_or_unknown = [
        r for r in enrichment_results if r.error is not None or r.verdict == EnrichmentVerdict.UNKNOWN
    ]
    if errored_or_unknown:
        gaps.append(f"{len(errored_or_unknown)} enrichment lookup(s) errored or returned unknown verdicts")

    if "follow-up" not in correlate_step.output_summary and "open-value search" not in correlate_step.output_summary:
        gaps.append("correlation follow-up/open-value search menu was not used")

    if not alert.mitre:
        gaps.append("no MITRE ATT&CK mapping available for this alert")

    return "; ".join(gaps)


def _claims_for(draft: DraftReportCanonical) -> list[str]:
    return [draft.alert_summary, draft.rationale, *[a.value for a in draft.recommended_actions]]


def _apply_self_check_corrections(
    draft: DraftReportCanonical, result: SelfCheckResult
) -> tuple[DraftReportCanonical, list[str]] | None:
    claims = _claims_for(draft)
    if len(result.audits) != len(claims):
        return None

    alert_summary = draft.alert_summary
    rationale = draft.rationale
    flagged_claims: list[str] = []

    summary_audit = result.audits[0]
    if not summary_audit.supported:
        if summary_audit.correction:
            alert_summary = summary_audit.correction
        else:
            flagged_claims.append(claims[0])

    rationale_audit = result.audits[1]
    if not rationale_audit.supported:
        if rationale_audit.correction:
            rationale = rationale_audit.correction
        else:
            flagged_claims.append(claims[1])

    kept_actions = []
    for claim, action, audit in zip(claims[2:], draft.recommended_actions, result.audits[2:]):
        if audit.supported:
            kept_actions.append(action)
        else:
            flagged_claims.append(claim)
    if not kept_actions:
        kept_actions = [RecommendedAction.ESCALATE_TO_HUMAN_ANALYST]

    corrected = DraftReportCanonical(alert_summary=alert_summary, rationale=rationale, recommended_actions=kept_actions)
    return corrected, flagged_claims


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
        self._degraded_reasons: list[str] = []

    def _step_ingest_and_parse(self, alert: Alert, model_available: bool) -> InvestigationStep:
        logger.debug(
            "_step_ingest_and_parse input: alert_id=%s, rule_id=%s, model_available=%s",
            alert.alert_id, alert.rule_id, model_available,
        )
        step = InvestigationStep(
            step_name=Step.INGEST_AND_PARSE.value,
            action="completed",
            tool_used=None,
            input=None,
            output_summary=f"alert {alert.alert_id} ingested; model available: {model_available}",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug("_step_ingest_and_parse output: %s", step.output_summary)
        return step

    def _step_extract_indicators(
        self, alert: Alert, model_available: bool
    ) -> tuple[list[Indicator], CommandDecodeResult | None, InvestigationStep]:
        logger.debug(
            "_step_extract_indicators input: alert_id=%s, model_available=%s", alert.alert_id, model_available
        )
        command_decode_result, decode_attempted, decode_discarded = _decode_command(alert)
        decode_note = ""
        if command_decode_result is not None:
            decode_note = (
                f"; command decode: {len(command_decode_result.decoded_segments)} segment(s) decoded, "
                f"{decode_discarded} discarded"
            )
        extra_texts = _command_extra_texts(alert, command_decode_result)

        validated, candidate_count, validated_count = extract_and_validate(alert, extra_texts=extra_texts)

        if not model_available:
            step = InvestigationStep(
                step_name=Step.EXTRACT_INDICATORS.value,
                action="completed",
                tool_used="regex_extraction",
                input=None,
                output_summary=(
                    f"regex: {candidate_count} candidates, {validated_count} validated{decode_note} "
                    "(LLM-assisted extraction skipped: model unavailable)"
                ),
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug(
                "_step_extract_indicators output: %s indicator(s): %s",
                len(validated), [(type(i).__name__, i.value) for i in validated],
            )
            return validated, command_decode_result, step

        llm_validated, llm_candidate_count, llm_validated_count, llm_error = self._extract_indicators_via_llm(
            alert, extra_texts
        )
        merged = _merge_indicators(validated, llm_validated)

        if llm_error is not None:
            self._degraded_reasons.append(f"indicator extraction LLM failed: {llm_error}")
            summary = (
                f"regex: {candidate_count} candidates, {validated_count} validated{decode_note}; "
                f"LLM-assisted extraction failed: {llm_error}"
            )
        else:
            summary = (
                f"regex: {candidate_count} candidates, {validated_count} validated{decode_note}; "
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
        logger.debug(
            "_step_extract_indicators output: %s indicator(s): %s",
            len(merged), [(type(i).__name__, i.value) for i in merged],
        )
        return merged, command_decode_result, step

    def _extract_indicators_via_llm(
        self, alert: Alert, extra_texts: list[str] | None = None
    ) -> tuple[list[Indicator], int, int, str | None]:
        prompt = build_extract_indicators_prompt(alert, extra_texts)
        logger.debug("_extract_indicators_via_llm prompt: %s", prompt)
        try:
            result = self._llm_client.generate_structured(prompt, ExtractedIndicators)
        except LLMClientError as exc:
            logger.debug("_extract_indicators_via_llm failed: %s", exc.kind)
            return [], 0, 0, exc.kind
        logger.debug("_extract_indicators_via_llm result: %s", result.model_dump_json())

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
        logger.debug(
            "_step_enrich input: %s indicator(s): %s",
            len(indicators), [(type(i).__name__, i.value) for i in indicators],
        )
        if not indicators:
            step = InvestigationStep(
                step_name=Step.ENRICH.value,
                action="skipped",
                tool_used=None,
                input=None,
                output_summary="skipped: no validated indicators to enrich",
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_enrich output: skipped, no indicators")
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
        logger.debug("_step_enrich output: %s", [r.model_dump_json() for r in results])
        return results, step

    def _step_gather_context(
        self, alert: Alert
    ) -> tuple[AgentContext | None, RuleMetadata | None, InvestigationStep]:
        logger.debug("_step_gather_context input: agent_id=%s, rule_id=%s", alert.agent.id, alert.rule_id)
        try:
            agent_context = self._siem.get_agent_context(alert.agent.id)
            rule_metadata = self._siem.get_rule_metadata(alert.rule_id)
        except SIEMConnectorError as exc:
            self._degraded_reasons.append(f"SIEM context unavailable: {exc.kind}")
            step = InvestigationStep(
                step_name=Step.GATHER_CONTEXT.value,
                action="degraded",
                tool_used="siem_connector",
                input=None,
                output_summary=f"could not gather host/rule context: {exc.kind}",
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_gather_context output: failed: %s", exc.kind)
            return None, None, step

        step = InvestigationStep(
            step_name=Step.GATHER_CONTEXT.value,
            action="completed",
            tool_used="siem_connector",
            input=None,
            output_summary=f"gathered context for agent {alert.agent.id}, rule {alert.rule_id}",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug(
            "_step_gather_context output: agent_context=%s, rule_metadata=%s",
            agent_context.model_dump_json() if agent_context is not None else None,
            rule_metadata.model_dump_json() if rule_metadata is not None else None,
        )
        return agent_context, rule_metadata, step

    def _run_canonical_searches(
        self, alert: Alert
    ) -> tuple[dict[SearchTemplate, SearchQuery | None], dict[SearchTemplate, SearchResult], int, int]:
        queries = build_canonical_queries(alert)
        results: dict[SearchTemplate, SearchResult] = {}
        failed_count = 0
        for template, query in queries.items():
            if query is not None:
                try:
                    results[template] = self._siem.search(query)
                except SIEMConnectorError:
                    failed_count += 1
        evidence_count = sum(r.total_count for r in results.values())
        return queries, results, evidence_count, failed_count

    def _step_correlate(
        self, alert: Alert, enrichment_results: list[EnrichmentResult], model_available: bool
    ) -> tuple[PatternType, int, InvestigationStep]:
        logger.debug(
            "_step_correlate input: alert_id=%s, enrichment_count=%s, model_available=%s",
            alert.alert_id, len(enrichment_results), model_available,
        )
        queries, results, evidence_count, failed_count = self._run_canonical_searches(alert)
        failed_note = f"; {failed_count} canonical search(es) failed" if failed_count else ""
        if failed_count:
            self._degraded_reasons.append(f"{failed_count} canonical search(es) failed")

        if not model_available:
            step = InvestigationStep(
                step_name=Step.CORRELATE.value,
                action="completed",
                tool_used="siem_connector",
                input=None,
                output_summary=(
                    f"ran {len(results)} canonical search(es), {evidence_count} total evidence"
                    f"{failed_note} (classification skipped: model unavailable)"
                ),
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug(
                "_step_correlate output: pattern_type=other (skipped), evidence_count=%s%s",
                evidence_count, failed_note,
            )
            return PatternType.OTHER, evidence_count, step

        decision = self._classify_correlation(alert, results, evidence_count, enrichment_results)
        pattern_type = decision.pattern_type

        follow_up_note = ""
        if decision.follow_up_query != SearchTemplate.NONE_NEEDED:
            follow_up_query = queries.get(decision.follow_up_query)
            if follow_up_query is not None:
                try:
                    follow_up_result = self._siem.search(follow_up_query)
                    evidence_count += follow_up_result.total_count
                    follow_up_note = f"; follow-up {decision.follow_up_query.value} added {follow_up_result.total_count}"
                except SIEMConnectorError:
                    follow_up_note = f"; follow-up {decision.follow_up_query.value} failed"
                    self._degraded_reasons.append(f"correlation follow-up {decision.follow_up_query.value} failed")

        open_value_note = ""
        if pattern_type in (PatternType.NONE, PatternType.OTHER):
            open_value_note = self._run_open_value_search(alert, results)

        step = InvestigationStep(
            step_name=Step.CORRELATE.value,
            action="completed",
            tool_used="siem_connector+llm",
            input=None,
            output_summary=(
                f"pattern_type={pattern_type.value}, evidence_count={evidence_count}"
                f"{failed_note}{follow_up_note}{open_value_note}"
            ),
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug(
            "_step_correlate output: pattern_type=%s, evidence_count=%s%s%s%s",
            pattern_type.value, evidence_count, failed_note, follow_up_note, open_value_note,
        )
        return pattern_type, evidence_count, step

    def _classify_correlation(
        self, alert: Alert, canonical_results: dict[SearchTemplate, SearchResult], evidence_count: int,
        enrichment_results: list[EnrichmentResult],
    ) -> CorrelationDecision:
        prompt = build_correlation_decision_prompt(alert, canonical_results, evidence_count, enrichment_results)
        logger.debug("_classify_correlation prompt: %s", prompt)
        try:
            decision = self._llm_client.generate_structured(prompt, CorrelationDecision)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"correlation classification failed: {exc.kind}")
            logger.debug("_classify_correlation failed: %s, falling back to OTHER/NONE_NEEDED", exc.kind)
            return CorrelationDecision(pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED)
        logger.debug("_classify_correlation result: %s", decision.model_dump_json())
        return decision

    def _run_open_value_search(
        self, alert: Alert, canonical_results: dict[SearchTemplate, SearchResult]
    ) -> str:
        prompt = build_open_value_search_prompt(alert, canonical_results)
        logger.debug("_run_open_value_search prompt: %s", prompt)
        try:
            proposal = self._llm_client.generate_structured(prompt, OpenValueSearchProposal)
        except LLMClientError:
            logger.debug("_run_open_value_search: proposal call failed, skipping")
            return ""
        logger.debug("_run_open_value_search result: %s", proposal.model_dump_json())

        query = SearchQuery(
            clauses=[SearchClause(field="full_log", operator="contains", value=proposal.search_value)],
            time_range=(alert.timestamp - CANONICAL_SEARCH_WINDOW, alert.timestamp),
        )
        try:
            result = self._siem.search(query)
        except SIEMConnectorError:
            logger.debug("_run_open_value_search: SIEM search failed for value %r", proposal.search_value)
            return f"; open-value search for {proposal.search_value!r} failed"
        logger.debug(
            "_run_open_value_search: SIEM search for %r found %s result(s)",
            proposal.search_value, result.total_count,
        )
        return (
            f"; open-value search for {proposal.search_value!r} found {result.total_count} "
            "(noisier, unstructured match)"
        )

    def _step_risk_assessment(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], model_available: bool,
        command_context: CommandDecodeResult | None = None,
    ) -> tuple[RiskAssessment, InvestigationStep]:
        logger.debug(
            "_step_risk_assessment input: pattern_type=%s, evidence_count=%s, enrichment_count=%s, model_available=%s",
            pattern_type.value, evidence_count, len(enrichment_results), model_available,
        )
        if not model_available:
            assessment = RiskAssessment(
                severity=Severity.LOW, confidence=Confidence.LOW,
                rationale="risk assessment skipped: model unavailable",
            )
            step = InvestigationStep(
                step_name=Step.RISK_ASSESSMENT.value, action="skipped", tool_used=None, input=None,
                output_summary="skipped: model unavailable", timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_risk_assessment output: skipped: %s", assessment.model_dump_json())
            return assessment, step

        assessment = self._assess_risk(alert, pattern_type, evidence_count, enrichment_results, command_context)
        step = InvestigationStep(
            step_name=Step.RISK_ASSESSMENT.value, action="completed", tool_used="llm", input=None,
            output_summary=f"severity={assessment.severity.value}, confidence={assessment.confidence.value}",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug("_step_risk_assessment output: %s", assessment.model_dump_json())
        return assessment, step

    def _assess_risk(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], command_context: CommandDecodeResult | None = None,
    ) -> RiskAssessment:
        prompt = build_risk_assessment_prompt(
            alert, pattern_type, evidence_count, enrichment_results, command_context, _context_raw_log(alert)
        )
        logger.debug("_assess_risk prompt: %s", prompt)
        try:
            assessment = self._llm_client.generate_structured(prompt, RiskAssessment)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"risk assessment failed: {exc.kind}")
            logger.debug("_assess_risk failed: %s", exc.kind)
            return RiskAssessment(
                severity=Severity.LOW, confidence=Confidence.LOW,
                rationale=f"risk assessment failed: {exc.kind}",
            )
        logger.debug("_assess_risk result: %s", assessment.model_dump_json())
        return assessment

    def _step_draft_report(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment, model_available: bool,
        command_context: CommandDecodeResult | None = None,
    ) -> tuple[DraftReportCanonical, DraftReportExperimental | None, InvestigationStep]:
        logger.debug(
            "_step_draft_report input: pattern_type=%s, evidence_count=%s, severity=%s, model_available=%s",
            pattern_type.value, evidence_count, risk_assessment.severity.value, model_available,
        )
        fallback_summary = (
            f"Rule {alert.rule_id} ({alert.rule_description}), level {alert.rule_level}, "
            f"on agent {alert.agent.name}."
        )
        if not model_available:
            draft = DraftReportCanonical(
                alert_summary=fallback_summary,
                rationale=risk_assessment.rationale,
                recommended_actions=[RecommendedAction.ESCALATE_TO_HUMAN_ANALYST],
            )
            step = InvestigationStep(
                step_name=Step.DRAFT_REPORT.value, action="skipped", tool_used=None, input=None,
                output_summary="skipped: model unavailable", timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_draft_report output: skipped: %s", draft.model_dump_json())
            return draft, None, step

        draft = self._draft_canonical(
            alert, pattern_type, evidence_count, enrichment_results, risk_assessment, fallback_summary,
            command_context,
        )
        experimental = self._draft_experimental(
            alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context
        )
        summary = f"draft-A: {len(draft.recommended_actions)} action(s) selected"
        summary += (
            "; draft-B failed" if experimental is None
            else f"; draft-B: experimental triage={experimental.triage_verdict.value}"
        )
        step = InvestigationStep(
            step_name=Step.DRAFT_REPORT.value, action="completed", tool_used="llm", input=None,
            output_summary=summary, timestamp=datetime.now(timezone.utc),
        )
        logger.debug(
            "_step_draft_report output: draft=%s, experimental=%s",
            draft.model_dump_json(), experimental.model_dump_json() if experimental is not None else None,
        )
        return draft, experimental, step

    def _draft_canonical(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment, fallback_summary: str,
        command_context: CommandDecodeResult | None = None,
    ) -> DraftReportCanonical:
        prompt = build_draft_canonical_prompt(
            alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context, _context_raw_log(alert)
        )
        logger.debug("_draft_canonical prompt: %s", prompt)
        try:
            draft = self._llm_client.generate_structured(prompt, DraftReportCanonical)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"draft report failed: {exc.kind}")
            logger.debug("_draft_canonical failed: %s", exc.kind)
            return DraftReportCanonical(
                alert_summary=fallback_summary,
                rationale=risk_assessment.rationale,
                recommended_actions=[RecommendedAction.ESCALATE_TO_HUMAN_ANALYST],
            )
        logger.debug("_draft_canonical result: %s", draft.model_dump_json())
        return draft

    def _draft_experimental(
        self, alert: Alert, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment,
        command_context: CommandDecodeResult | None = None,
    ) -> DraftReportExperimental | None:
        prompt = build_draft_experimental_prompt(
            alert, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context, _context_raw_log(alert)
        )
        logger.debug("_draft_experimental prompt: %s", prompt)
        try:
            experimental = self._llm_client.generate_structured(prompt, DraftReportExperimental)
        except LLMClientError:
            logger.debug("_draft_experimental failed")
            return None
        logger.debug("_draft_experimental result: %s", experimental.model_dump_json())
        return experimental

    def _step_self_check(
        self, alert: Alert, draft: DraftReportCanonical, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment,
        correlate_step: InvestigationStep, model_available: bool,
        command_context: CommandDecodeResult | None = None,
    ) -> tuple[DraftReportCanonical, str, InvestigationStep]:
        logger.debug("_step_self_check input: draft=%s, model_available=%s", draft.model_dump_json(), model_available)
        if not model_available:
            notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, [])
            notes = "self-check skipped: model unavailable" + (f"; {notes}" if notes else "")
            step = InvestigationStep(
                step_name=Step.SELF_CHECK.value, action="skipped", tool_used=None, input=None,
                output_summary="skipped: model unavailable", timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_self_check output: skipped, draft unchanged, notes=%r", notes)
            return draft, notes, step

        result, failure_kind = self._run_self_check(
            draft, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context, _context_raw_log(alert)
        )
        if result is None:
            notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, [])
            notes = f"self-check could not run: {failure_kind}" + (f"; {notes}" if notes else "")
            step = InvestigationStep(
                step_name=Step.SELF_CHECK.value, action="degraded", tool_used="llm", input=None,
                output_summary="self-check call failed; corrections not applied", timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_self_check output: call failed, draft unchanged, notes=%r", notes)
            return draft, notes, step

        correction_result = _apply_self_check_corrections(draft, result)
        if correction_result is None:
            self._degraded_reasons.append("self-check returned a mismatched audit count")
            notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, [])
            notes = "self-check audit count did not match claim count; corrections not applied" + (f"; {notes}" if notes else "")
            step = InvestigationStep(
                step_name=Step.SELF_CHECK.value, action="degraded", tool_used="llm", input=None,
                output_summary=f"self-check returned {len(result.audits)} audit(s) for {len(_claims_for(draft))} claim(s); corrections not applied",
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug(
                "_step_self_check output: mismatched audit count (%s audits, %s claims), draft unchanged, notes=%r",
                len(result.audits), len(_claims_for(draft)), notes,
            )
            return draft, notes, step

        corrected_draft, flagged_claims = correction_result
        if flagged_claims:
            self._degraded_reasons.append(f"self-check flagged {len(flagged_claims)} unsupported claim(s)")
        notes = _compute_uncertainty_notes(alert, enrichment_results, correlate_step, flagged_claims)
        step = InvestigationStep(
            step_name=Step.SELF_CHECK.value, action="completed", tool_used="llm", input=None,
            output_summary=f"audited {len(result.audits)} claim(s), {len(flagged_claims)} flagged",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug(
            "_step_self_check output: corrected_draft=%s, flagged_claims=%s, notes=%r",
            corrected_draft.model_dump_json(), flagged_claims, notes,
        )
        return corrected_draft, notes, step

    def _run_self_check(
        self, draft: DraftReportCanonical, pattern_type: PatternType, evidence_count: int,
        enrichment_results: list[EnrichmentResult], risk_assessment: RiskAssessment,
        command_context: CommandDecodeResult | None = None, raw_log: str | None = None,
    ) -> tuple[SelfCheckResult | None, str | None]:
        prompt = build_self_check_prompt(
            draft, pattern_type, evidence_count, enrichment_results, risk_assessment, command_context, raw_log
        )
        logger.debug("_run_self_check prompt: %s", prompt)
        try:
            result = self._llm_client.generate_structured(prompt, SelfCheckResult)
        except LLMClientError as exc:
            self._degraded_reasons.append(f"self-check failed: {exc.kind}")
            logger.debug("_run_self_check failed: %s", exc.kind)
            return None, exc.kind
        logger.debug("_run_self_check result: %s", result.model_dump_json())
        return result, None

    def _assemble_report(
        self, alert: Alert, timeline: list[InvestigationStep], enrichment_results: list[EnrichmentResult],
        risk_assessment: RiskAssessment, draft: DraftReportCanonical, experimental: DraftReportExperimental | None,
        uncertainty_notes: str, model_available: bool, command_analysis: CommandDecodeResult | None = None,
    ) -> Report:
        status = ReportStatus.NEEDS_HUMAN_REVIEW if self._degraded_reasons else ReportStatus.COMPLETE
        return Report(
            report_id=uuid4(),
            alert_id=alert.alert_id,
            generated_at=datetime.now(timezone.utc),
            alert_summary=draft.alert_summary,
            investigation_timeline=timeline,
            enrichment_findings=enrichment_results,
            risk_assessment=RiskAssessment(
                severity=risk_assessment.severity, confidence=risk_assessment.confidence, rationale=draft.rationale,
            ),
            recommended_actions=[a.value for a in draft.recommended_actions],
            recommended_actions_freeform_experimental=(
                experimental.recommended_actions_freeform if experimental is not None else None
            ),
            triage_verdict_experimental=experimental.triage_verdict.value if experimental is not None else None,
            triage_rationale_experimental=experimental.triage_rationale if experimental is not None else None,
            uncertainty_notes=uncertainty_notes,
            status=status,
            model_metadata=ModelMetadata(
                # "none" when the model never ran: naming a model that produced nothing
                # would misattribute a stub-shaped report to it.
                model_name=self._llm_client.model_name() if model_available else "none",
                model_version="none",
                prompt_version="4d-v1",
            ),
            command_analysis=command_analysis,
        )

    def _step_finalize_and_persist(self, alert: Alert, report: Report) -> InvestigationStep:
        logger.debug(
            "_step_finalize_and_persist input: report_id=%s, alert_id=%s", report.report_id, alert.alert_id
        )
        try:
            self._alert_store.save_report(report)
            self._alert_store.update_alert_status(str(alert.alert_id), AlertStatus.INVESTIGATED)
        except Exception as exc:
            step = InvestigationStep(
                step_name=Step.FINALIZE_AND_PERSIST.value,
                action="degraded",
                tool_used="alert_store",
                input=None,
                output_summary=f"could not persist report or update alert status: {exc}",
                timestamp=datetime.now(timezone.utc),
            )
            logger.debug("_step_finalize_and_persist output: failed: %s", exc)
            return step
        step = InvestigationStep(
            step_name=Step.FINALIZE_AND_PERSIST.value,
            action="completed",
            tool_used="alert_store",
            input=None,
            output_summary=f"report {report.report_id} persisted, alert marked investigated",
            timestamp=datetime.now(timezone.utc),
        )
        logger.debug("_step_finalize_and_persist output: persisted")
        return step

    def investigate(self, alert: Alert) -> Report:
        self._degraded_reasons = []
        model_available = self._llm_client.model_available()
        if not model_available:
            self._degraded_reasons.append("model unavailable")
        timeline: list[InvestigationStep] = [self._step_ingest_and_parse(alert, model_available)]

        indicators, command_decode_result, extract_step = self._step_extract_indicators(alert, model_available)
        timeline.append(extract_step)

        enrichment_results, enrich_step = self._step_enrich(indicators)
        timeline.append(enrich_step)

        _agent_context, _rule_metadata, context_step = self._step_gather_context(alert)
        timeline.append(context_step)

        pattern_type, evidence_count, correlate_step = self._step_correlate(
            alert, enrichment_results, model_available
        )
        timeline.append(correlate_step)

        risk_assessment, risk_step = self._step_risk_assessment(
            alert, pattern_type, evidence_count, enrichment_results, model_available,
            command_context=command_decode_result,
        )
        timeline.append(risk_step)

        draft, experimental, draft_step = self._step_draft_report(
            alert, pattern_type, evidence_count, enrichment_results, risk_assessment, model_available,
            command_context=command_decode_result,
        )
        timeline.append(draft_step)

        draft, uncertainty_notes, self_check_step = self._step_self_check(
            alert, draft, pattern_type, evidence_count, enrichment_results, risk_assessment,
            correlate_step, model_available, command_context=command_decode_result,
        )
        timeline.append(self_check_step)

        report = self._assemble_report(
            alert, timeline, enrichment_results, risk_assessment, draft, experimental, uncertainty_notes,
            model_available, command_analysis=command_decode_result,
        )
        finalize_step = self._step_finalize_and_persist(alert, report)
        report.investigation_timeline.append(finalize_step)
        return report
