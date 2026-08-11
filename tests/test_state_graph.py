from datetime import datetime, timezone
from uuid import uuid4

from app.agent.schemas import (
    CorrelationDecision,
    ExtractedIndicators,
    IndicatorCandidate,
    OpenValueSearchProposal,
    PatternType,
    SearchTemplate,
)
from app.agent.state_graph import AgenticAnalyst, Step
from app.enrichment.registry import EnrichmentRegistry
from app.integration.errors import SIEMConnectorError
from app.integration.models import AgentContext, RuleMetadata, SearchResult
from app.llm.errors import LLMClientError
from app.schemas import AgentRef, Alert, EnrichmentResult
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


def test_step_enrich_calls_registry_for_each_indicator():
    registry = EnrichmentRegistry()
    registry.register(_FakeIPProvider(result=_make_enrichment_result()))
    analyst = _make_analyst(enrichment_registry=registry)
    indicators, _ = analyst._step_extract_indicators(
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
            },
        ),
    )

    report = analyst.investigate(alert)

    context_step = next(s for s in report.investigation_timeline if s.step_name == Step.GATHER_CONTEXT.value)
    assert context_step.action == "degraded"
    assert report.status == ReportStatus.NEEDS_HUMAN_REVIEW


def test_step_enrich_degrades_when_no_provider_registered_for_type():
    analyst = _make_analyst(enrichment_registry=EnrichmentRegistry())
    indicators, _ = analyst._step_extract_indicators(
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
