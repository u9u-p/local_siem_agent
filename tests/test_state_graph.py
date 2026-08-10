from datetime import datetime, timezone
from uuid import uuid4

from app.agent.state_graph import AgenticAnalyst, Step
from app.enrichment.registry import EnrichmentRegistry
from app.integration.models import AgentContext, RuleMetadata
from app.schemas import AgentRef, Alert, EnrichmentResult
from app.schemas import EnrichmentVerdict, IndicatorType


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
