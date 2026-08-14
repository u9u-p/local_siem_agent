from uuid import uuid4

import pytest

from app.agent.schemas import PatternType
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

    pattern_type, evidence_count, step = live_analyst._step_correlate(alert, [], model_available=True)

    assert pattern_type == PatternType.BRUTE_FORCE
    assert step.action == "completed"
    assert evidence_count >= 14  # at least the fake SIEM's canned canonical-search total
