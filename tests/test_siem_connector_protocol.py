from datetime import datetime, timezone
from uuid import uuid4

from app.integration.models import AgentContext, RuleMetadata, SearchClause, SearchQuery, SearchResult
from app.integration.siem_connector import SIEMConnector
from app.schemas import AgentRef, Alert


class _FakeConnector:
    def health_check(self) -> bool:
        return True

    def pull_alerts(self, since, until=None, limit=500):
        return []

    def search(self, query: SearchQuery) -> SearchResult:
        return SearchResult(alerts=[], total_count=0)

    def get_agent_context(self, agent_id: str) -> AgentContext:
        return AgentContext(id=agent_id, name="web-01", ip="10.0.0.5", status="active")

    def get_rule_metadata(self, rule_id: str) -> RuleMetadata:
        return RuleMetadata(rule_id=rule_id, description="x", level=5)


def test_fake_connector_satisfies_siem_connector_protocol():
    connector: SIEMConnector = _FakeConnector()
    assert connector.health_check() is True
    assert connector.pull_alerts(since=datetime.now(timezone.utc)) == []
    assert connector.search(SearchQuery(clauses=[SearchClause(field="rule.level", operator="eq", value=5)])).total_count == 0
    assert connector.get_agent_context("001").id == "001"
    assert connector.get_rule_metadata("5710").rule_id == "5710"
