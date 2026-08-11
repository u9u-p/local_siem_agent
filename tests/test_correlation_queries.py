from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.agent.correlation_queries import build_canonical_queries
from app.agent.schemas import SearchTemplate
from app.schemas import AgentRef, Alert


def _make_alert(**overrides):
    defaults = dict(
        alert_id=uuid4(),
        source_alert_id="1699999999.123456",
        source_system="wazuh",
        rule_id="5710",
        rule_description="sshd: Attempt to login using a non-existent user",
        rule_level=5,
        timestamp=datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id="001", name="web-01", ip="10.0.0.5"),
        manager_name="wazuh-manager",
        location="/var/log/auth.log",
        full_log="Invalid user admin from 203.0.113.5",
        raw_json={"rule": {"id": "5710"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_builds_same_src_ip_query_when_source_ip_present():
    alert = _make_alert(source_ip="203.0.113.5")

    queries = build_canonical_queries(alert)

    query = queries[SearchTemplate.SAME_SRC_IP_24H]
    assert query is not None
    assert query.clauses[0].field == "source_ip"
    assert query.clauses[0].operator == "eq"
    assert query.clauses[0].value == "203.0.113.5"
    assert query.time_range == (alert.timestamp - timedelta(hours=24), alert.timestamp)


def test_same_src_ip_query_is_none_when_source_ip_absent():
    alert = _make_alert(source_ip=None)

    queries = build_canonical_queries(alert)

    assert queries[SearchTemplate.SAME_SRC_IP_24H] is None


def test_builds_same_rule_id_host_query_with_compound_clauses():
    alert = _make_alert()

    queries = build_canonical_queries(alert)

    query = queries[SearchTemplate.SAME_RULE_ID_HOST]
    assert query is not None
    assert len(query.clauses) == 2
    assert {(c.field, c.value) for c in query.clauses} == {("rule_id", "5710"), ("agent.id", "001")}


def test_builds_same_dst_host_query_when_destination_ip_present():
    alert = _make_alert(destination_ip="198.51.100.9")

    queries = build_canonical_queries(alert)

    query = queries[SearchTemplate.SAME_DST_HOST]
    assert query is not None
    assert query.clauses[0].field == "destination_ip"
    assert query.clauses[0].value == "198.51.100.9"


def test_same_dst_host_query_is_none_when_destination_ip_absent():
    alert = _make_alert(destination_ip=None)

    queries = build_canonical_queries(alert)

    assert queries[SearchTemplate.SAME_DST_HOST] is None
