from datetime import datetime, timedelta, timezone
from uuid import uuid4

from app.agent.correlation_queries import build_canonical_queries, distinct_value_counts
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
    assert query.clauses[0].field == "data.srcip"
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
    assert {(c.field, c.value) for c in query.clauses} == {("rule.id", "5710"), ("agent.id", "001")}


def test_builds_same_dst_host_query_when_destination_ip_present():
    alert = _make_alert(destination_ip="198.51.100.9")

    queries = build_canonical_queries(alert)

    query = queries[SearchTemplate.SAME_DST_HOST]
    assert query is not None
    assert query.clauses[0].field == "data.dstip"
    assert query.clauses[0].value == "198.51.100.9"


def test_same_dst_host_query_is_none_when_destination_ip_absent():
    alert = _make_alert(destination_ip=None)

    queries = build_canonical_queries(alert)

    assert queries[SearchTemplate.SAME_DST_HOST] is None


from app.schemas import ProcessExecutionFields


def test_builds_same_command_line_query_when_process_command_line_present():
    alert = _make_alert(process=ProcessExecutionFields(command_line="powershell.exe -enc AAA"))

    queries = build_canonical_queries(alert)

    query = queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE]
    assert query is not None
    assert query.clauses[0].field == "data.win.eventdata.commandLine"
    assert query.clauses[0].operator == "eq"
    assert query.clauses[0].value == "powershell.exe -enc AAA"


def test_same_command_line_query_is_none_when_process_absent():
    alert = _make_alert()

    queries = build_canonical_queries(alert)

    assert queries[SearchTemplate.SAME_COMMAND_LINE_ENV_WIDE] is None


def test_distinct_value_counts_separates_scanning_from_brute_force():
    # One source IP touching many destination ports is scanning; the bare total_count
    # both cases share (5) cannot express that, but the cardinality can.
    scanning = [
        _make_alert(source_ip="203.0.113.5", destination_ip="10.0.0.5", destination_port=port)
        for port in (22, 80, 443, 3389, 8080)
    ]

    counts = distinct_value_counts(scanning)

    assert counts["source ips"] == 1
    assert counts["destination ports"] == 5


def test_distinct_value_counts_ignores_missing_values():
    alerts = [
        _make_alert(dst_user="root"),
        _make_alert(dst_user="root"),
        _make_alert(dst_user=None),
    ]

    counts = distinct_value_counts(alerts)

    assert counts["target users"] == 1


def test_distinct_value_counts_returns_zeros_for_empty_alert_list():
    counts = distinct_value_counts([])

    assert set(counts.values()) == {0}


def test_distinct_value_counts_treats_blank_values_as_absent():
    # _lacks_typed_context uses truthiness on these same fields; the two helpers must agree.
    alerts = [_make_alert(source_ip=""), _make_alert(source_ip="203.0.113.5")]

    assert distinct_value_counts(alerts)["source ips"] == 1
