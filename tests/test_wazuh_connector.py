from datetime import datetime, timezone

import httpx
import respx

from app.integration.wazuh_connector import WazuhConnector

INDEXER_URL = "https://wazuh-indexer.test:9200"
MANAGER_URL = "https://wazuh-manager.test:55000"


def _make_connector(**overrides):
    defaults = dict(
        indexer_url=INDEXER_URL,
        indexer_username="admin",
        indexer_password="indexer-pw",
        manager_url=MANAGER_URL,
        manager_username="wazuh-wui",
        manager_password="manager-pw",
        verify_ssl=False,
    )
    defaults.update(overrides)
    return WazuhConnector(**defaults)


@respx.mock
def test_health_check_returns_true_when_both_backends_reachable():
    respx.get(f"{INDEXER_URL}/_cluster/health").mock(return_value=httpx.Response(200, json={"status": "green"}))
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    respx.get(f"{MANAGER_URL}/agents").mock(
        return_value=httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})
    )
    connector = _make_connector()

    assert connector.health_check() is True


@respx.mock
def test_health_check_returns_false_when_indexer_unreachable():
    respx.get(f"{INDEXER_URL}/_cluster/health").mock(return_value=httpx.Response(503))
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    respx.get(f"{MANAGER_URL}/agents").mock(
        return_value=httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})
    )
    connector = _make_connector()

    assert connector.health_check() is False


@respx.mock
def test_pull_alerts_maps_indexer_hits_to_alerts():
    respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_source": {
                                "agent": {"ip": "10.0.0.5", "name": "web-01", "id": "001"},
                                "manager": {"name": "wazuh-manager"},
                                "data": {"srcip": "203.0.113.5"},
                                "rule": {"level": 5, "description": "sshd auth failure", "groups": [], "id": "5710"},
                                "location": "/var/log/auth.log",
                                "full_log": "Invalid user admin from 203.0.113.5",
                                "id": "1699999999.123456",
                                "timestamp": "2026-08-10T09:00:00.000+0000",
                            }
                        }
                    ],
                }
            },
        )
    )
    connector = _make_connector()

    alerts = connector.pull_alerts(since=datetime(2026, 8, 10, tzinfo=timezone.utc))

    assert len(alerts) == 1
    assert alerts[0].rule_id == "5710"
    assert alerts[0].source_ip == "203.0.113.5"


from app.integration.models import SearchQuery


@respx.mock
def test_search_translates_eq_operator_to_term_query():
    route = respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
    )
    connector = _make_connector()

    result = connector.search(SearchQuery(field="rule.level", operator="eq", value=5))

    assert result.total_count == 0
    sent_body = route.calls.last.request.content
    import json

    parsed = json.loads(sent_body)
    assert parsed["query"]["bool"]["must"] == [{"term": {"rule.level": 5}}]


@respx.mock
def test_search_translates_contains_operator_to_match_query():
    route = respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
    )
    connector = _make_connector()

    connector.search(SearchQuery(field="full_log", operator="contains", value="Invalid user"))

    import json

    parsed = json.loads(route.calls.last.request.content)
    assert parsed["query"]["bool"]["must"] == [{"match": {"full_log": "Invalid user"}}]


@respx.mock
def test_search_translates_range_operator_and_time_range_filter():
    route = respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_source": {
                                "agent": {"ip": "10.0.0.5", "name": "web-01", "id": "001"},
                                "manager": {"name": "wazuh-manager"},
                                "data": {},
                                "rule": {"level": 5, "description": "x", "groups": [], "id": "5710"},
                                "location": "/var/log/auth.log",
                                "full_log": "x",
                                "id": "1699999999.123456",
                                "timestamp": "2026-08-10T09:00:00.000+0000",
                            }
                        }
                    ],
                }
            },
        )
    )
    connector = _make_connector()
    since = datetime(2026, 8, 10, tzinfo=timezone.utc)
    until = datetime(2026, 8, 11, tzinfo=timezone.utc)

    result = connector.search(
        SearchQuery(field="rule.level", operator="range", value={"gte": 3}, time_range=(since, until))
    )

    assert result.total_count == 1
    import json

    parsed = json.loads(route.calls.last.request.content)
    assert {"range": {"rule.level": {"gte": 3}}} in parsed["query"]["bool"]["must"]
    assert any("timestamp" in clause.get("range", {}) for clause in parsed["query"]["bool"]["filter"])


@respx.mock
def test_search_translates_terms_operator_to_terms_query():
    route = respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
    )
    connector = _make_connector()

    connector.search(SearchQuery(field="rule.groups", operator="terms", value=["authentication_failed", "syslog"]))

    import json

    parsed = json.loads(route.calls.last.request.content)
    assert parsed["query"]["bool"]["must"] == [
        {"terms": {"rule.groups": ["authentication_failed", "syslog"]}}
    ]


@respx.mock
def test_get_agent_context_maps_manager_response():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    respx.get(f"{MANAGER_URL}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [
                        {
                            "id": "001",
                            "name": "web-01",
                            "ip": "10.0.0.5",
                            "status": "active",
                            "os": {"platform": "ubuntu", "version": "22.04"},
                            "version": "Wazuh v4.14.1",
                            "lastKeepAlive": "2026-08-10T09:00:00Z",
                        }
                    ]
                },
                "error": 0,
            },
        )
    )
    connector = _make_connector()

    context = connector.get_agent_context("001")

    assert context.id == "001"
    assert context.os_platform == "ubuntu"
    assert context.os_version == "22.04"
    assert context.agent_version == "Wazuh v4.14.1"
    assert context.status == "active"


@respx.mock
def test_get_rule_metadata_maps_manager_response_with_flat_mitre_list():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    respx.get(f"{MANAGER_URL}/rules").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [
                        {
                            "id": 5710,
                            "description": "sshd: Attempt to login using a non-existent user",
                            "level": 5,
                            "groups": ["authentication_failed", "syslog"],
                            "mitre": ["T1110"],
                        }
                    ]
                },
                "error": 0,
            },
        )
    )
    connector = _make_connector()

    metadata = connector.get_rule_metadata("5710")

    assert metadata.rule_id == "5710"
    assert metadata.level == 5
    assert metadata.groups == ["authentication_failed", "syslog"]
    assert metadata.mitre_technique_ids == ["T1110"]


@respx.mock
def test_get_agent_context_retries_once_after_401():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        side_effect=[
            httpx.Response(200, json={"data": {"token": "expired-token"}, "error": 0}),
            httpx.Response(200, json={"data": {"token": "fresh-token"}, "error": 0}),
        ]
    )
    respx.get(f"{MANAGER_URL}/agents").mock(
        side_effect=[
            httpx.Response(401, json={"title": "Unauthorized", "detail": "No authorization token provided"}),
            httpx.Response(
                200,
                json={
                    "data": {
                        "affected_items": [
                            {"id": "001", "name": "web-01", "ip": "10.0.0.5", "status": "active"}
                        ]
                    },
                    "error": 0,
                },
            ),
        ]
    )
    connector = _make_connector()

    context = connector.get_agent_context("001")

    assert context.id == "001"
