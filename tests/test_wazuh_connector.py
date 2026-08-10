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
