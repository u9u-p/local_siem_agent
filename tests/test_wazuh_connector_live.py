from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings
from app.integration.wazuh_connector import WazuhConnector


def _load_live_settings() -> Settings | None:
    settings = Settings()
    required = (
        settings.wazuh_indexer_url,
        settings.wazuh_indexer_username,
        settings.wazuh_indexer_password,
        settings.wazuh_manager_url,
        settings.wazuh_manager_username,
        settings.wazuh_manager_password,
    )
    if not all(required):
        return None
    return settings


@pytest.fixture
def live_connector():
    settings = _load_live_settings()
    if settings is None:
        pytest.skip("WAZUH_* settings not configured in .env — skipping real-instance test")
    return WazuhConnector(
        indexer_url=settings.wazuh_indexer_url,
        indexer_username=settings.wazuh_indexer_username,
        indexer_password=settings.wazuh_indexer_password,
        manager_url=settings.wazuh_manager_url,
        manager_username=settings.wazuh_manager_username,
        manager_password=settings.wazuh_manager_password,
        verify_ssl=settings.wazuh_verify_ssl,
    )


def test_live_health_check_succeeds(live_connector):
    assert live_connector.health_check() is True


def test_live_pull_alerts_returns_alert_list(live_connector):
    since = datetime.now(timezone.utc) - timedelta(days=7)

    alerts = live_connector.pull_alerts(since=since, limit=5)

    assert isinstance(alerts, list)
    # This call itself is the empirical check for design spec §6: if the Indexer's
    # alert documents use a different timestamp field name than "timestamp" for the
    # range query, this call will return zero alerts even when alerts exist in that
    # window (rather than raising) — if that happens, inspect one real hit's _source
    # keys directly (GET /wazuh-alerts-*/_search with no filter, size=1) and update
    # WazuhConnector.pull_alerts'/.search()'s range-query field name accordingly.
