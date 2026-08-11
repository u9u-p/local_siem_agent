from app.config import Settings
from app.enrichment.providers.abuseipdb import AbuseIPDBProvider
from app.enrichment.providers.virustotal import VirusTotalProvider
from app.integration.siem_connector import SIEMConnector
from app.integration.wazuh_connector import WazuhConnector
from app.llm.client import LLMClient
from app.llm.ollama_client import OllamaClient
from app.schemas import IndicatorType
from app.storage.sqlite_alert_store import SQLiteAlertStore
from app.wiring import (
    build_alert_store,
    build_analyst,
    build_enrichment_registry,
    build_llm_client,
    build_siem_connector,
)


def _wazuh_settings(**overrides) -> Settings:
    defaults = dict(
        wazuh_indexer_url="https://localhost:9200",
        wazuh_indexer_username="admin",
        wazuh_indexer_password="pw",
        wazuh_manager_url="https://localhost:55000",
        wazuh_manager_username="wazuh-wui",
        wazuh_manager_password="pw2",
        _env_file=None,
    )
    defaults.update(overrides)
    return Settings(**defaults)


def test_build_siem_connector_returns_a_wazuh_connector():
    connector = build_siem_connector(_wazuh_settings())
    assert isinstance(connector, WazuhConnector)
    assert isinstance(connector, SIEMConnector)


def test_build_siem_connector_raises_on_missing_settings():
    settings = Settings(_env_file=None)  # no wazuh_* fields set
    try:
        build_siem_connector(settings)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "WAZUH_INDEXER_URL" in str(exc)


def test_build_llm_client_returns_an_ollama_client():
    client = build_llm_client(Settings(_env_file=None))
    assert isinstance(client, OllamaClient)
    assert isinstance(client, LLMClient)


def test_build_alert_store_returns_a_sqlite_alert_store(tmp_path):
    settings = Settings(database_path=str(tmp_path / "test.db"), _env_file=None)
    store = build_alert_store(settings)
    assert isinstance(store, SQLiteAlertStore)


def test_build_enrichment_registry_registers_nothing_when_no_keys_set():
    registry = build_enrichment_registry(Settings(_env_file=None))
    assert registry.providers_for(IndicatorType.IP) == []
    assert registry.providers_for(IndicatorType.DOMAIN) == []


def test_build_enrichment_registry_registers_abuseipdb_when_key_set():
    registry = build_enrichment_registry(Settings(abuseipdb_api_key="key123", _env_file=None))
    providers = registry.providers_for(IndicatorType.IP)
    assert len(providers) == 1
    assert isinstance(providers[0], AbuseIPDBProvider)


def test_build_enrichment_registry_registers_virustotal_when_key_set():
    registry = build_enrichment_registry(Settings(virustotal_api_key="key456", _env_file=None))
    providers = registry.providers_for(IndicatorType.DOMAIN)
    assert len(providers) == 1
    assert isinstance(providers[0], VirusTotalProvider)


def test_build_analyst_reuses_a_passed_in_alert_store(tmp_path):
    settings = _wazuh_settings(database_path=str(tmp_path / "test.db"))
    alert_store = build_alert_store(settings)
    from app.agent.state_graph import AgenticAnalyst

    analyst = build_analyst(settings, alert_store=alert_store)
    assert isinstance(analyst, AgenticAnalyst)
    assert analyst._alert_store is alert_store


def test_build_analyst_builds_its_own_alert_store_when_none_given(tmp_path):
    settings = _wazuh_settings(database_path=str(tmp_path / "test.db"))
    from app.agent.state_graph import AgenticAnalyst

    analyst = build_analyst(settings)
    assert isinstance(analyst, AgenticAnalyst)
