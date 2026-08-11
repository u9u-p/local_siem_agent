from app.agent.state_graph import AgenticAnalyst
from app.config import Settings
from app.enrichment.providers.abuseipdb import AbuseIPDBProvider
from app.enrichment.providers.virustotal import VirusTotalProvider
from app.enrichment.registry import EnrichmentRegistry
from app.integration.siem_connector import SIEMConnector
from app.integration.wazuh_connector import WazuhConnector
from app.llm.client import LLMClient
from app.llm.ollama_client import OllamaClient
from app.storage.alert_store import AlertStore
from app.storage.db import get_engine, init_db
from app.storage.sqlite_alert_store import SQLiteAlertStore


def build_siem_connector(settings: Settings) -> SIEMConnector:
    required = [
        ("WAZUH_INDEXER_URL", settings.wazuh_indexer_url),
        ("WAZUH_INDEXER_USERNAME", settings.wazuh_indexer_username),
        ("WAZUH_INDEXER_PASSWORD", settings.wazuh_indexer_password),
        ("WAZUH_MANAGER_URL", settings.wazuh_manager_url),
        ("WAZUH_MANAGER_USERNAME", settings.wazuh_manager_username),
        ("WAZUH_MANAGER_PASSWORD", settings.wazuh_manager_password),
    ]
    missing = [name for name, value in required if not value]
    if missing:
        raise RuntimeError(f"Missing required Wazuh settings: {', '.join(missing)}")
    return WazuhConnector(
        indexer_url=settings.wazuh_indexer_url,
        indexer_username=settings.wazuh_indexer_username,
        indexer_password=settings.wazuh_indexer_password,
        manager_url=settings.wazuh_manager_url,
        manager_username=settings.wazuh_manager_username,
        manager_password=settings.wazuh_manager_password,
        verify_ssl=settings.wazuh_verify_ssl,
    )


def build_llm_client(settings: Settings) -> LLMClient:
    return OllamaClient(
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        timeout_seconds=settings.llm_timeout_seconds,
    )


def build_alert_store(settings: Settings) -> AlertStore:
    engine = get_engine(settings.database_path)
    init_db(engine)
    return SQLiteAlertStore(engine)


def build_enrichment_registry(settings: Settings) -> EnrichmentRegistry:
    registry = EnrichmentRegistry()
    if settings.abuseipdb_api_key:
        registry.register(AbuseIPDBProvider(api_key=settings.abuseipdb_api_key))
    if settings.virustotal_api_key:
        registry.register(VirusTotalProvider(api_key=settings.virustotal_api_key))
    return registry


class _UnconfiguredSIEMConnector:
    """Placeholder used when Wazuh settings are incomplete.

    Structurally satisfies the SIEMConnector protocol (so an AgenticAnalyst can
    still be constructed, e.g. for report-browsing CLI paths that never touch
    the SIEM) but raises clearly the moment any method is actually invoked,
    rather than failing at construction time the way build_siem_connector does
    for callers that need a real connection up front.
    """

    def health_check(self) -> bool:
        return False

    def pull_alerts(self, since, until=None, limit=500):  # noqa: ANN001
        raise RuntimeError("Wazuh is not configured; cannot pull alerts")

    def search(self, query):  # noqa: ANN001
        raise RuntimeError("Wazuh is not configured; cannot search")

    def get_agent_context(self, agent_id):  # noqa: ANN001
        raise RuntimeError("Wazuh is not configured; cannot get agent context")

    def get_rule_metadata(self, rule_id):  # noqa: ANN001
        raise RuntimeError("Wazuh is not configured; cannot get rule metadata")


def build_analyst(settings: Settings, alert_store: AlertStore | None = None) -> AgenticAnalyst:
    try:
        siem = build_siem_connector(settings)
    except RuntimeError:
        siem = _UnconfiguredSIEMConnector()
    return AgenticAnalyst(
        siem=siem,
        alert_store=alert_store if alert_store is not None else build_alert_store(settings),
        enrichment_registry=build_enrichment_registry(settings),
        llm_client=build_llm_client(settings),
    )
