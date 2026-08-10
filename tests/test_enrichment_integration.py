import httpx
import respx

from app.enrichment.indicators import DomainIndicator, IPIndicator, HashIndicator
from app.enrichment.providers.abuseipdb import AbuseIPDBProvider
from app.enrichment.providers.virustotal import VirusTotalProvider
from app.enrichment.registry import EnrichmentRegistry
from app.schemas import EnrichmentVerdict

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
FILE_URL = f"https://www.virustotal.com/api/v3/files/{'b' * 64}"
DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/example.com"


@respx.mock
def test_registry_and_provider_compose_end_to_end():
    respx.get(CHECK_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "ipAddress": "203.0.113.5"}})
    )
    registry = EnrichmentRegistry()
    registry.register(AbuseIPDBProvider(api_key="test-key"))

    result = registry.enrich(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.MALICIOUS
    assert result.provider_id == "abuseipdb"


@respx.mock
def test_registry_degrades_gracefully_on_provider_auth_failure():
    respx.get(CHECK_URL).mock(return_value=httpx.Response(401, json={"errors": [{"detail": "invalid key"}]}))
    registry = EnrichmentRegistry()
    registry.register(AbuseIPDBProvider(api_key="bad-key"))

    result = registry.enrich(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.UNKNOWN
    assert result.error == "auth_failed"


@respx.mock
def test_registry_routes_ip_and_hash_indicators_to_their_own_providers():
    respx.get(CHECK_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "ipAddress": "203.0.113.5"}})
    )
    respx.get(FILE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "id": "b" * 64,
                    "type": "file",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 6,
                            "suspicious": 0,
                            "harmless": 10,
                            "undetected": 5,
                            "timeout": 0,
                        }
                    },
                }
            },
        )
    )
    registry = EnrichmentRegistry()
    registry.register(AbuseIPDBProvider(api_key="test-key"))
    registry.register(VirusTotalProvider(api_key="test-vt-key"))

    ip_result = registry.enrich(IPIndicator(value="203.0.113.5"))
    hash_result = registry.enrich(HashIndicator(value="b" * 64))

    assert ip_result.provider_id == "abuseipdb"
    assert ip_result.verdict == EnrichmentVerdict.MALICIOUS
    assert hash_result.provider_id == "virustotal"
    assert hash_result.verdict == EnrichmentVerdict.MALICIOUS


@respx.mock
def test_registry_routes_domain_indicator_to_virustotal():
    respx.get(DOMAIN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 0,
                            "harmless": 10,
                            "undetected": 5,
                        }
                    }
                }
            },
        )
    )
    registry = EnrichmentRegistry()
    registry.register(VirusTotalProvider(api_key="test-vt-key"))

    result = registry.enrich(DomainIndicator(value="example.com"))

    assert result.provider_id == "virustotal"
    assert result.verdict == EnrichmentVerdict.CLEAN
