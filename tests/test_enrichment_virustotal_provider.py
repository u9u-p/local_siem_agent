import httpx
import respx

from app.enrichment.indicators import DomainIndicator
from app.enrichment.providers.virustotal import VirusTotalProvider
from app.schemas import EnrichmentVerdict

DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/example.com"


def _domain_response(malicious: int, suspicious: int = 0, harmless: int = 10, undetected: int = 5) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "id": "example.com",
                "type": "domain",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "timeout": 0,
                    }
                },
            }
        },
    )


@respx.mock
def test_lookup_returns_malicious_verdict_at_five_or_more_engines():
    respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=5))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(DomainIndicator(value="example.com"))

    assert result.verdict == EnrichmentVerdict.MALICIOUS
    assert result.provider_id == "virustotal"
    assert result.indicator_value == "example.com"
    assert result.error is None


@respx.mock
def test_lookup_returns_suspicious_verdict_below_five_malicious():
    respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=2))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(DomainIndicator(value="example.com"))

    assert result.verdict == EnrichmentVerdict.SUSPICIOUS


@respx.mock
def test_lookup_returns_suspicious_verdict_on_suspicious_only():
    respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=0, suspicious=1))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(DomainIndicator(value="example.com"))

    assert result.verdict == EnrichmentVerdict.SUSPICIOUS


@respx.mock
def test_lookup_returns_clean_verdict_when_no_engines_flag_it():
    respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=0, suspicious=0))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(DomainIndicator(value="example.com"))

    assert result.verdict == EnrichmentVerdict.CLEAN
    assert result.score == 0.0


@respx.mock
def test_lookup_sends_api_key_header():
    route = respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=0))
    provider = VirusTotalProvider(api_key="test-key")

    provider.lookup(DomainIndicator(value="example.com"))

    assert route.calls.last.request.headers["x-apikey"] == "test-key"
