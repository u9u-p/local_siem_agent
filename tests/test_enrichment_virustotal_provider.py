import base64

import httpx
import respx

from app.enrichment.indicators import DomainIndicator, HashIndicator, URLIndicator
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


FILE_URL = f"https://www.virustotal.com/api/v3/files/{'a' * 64}"


def _file_response(malicious: int) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "id": "a" * 64,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": 0,
                        "harmless": 10,
                        "undetected": 5,
                        "timeout": 0,
                        "confirmed-timeout": 0,
                        "failure": 0,
                        "type-unsupported": 0,
                    }
                },
            }
        },
    )


@respx.mock
def test_lookup_hash_indicator_queries_files_endpoint():
    respx.get(FILE_URL).mock(return_value=_file_response(malicious=6))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(HashIndicator(value="a" * 64))

    assert result.verdict == EnrichmentVerdict.MALICIOUS
    assert result.indicator_value == "a" * 64


def test_url_lookup_uses_unpadded_base64_id():
    raw_url = "https://example.com/malware.exe"
    expected_id = base64.urlsafe_b64encode(raw_url.encode()).decode().rstrip("=")
    url_endpoint = f"https://www.virustotal.com/api/v3/urls/{expected_id}"

    with respx.mock:
        respx.get(url_endpoint).mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "id": expected_id,
                        "type": "url",
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
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
        provider = VirusTotalProvider(api_key="test-key")

        result = provider.lookup(URLIndicator(value=raw_url))

        assert result.verdict == EnrichmentVerdict.CLEAN
        assert result.indicator_value == raw_url
