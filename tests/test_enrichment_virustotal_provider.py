import httpx
import pytest
import respx

from app.enrichment.errors import EnrichmentError
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
    expected_id = "aHR0cHM6Ly9leGFtcGxlLmNvbS9tYWx3YXJlLmV4ZQ"
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


@respx.mock
def test_lookup_raises_auth_failed_on_401():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}}))
    provider = VirusTotalProvider(api_key="bad-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "auth_failed"


@respx.mock
def test_lookup_raises_not_found_on_404():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "not_found"


@respx.mock
def test_lookup_raises_rate_limited_on_429():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(429, json={"error": {"code": "QuotaExceededError"}}))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "rate_limited"


@respx.mock
def test_lookup_raises_http_error_on_500():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(500, text="internal server error"))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "http_error"


@respx.mock
def test_lookup_raises_timeout_on_client_timeout():
    respx.get(DOMAIN_URL).mock(side_effect=httpx.TimeoutException("timed out"))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "timeout"


@respx.mock
def test_lookup_raises_network_error_on_connect_error():
    respx.get(DOMAIN_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "network_error"


@respx.mock
def test_lookup_raises_bad_response_on_malformed_body():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(200, json={"unexpected": "shape"}))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "bad_response"


@respx.mock
def test_lookup_raises_bad_response_on_non_json_body():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(200, text="<html>not json</html>"))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "bad_response"
