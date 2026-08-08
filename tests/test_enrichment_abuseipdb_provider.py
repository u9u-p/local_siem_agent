import httpx
import pytest
import respx

from app.enrichment.errors import EnrichmentError
from app.enrichment.indicators import IPIndicator
from app.enrichment.providers.abuseipdb import AbuseIPDBProvider
from app.schemas import EnrichmentVerdict

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


@respx.mock
def test_lookup_returns_malicious_verdict_above_threshold():
    respx.get(CHECK_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "ipAddress": "203.0.113.5"}})
    )
    provider = AbuseIPDBProvider(api_key="test-key")

    result = provider.lookup(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.MALICIOUS
    assert result.score == 90.0
    assert result.provider_id == "abuseipdb"
    assert result.indicator_value == "203.0.113.5"
    assert result.error is None


@respx.mock
def test_lookup_returns_suspicious_verdict_in_mid_range():
    respx.get(CHECK_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 50, "ipAddress": "203.0.113.5"}})
    )
    provider = AbuseIPDBProvider(api_key="test-key")

    result = provider.lookup(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.SUSPICIOUS


@respx.mock
def test_lookup_returns_clean_verdict_below_threshold():
    respx.get(CHECK_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 5, "ipAddress": "203.0.113.5"}})
    )
    provider = AbuseIPDBProvider(api_key="test-key")

    result = provider.lookup(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.CLEAN


@respx.mock
def test_lookup_raises_auth_failed_on_401():
    respx.get(CHECK_URL).mock(return_value=httpx.Response(401, json={"errors": [{"detail": "invalid key"}]}))
    provider = AbuseIPDBProvider(api_key="bad-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(IPIndicator(value="203.0.113.5"))
    assert exc_info.value.kind == "auth_failed"


@respx.mock
def test_lookup_raises_rate_limited_on_429():
    respx.get(CHECK_URL).mock(return_value=httpx.Response(429, json={"errors": [{"detail": "rate limited"}]}))
    provider = AbuseIPDBProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(IPIndicator(value="203.0.113.5"))
    assert exc_info.value.kind == "rate_limited"


@respx.mock
def test_lookup_raises_not_found_on_404():
    respx.get(CHECK_URL).mock(return_value=httpx.Response(404, json={"errors": [{"detail": "not found"}]}))
    provider = AbuseIPDBProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(IPIndicator(value="203.0.113.5"))
    assert exc_info.value.kind == "not_found"


@respx.mock
def test_lookup_raises_timeout_on_client_timeout():
    respx.get(CHECK_URL).mock(side_effect=httpx.TimeoutException("timed out"))
    provider = AbuseIPDBProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(IPIndicator(value="203.0.113.5"))
    assert exc_info.value.kind == "timeout"
