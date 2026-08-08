import pytest

from app.enrichment.errors import EnrichmentError


def test_enrichment_error_carries_kind_and_message():
    error = EnrichmentError("rate_limited", "AbuseIPDB rate limit exceeded")
    assert error.kind == "rate_limited"
    assert str(error) == "AbuseIPDB rate limit exceeded"


def test_enrichment_error_is_an_exception():
    with pytest.raises(EnrichmentError):
        raise EnrichmentError("timeout", "took too long")
