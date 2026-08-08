from datetime import datetime, timezone

import pytest

from app.enrichment.errors import EnrichmentError
from app.enrichment.indicators import IPIndicator
from app.enrichment.registry import EnrichmentRegistry
import app.enrichment.registry as registry_module
from app.schemas import EnrichmentResult, EnrichmentVerdict, IndicatorType


class _FakeProvider:
    provider_id = "abuseipdb"
    supported_types = frozenset({IndicatorType.IP})

    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error
        self.calls = 0

    def lookup(self, indicator):
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._result


def _make_result(**overrides):
    defaults = dict(
        indicator_type=IndicatorType.IP,
        indicator_value="203.0.113.5",
        provider_id="abuseipdb",
        queried_at=datetime.now(timezone.utc),
        verdict=EnrichmentVerdict.CLEAN,
        score=1.0,
        cache_expires_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return EnrichmentResult(**defaults)


def test_enrich_returns_provider_result_on_success():
    provider = _FakeProvider(result=_make_result())
    registry = EnrichmentRegistry()
    registry.register(provider)

    result = registry.enrich(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.CLEAN
    assert provider.calls == 1


def test_enrich_returns_unknown_verdict_on_provider_error():
    provider = _FakeProvider(error=EnrichmentError("timeout", "took too long"))
    registry = EnrichmentRegistry()
    registry.register(provider)

    result = registry.enrich(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.UNKNOWN
    assert result.error == "timeout"


def test_enrich_returns_rate_limited_without_calling_provider(monkeypatch):
    monkeypatch.setitem(registry_module._DAILY_LIMITS, "abuseipdb", 0)
    provider = _FakeProvider(result=_make_result())
    registry = EnrichmentRegistry()
    registry.register(provider)

    result = registry.enrich(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.UNKNOWN
    assert result.error == "rate_limited"
    assert provider.calls == 0


def test_enrich_raises_when_no_provider_registered():
    registry = EnrichmentRegistry()

    with pytest.raises(ValueError):
        registry.enrich(IPIndicator(value="203.0.113.5"))
