from datetime import datetime, timezone
from typing import Protocol

from app.enrichment.errors import EnrichmentError
from app.enrichment.indicators import Indicator
from app.enrichment.rate_limiter import DailyRateLimiter
from app.schemas import EnrichmentResult, EnrichmentVerdict, IndicatorType

_DAILY_LIMITS = {"abuseipdb": 1000}


class EnrichmentProvider(Protocol):
    provider_id: str
    supported_types: frozenset[IndicatorType]

    def lookup(self, indicator: Indicator) -> EnrichmentResult: ...


class EnrichmentRegistry:
    def __init__(self) -> None:
        self._providers: dict[IndicatorType, list[EnrichmentProvider]] = {}
        self._limiters: dict[str, DailyRateLimiter] = {}

    def register(self, provider: EnrichmentProvider) -> None:
        for indicator_type in provider.supported_types:
            self._providers.setdefault(indicator_type, []).append(provider)
        self._limiters[provider.provider_id] = DailyRateLimiter(_DAILY_LIMITS[provider.provider_id])

    def providers_for(self, indicator_type: IndicatorType) -> list[EnrichmentProvider]:
        return list(self._providers.get(indicator_type, []))

    def _unknown_result(self, indicator: Indicator, provider_id: str, error: str) -> EnrichmentResult:
        queried_at = datetime.now(timezone.utc)
        return EnrichmentResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            provider_id=provider_id,
            queried_at=queried_at,
            verdict=EnrichmentVerdict.UNKNOWN,
            score=0.0,
            cache_expires_at=queried_at,  # not meaningful until caching (deferred) lands
            error=error,
        )

    def enrich(self, indicator: Indicator) -> EnrichmentResult:
        providers = self.providers_for(indicator.indicator_type)
        if not providers:
            raise ValueError(f"no provider registered for {indicator.indicator_type}")

        # Highest-priority (first-registered) provider only — cross-provider fallback
        # on error is out of scope until a second IP-capable provider exists.
        provider = providers[0]
        limiter = self._limiters[provider.provider_id]
        if not limiter.try_acquire():
            return self._unknown_result(indicator, provider.provider_id, "rate_limited")

        try:
            return provider.lookup(indicator)
        except EnrichmentError as exc:
            return self._unknown_result(indicator, provider.provider_id, exc.kind)
        except Exception:
            # Defensive net: a provider must never abort the investigation, even if it
            # raises something outside the EnrichmentError contract.
            return self._unknown_result(indicator, provider.provider_id, "unexpected_error")
