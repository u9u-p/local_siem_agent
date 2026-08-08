from datetime import datetime, timezone

import httpx

from app.enrichment.errors import EnrichmentError
from app.enrichment.indicators import IPIndicator
from app.schemas import EnrichmentResult, EnrichmentVerdict, IndicatorType

ABUSEIPDB_MALICIOUS_THRESHOLD = 75
ABUSEIPDB_SUSPICIOUS_THRESHOLD = 25


class AbuseIPDBProvider:
    provider_id = "abuseipdb"
    supported_types = frozenset({IndicatorType.IP})

    def __init__(self, api_key: str, client: httpx.Client | None = None) -> None:
        self._api_key = api_key
        self._client = client or httpx.Client(base_url="https://api.abuseipdb.com/api/v2", timeout=10.0)

    def lookup(self, indicator: IPIndicator) -> EnrichmentResult:
        try:
            response = self._client.get(
                "/check",
                params={"ipAddress": indicator.value, "maxAgeInDays": 90},
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
        except httpx.TimeoutException as exc:
            raise EnrichmentError("timeout", str(exc)) from exc

        if response.status_code == 401:
            raise EnrichmentError("auth_failed", "AbuseIPDB rejected the API key")
        if response.status_code == 429:
            raise EnrichmentError("rate_limited", "AbuseIPDB rate limit exceeded")
        if response.status_code == 404:
            raise EnrichmentError("not_found", f"no data for {indicator.value}")
        response.raise_for_status()

        payload = response.json()
        data = payload["data"]
        score = float(data["abuseConfidenceScore"])
        if score > ABUSEIPDB_MALICIOUS_THRESHOLD:
            verdict = EnrichmentVerdict.MALICIOUS
        elif score > ABUSEIPDB_SUSPICIOUS_THRESHOLD:
            verdict = EnrichmentVerdict.SUSPICIOUS
        else:
            verdict = EnrichmentVerdict.CLEAN

        queried_at = datetime.now(timezone.utc)
        return EnrichmentResult(
            indicator_type=IndicatorType.IP,
            indicator_value=indicator.value,
            provider_id=self.provider_id,
            queried_at=queried_at,
            verdict=verdict,
            score=score,
            raw_response=payload,
            cache_expires_at=queried_at,  # not meaningful until caching (deferred) lands
            error=None,
        )
