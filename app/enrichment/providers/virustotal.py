from datetime import datetime, timezone

import httpx

from app.enrichment.errors import EnrichmentError
from app.enrichment.indicators import DomainIndicator, HashIndicator, URLIndicator
from app.schemas import EnrichmentResult, EnrichmentVerdict, IndicatorType

VIRUSTOTAL_MALICIOUS_ENGINE_COUNT = 5


class VirusTotalProvider:
    provider_id = "virustotal"
    supported_types = frozenset({IndicatorType.DOMAIN, IndicatorType.FILE_HASH, IndicatorType.URL})

    def __init__(self, api_key: str, client: httpx.Client | None = None) -> None:
        self._api_key = api_key
        self._client = client or httpx.Client(base_url="https://www.virustotal.com/api/v3", timeout=10.0)

    def lookup(self, indicator: DomainIndicator | HashIndicator | URLIndicator) -> EnrichmentResult:
        path = self._path_for(indicator)
        response = self._client.get(path, headers={"x-apikey": self._api_key})

        payload = response.json()
        stats = payload["data"]["attributes"]["last_analysis_stats"]
        malicious = int(stats["malicious"])
        suspicious = int(stats["suspicious"])
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))

        if malicious >= VIRUSTOTAL_MALICIOUS_ENGINE_COUNT:
            verdict = EnrichmentVerdict.MALICIOUS
        elif malicious >= 1 or suspicious >= 1:
            verdict = EnrichmentVerdict.SUSPICIOUS
        else:
            verdict = EnrichmentVerdict.CLEAN

        total = malicious + suspicious + harmless + undetected
        score = (malicious / total * 100) if total else 0.0

        queried_at = datetime.now(timezone.utc)
        return EnrichmentResult(
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value,
            provider_id=self.provider_id,
            queried_at=queried_at,
            verdict=verdict,
            score=score,
            raw_response=payload,
            cache_expires_at=queried_at,  # not meaningful until caching (Phase 6a) lands
            error=None,
        )

    def _path_for(self, indicator: DomainIndicator | HashIndicator | URLIndicator) -> str:
        if indicator.indicator_type == IndicatorType.DOMAIN:
            return f"/domains/{indicator.value}"
        if indicator.indicator_type == IndicatorType.FILE_HASH:
            return f"/files/{indicator.value}"
        raise NotImplementedError("URL lookup added in Task 4")
