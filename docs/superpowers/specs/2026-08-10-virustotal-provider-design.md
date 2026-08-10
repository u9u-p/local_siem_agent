# VirusTotal Provider + Multi-Type Indicators (Phase 2b) Design

**Date:** 10 Aug 2026
**Parent design:** `CLAUDE.md` §1.3 (Enrichment Protocols), §5 (Enrichment Plugin Architecture — names `VirusTotalProvider` as a second adapter)
**Roadmap:** Phase 2b — inserted between Phase 2 (Enrichment core, done) and Phase 4b, pulled forward from the originally-deferred "Phase 6b: second Enrichment provider" because Phase 4b's indicator-extraction/enrichment steps benefit from having multiple indicator types already routable.
**Depends on:** Phase 2 (`app/enrichment/*`, already merged) — extends it, doesn't modify its core `EnrichmentRegistry`/`DailyRateLimiter`/`EnrichmentError` machinery.

---

## Context

CLAUDE.md §5 always named `VirusTotalProvider` as a second adapter alongside `AbuseIPDBProvider`, with routing `IP → [abuseipdb, virustotal]`, `FILE_HASH → [virustotal]`, `DOMAIN → [virustotal]`. Brainstorming clarified the actual goal is **breadth, not depth**: one alert can contain several *different* indicator types (an IP and a file hash, say), each routed to its own dedicated provider — not two providers competing over the same indicator with a reconciliation step. This simplifies the design significantly: **no changes to `EnrichmentRegistry` are needed at all.**

`EnrichmentRegistry.register()` already loops over `provider.supported_types` and appends each type to its own list (`app/enrichment/registry.py:24-27`). Registering a multi-type `VirusTotalProvider` alongside the existing single-type `AbuseIPDBProvider` automatically produces `{IP: [abuseipdb], DOMAIN: [virustotal], FILE_HASH: [virustotal], URL: [virustotal]}` — exactly "one provider per type" — with zero registry code changes. The only real gaps are (1) indicator types beyond IP don't exist yet, and (2) there's no second provider to route them to.

**Scope decision from brainstorming:** VirusTotal covers `DOMAIN`, `FILE_HASH`, and `URL` (its real API supports all three cleanly). `EMAIL` (the fifth `IndicatorType` member, from Foundation) remains unenriched — no provider in this design's set has a public reputation API for arbitrary email addresses.

**Compliance note, not blocking for this POC:** VirusTotal's free/public API tier's terms explicitly prohibit "business workflows that do not contribute new files" and commercial use (confirmed in their docs, not inferred). Fine for a demo; a Premium key would be the compliant choice before any real use — flagging so it isn't forgotten, consistent with this project's practice of surfacing this kind of thing rather than silently assuming a free tier is fine forever.

---

## 1. Researched VirusTotal API v3 facts (cited, not assumed)

| Fact | Detail | Source |
|---|---|---|
| Auth | `x-apikey` header | docs.virustotal.com/reference/authentication |
| Base URL | `https://www.virustotal.com/api/v3` | docs.virustotal.com/reference/domain-info |
| Domain lookup | `GET /domains/{domain}` | docs.virustotal.com/reference/domain-info |
| File hash lookup | `GET /files/{hash}` (MD5/SHA1/SHA256 all accepted directly) | docs.virustotal.com/reference/file-info |
| URL lookup | `GET /urls/{id}` where `id` = unpadded base64 of the raw URL string (`base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")`) — a direct lookup, no submission step required; returns 404 cleanly if never scanned | docs.virustotal.com/reference/url-info, /reference/url |
| Response shape | All three: `data.attributes.last_analysis_stats` = `{harmless, malicious, suspicious, undetected, timeout, ...}` engine counts. Files' stats object has extra keys (`confirmed-timeout`, `failure`, `type-unsupported`) domains/URLs don't — read defensively, don't assume a fixed key set | docs.virustotal.com/reference/domains-object, /reference/files, /reference/url-object |
| Rate limits (public tier) | ~500/day, ~4/min | docs.virustotal.com/reference/public-vs-premium-api |
| Errors | `401` `WrongCredentialsError` (bad key); `404` `NotFoundError` (never scanned); `429` `QuotaExceededError`/`TooManyRequestsError` (rate limited); `503`/`504` transient/timeout. Consistent body: `{"error": {"code": "...", "message": "..."}}` | docs.virustotal.com/reference/errors |
| Verdict threshold | **No official VirusTotal recommendation exists** — confirmed absent from their docs. This design's threshold (§4 below) is an explicit project decision, not vendor guidance. | (absence confirmed by direct search) |

---

## 2. File Structure

```
app/enrichment/
  indicators.py          # MODIFIED: + HashIndicator, DomainIndicator, URLIndicator; Indicator becomes a Union
  providers/
    virustotal.py         # NEW
```

`app/config.py` gains `virustotal_api_key: str | None = None`. `app/enrichment/registry.py`'s `_DAILY_LIMITS` dict gains `"virustotal": 500`. No other registry changes.

---

## 3. New Indicator Types

```python
# app/enrichment/indicators.py (additions — alongside the existing `import ipaddress`,
# `from pydantic import BaseModel, field_validator`, `from app.schemas import IndicatorType`)
import re
import urllib.parse

_HASH_PATTERNS = {
    32: re.compile(r"^[0-9a-fA-F]{32}$"),   # MD5
    40: re.compile(r"^[0-9a-fA-F]{40}$"),   # SHA1
    64: re.compile(r"^[0-9a-fA-F]{64}$"),   # SHA256
}

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


class HashIndicator(BaseModel):
    indicator_type: IndicatorType = IndicatorType.FILE_HASH
    value: str

    @field_validator("value")
    @classmethod
    def _validate_hash(cls, v: str) -> str:
        pattern = _HASH_PATTERNS.get(len(v))
        if pattern is None or not pattern.match(v):
            raise ValueError(f"not a valid MD5/SHA1/SHA256 hash: {v}")
        return v.lower()


class DomainIndicator(BaseModel):
    indicator_type: IndicatorType = IndicatorType.DOMAIN
    value: str

    @field_validator("value")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        if not _DOMAIN_RE.match(v):
            raise ValueError(f"not a valid domain name: {v}")
        return v.lower()


class URLIndicator(BaseModel):
    indicator_type: IndicatorType = IndicatorType.URL
    value: str

    @field_validator("value")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        parsed = urllib.parse.urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"not a valid http(s) URL: {v}")
        return v


Indicator = IPIndicator | HashIndicator | DomainIndicator | URLIndicator
```

`HashIndicator`/`DomainIndicator` canonicalize to lowercase (matching `IPIndicator`'s existing "canonical form for cache-key stability" rationale — still relevant once caching lands in Phase 6a, even though it's not built yet). The domain regex is a deliberately-scoped RFC-1035-ish pattern, not a full parser — good enough to reject garbage, not a substitute for a dedicated library if domain validation ever needs to get stricter.

---

## 4. `VirusTotalProvider`

```python
# app/enrichment/providers/virustotal.py
import base64
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
        try:
            response = self._client.get(path, headers={"x-apikey": self._api_key})
        except httpx.TimeoutException as exc:
            raise EnrichmentError("timeout", str(exc)) from exc
        except httpx.RequestError as exc:
            raise EnrichmentError("network_error", str(exc)) from exc

        if response.status_code == 401:
            raise EnrichmentError("auth_failed", "VirusTotal rejected the API key")
        if response.status_code == 404:
            raise EnrichmentError("not_found", f"no VirusTotal report for {indicator.value}")
        if response.status_code == 429:
            raise EnrichmentError("rate_limited", "VirusTotal rate limit exceeded")
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise EnrichmentError("http_error", str(exc)) from exc

        try:
            payload = response.json()
            stats = payload["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats["malicious"])
            suspicious = int(stats["suspicious"])
            harmless = int(stats.get("harmless", 0))
            undetected = int(stats.get("undetected", 0))
        except (ValueError, KeyError, TypeError) as exc:
            raise EnrichmentError("bad_response", str(exc)) from exc

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
        url_id = base64.urlsafe_b64encode(indicator.value.encode()).decode().rstrip("=")
        return f"/urls/{url_id}"
```

Verdict is driven by absolute engine counts (`malicious >= 5`), not the normalized `score` — `score` is a secondary, human-readable percentage carried on `EnrichmentResult` for consistency with `AbuseIPDBProvider`'s shape, not the decision variable. This mirrors the brainstorming decision: absolute counts are comparable across domain/hash/URL lookups regardless of how many total engines had an opinion, whereas a ratio can be skewed by a report with very few engines participating.

---

## 5. Config & Registry Changes

```python
# app/config.py — one new field
virustotal_api_key: str | None = None
```

```python
# app/enrichment/registry.py — one dict entry, no other changes
_DAILY_LIMITS = {"abuseipdb": 1000, "virustotal": 500}
```

No changes to `EnrichmentRegistry.register()`, `.providers_for()`, `.enrich()`, or `DailyRateLimiter` — all already correct for this multi-type, one-provider-per-type shape, as established in §Context.

---

## 6. Testing

- **New indicator types** (`tests/test_enrichment_indicators.py`, extended): valid/invalid cases per type — a real MD5/SHA1/SHA256 accepted, wrong-length/non-hex rejected; a real domain accepted, garbage rejected; a real `http(s)` URL accepted, a non-HTTP scheme or missing host rejected.
- **`VirusTotalProvider`** (`tests/test_enrichment_virustotal_provider.py`, new, respx-mocked): one test per indicator type's happy path (verdict derived correctly from mocked `last_analysis_stats`), plus the shared error-mapping tests (401/404/429/500/timeout/malformed-body) mirroring `AbuseIPDBProvider`'s existing test shape.
- **Registry integration** (`tests/test_enrichment_registry.py`, extended): register both `AbuseIPDBProvider` and a fake/mocked `VirusTotalProvider`, confirm `providers_for(IP)` returns only AbuseIPDB and `providers_for(DOMAIN)`/`providers_for(FILE_HASH)`/`providers_for(URL)` return only VirusTotal — proving the "one provider per type, multiple types" shape end-to-end with no registry code changes needed.
- **End-to-end scenario** (`tests/test_enrichment_integration.py`, extended): one respx-mocked flow enriching an IP indicator (→ AbuseIPDB) and a file-hash indicator (→ VirusTotal) from what stands in for one alert's extracted indicators, confirming both routes resolve independently and correctly — this is the concrete "alert contains IP and hashes" scenario from brainstorming.

---

## Open Items for the Implementation Plan

1. The domain-validation regex (§3) is a pragmatic, deliberately-scoped pattern — note in the plan that it's not a full RFC 1035 implementation, so a plan task shouldn't over-invest in edge cases (IDN/punycode, etc.) beyond rejecting obviously-malformed input.
2. VirusTotal's real per-minute rate limit (~4/min) is tighter relative to per-alert call volume than AbuseIPDB's daily-only limit — `DailyRateLimiter` doesn't model this. Not fixing it in this plan (consistent with Phase 2's existing simplification), but worth a one-line note in the plan's Global Constraints so it isn't mistaken for an oversight.
3. `.env.example` needs a `VIRUSTOTAL_API_KEY=` line added alongside the config change.
