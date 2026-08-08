# Enrichment Module Design

**Date:** 09 Aug 2026
**Parent design:** `CLAUDE.md` §1.3 (Enrichment module Protocols), §5 (Enrichment Plugin Architecture)
**Depends on:** Foundation subsystem (`app/schemas.py`, `app/config.py`) — already implemented and merged to `main`.

---

## Context

CLAUDE.md's §1.3 and §5 establish the Enrichment module's Protocols and architectural rules at a high level (deterministic routing, no LLM involvement, typed indicators only, cache-before-network, typed error handling). This document works out the concrete implementation: file structure, exact interfaces, one live provider (AbuseIPDB), and the decisions confirmed in brainstorming:

1. **First provider:** AbuseIPDB (IP reputation only) — simplest real integration, generous free-tier limit.
2. **API key:** loaded via an extension to the existing `Settings` class in `app/config.py`, not a separate `SecretsProvider` abstraction.
3. **Cache persistence:** `EnrichmentCache` gets its own SQLite file (`./data/cache.db`) and its own SQLModel metadata/engine, physically separate from `AlertStore`'s `alerts.db` — this was an explicit gap flagged by the Foundation plan's final review (SQLModel's metadata is global, so an unscoped `EnrichmentCache` table would silently land in the same file/metadata as `AlertStore`'s tables).
4. **Rate limiting:** in-memory, per-process token/day-window counter — resets on restart. Acceptable for a POC single long-running process; a restart losing partial daily-quota tracking is a minor, accepted limitation.

This plan does **not** wire the Enrichment module into the Agentic Analyst's state graph — that's a separate, later subsystem plan (CLAUDE.md §4). This plan produces a fully working, independently-testable Enrichment module: given an indicator, return an `EnrichmentResult`, cache-first, rate-limited, with typed error handling.

---

## 1. File Structure

```
app/enrichment/
  __init__.py
  indicators.py      # IPIndicator (validated Pydantic model) + Indicator type alias
  errors.py          # EnrichmentError and its typed variants
  cache_models.py    # SQLModel table for the cache, separate metadata/engine
  cache_db.py         # get_cache_engine/init_cache_db/get_cache_session (mirrors app/storage/db.py's pattern)
  cache.py           # EnrichmentCache Protocol + SQLiteEnrichmentCache impl
  rate_limiter.py    # DailyRateLimiter (in-memory, per-provider)
  registry.py        # EnrichmentRegistry
  providers/
    __init__.py
    abuseipdb.py     # AbuseIPDBProvider
```

`app/config.py` (existing file) gets one new field: `abuseipdb_api_key: str | None`.

---

## 2. Indicator Typing

```python
# app/enrichment/indicators.py
import re
from pydantic import BaseModel, field_validator

from app.schemas import IndicatorType

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

class IPIndicator(BaseModel):
    indicator_type: IndicatorType = IndicatorType.IP
    value: str

    @field_validator("value")
    @classmethod
    def _validate_ip(cls, v: str) -> str:
        if not _IPV4_RE.match(v):
            raise ValueError(f"not a valid IPv4 address: {v}")
        octets = v.split(".")
        if not all(0 <= int(o) <= 255 for o in octets):
            raise ValueError(f"not a valid IPv4 address: {v}")
        return v

Indicator = IPIndicator  # widened to a Union when a second indicator type is added
```

IPv4 only for this slice (matches AbuseIPDB's primary use case); IPv6 and other indicator types are added when a provider that needs them is added — no speculative validators for indicator types nothing in this plan consumes.

---

## 3. Typed Errors

```python
# app/enrichment/errors.py
class EnrichmentError(Exception):
    def __init__(self, kind: str, message: str):
        self.kind = kind  # "rate_limited" | "auth_failed" | "not_found" | "timeout"
        super().__init__(message)
```

A single class with a `kind` discriminator (not four subclasses) — the registry only ever needs to branch on `kind` to decide `verdict=UNKNOWN` + record the reason, per CLAUDE.md §5's "a provider outage must never abort the investigation."

---

## 4. Enrichment Cache — separate file, separate metadata

```python
# app/enrichment/cache_models.py
from datetime import datetime
from typing import Any

from sqlmodel import JSON, Column, Field, SQLModel

class CacheMetadata(SQLModel):
    pass  # placeholder base so this module's tables register on their OWN SQLModel subclass tree,
          # never on the shared SQLModel.metadata that app/storage/models.py populates

class EnrichmentCacheRecord(CacheMetadata, table=True):
    __tablename__ = "enrichment_cache"

    provider_id: str = Field(primary_key=True)
    indicator_type: str = Field(primary_key=True)
    indicator_value: str = Field(primary_key=True)
    result: dict[str, Any] = Field(sa_column=Column(JSON))
    cached_at: datetime
    expires_at: datetime = Field(index=True)
```

Composite primary key `(provider_id, indicator_type, indicator_value)` matches CLAUDE.md §5 exactly. `result` stores the full `EnrichmentResult.model_dump(mode="json")` — same `mode="json"` discipline the Foundation plan's final review established, since `EnrichmentResult` has two datetime fields (`queried_at`, `cache_expires_at`).

**Important — verify at implementation time:** SQLModel's `table=True` classes register on `SQLModel.metadata` by default regardless of an intermediate non-table base class; the `CacheMetadata` placeholder above may not actually achieve a separate metadata namespace. The implementer must confirm this (SQLModel/SQLAlchemy docs, or a quick test asserting `EnrichmentCacheRecord.metadata is not AlertRecord.metadata` — or, more robustly, that creating an engine via `get_cache_engine` and calling a cache-only `init_cache_db` does NOT create the `alerts`/`reports` tables in the cache file) and adjust the mechanism if needed (e.g. a distinct `SQLModel` subclass tree via `sqlmodel.SQLModel` isn't naturally separable — the reliable approach is usually a second `sqlalchemy.orm.declarative_base()`-style registry, which SQLModel exposes via constructing tables against a fresh `MetaData()` object passed explicitly). This is a known rough edge in SQLModel and should be resolved with a real passing test, not assumed from this sketch.

```python
# app/enrichment/cache_db.py — mirrors app/storage/db.py's shape
def get_cache_engine(cache_db_path: str): ...
def init_cache_db(engine) -> None: ...
def get_cache_session(engine) -> Session: ...
```

```python
# app/enrichment/cache.py
from typing import Protocol
from datetime import timedelta
from app.schemas import EnrichmentResult, IndicatorType

class EnrichmentCache(Protocol):
    def get(self, provider_id: str, indicator_type: IndicatorType, indicator_value: str) -> EnrichmentResult | None: ...
    def set(self, result: EnrichmentResult, ttl: timedelta) -> None: ...

class SQLiteEnrichmentCache:
    def __init__(self, engine) -> None: ...
    def get(self, provider_id, indicator_type, indicator_value) -> EnrichmentResult | None:
        # returns None if missing OR if expires_at has passed (expired entries are treated as a miss,
        # not actively deleted in this slice — a lazy-expiry read, simplest correct behavior for a POC)
        ...
    def set(self, result, ttl) -> None:
        # upsert on the composite primary key; cached_at=now, expires_at=now+ttl
        ...
```

---

## 5. Rate Limiter

```python
# app/enrichment/rate_limiter.py
from datetime import date

class DailyRateLimiter:
    def __init__(self, daily_limit: int) -> None:
        self._daily_limit = daily_limit
        self._count = 0
        self._window_date = date.today()

    def try_acquire(self) -> bool:
        today = date.today()
        if today != self._window_date:
            self._window_date = today
            self._count = 0
        if self._count >= self._daily_limit:
            return False
        self._count += 1
        return True
```

One instance per provider, held by the registry. `daily_limit` comes from a small static config dict in `registry.py` (e.g. `{"abuseipdb": 1000}`) — not user-configurable in this slice, matching the "config values per provider" note in CLAUDE.md §5 without introducing a config-file format nothing else needs yet.

---

## 6. AbuseIPDB Provider

```python
# app/enrichment/providers/abuseipdb.py
import httpx
from app.enrichment.errors import EnrichmentError
from app.enrichment.indicators import IPIndicator
from app.schemas import EnrichmentResult, EnrichmentVerdict, IndicatorType

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

        data = response.json()["data"]
        score = float(data["abuseConfidenceScore"])
        verdict = (
            EnrichmentVerdict.MALICIOUS if score > 75
            else EnrichmentVerdict.SUSPICIOUS if score > 25
            else EnrichmentVerdict.CLEAN
        )
        # queried_at/cache_expires_at, indicator_type/indicator_value, provider_id, raw_response
        # are all filled in by the caller (EnrichmentRegistry), per the plan's task breakdown —
        # this method returns the provider-specific parts (score, verdict, raw payload) and the
        # registry assembles the full EnrichmentResult. Exact split finalized in the implementation plan.
        ...
```

The verdict thresholds (75/25) are a reasonable starting default, not a value from an external spec — flagged so the implementation plan can treat them as an explicit, named constant (`ABUSEIPDB_MALICIOUS_THRESHOLD`, etc.) rather than inline magic numbers.

---

## 7. Registry

```python
# app/enrichment/registry.py
from datetime import datetime, timedelta, timezone

from app.enrichment.cache import EnrichmentCache
from app.enrichment.errors import EnrichmentError
from app.enrichment.indicators import Indicator
from app.enrichment.rate_limiter import DailyRateLimiter
from app.schemas import EnrichmentResult, EnrichmentVerdict, IndicatorType

_CACHE_TTL_BY_TYPE = {IndicatorType.IP: timedelta(hours=24)}
_DAILY_LIMITS = {"abuseipdb": 1000}

class EnrichmentRegistry:
    def __init__(self, cache: EnrichmentCache) -> None:
        self._cache = cache
        self._providers: dict[IndicatorType, list] = {}  # populated via register()
        self._limiters: dict[str, DailyRateLimiter] = {}

    def register(self, provider) -> None:
        for t in provider.supported_types:
            self._providers.setdefault(t, []).append(provider)
        self._limiters[provider.provider_id] = DailyRateLimiter(_DAILY_LIMITS[provider.provider_id])

    def providers_for(self, indicator_type: IndicatorType) -> list:
        return list(self._providers.get(indicator_type, []))

    def enrich(self, indicator: Indicator) -> EnrichmentResult:
        for provider in self.providers_for(indicator.indicator_type):
            cached = self._cache.get(provider.provider_id, indicator.indicator_type, indicator.value)
            if cached is not None:
                return cached

            limiter = self._limiters[provider.provider_id]
            if not limiter.try_acquire():
                return EnrichmentResult(
                    indicator_type=indicator.indicator_type, indicator_value=indicator.value,
                    provider_id=provider.provider_id, queried_at=datetime.now(timezone.utc),
                    verdict=EnrichmentVerdict.UNKNOWN, score=0.0,
                    cache_expires_at=datetime.now(timezone.utc), error="rate_limited",
                )

            try:
                result = provider.lookup(indicator)
            except EnrichmentError as exc:
                result = EnrichmentResult(
                    indicator_type=indicator.indicator_type, indicator_value=indicator.value,
                    provider_id=provider.provider_id, queried_at=datetime.now(timezone.utc),
                    verdict=EnrichmentVerdict.UNKNOWN, score=0.0,
                    cache_expires_at=datetime.now(timezone.utc), error=exc.kind,
                )
                return result  # don't cache errors — a transient outage shouldn't stick for the TTL

            self._cache.set(result, _CACHE_TTL_BY_TYPE[indicator.indicator_type])
            return result

        raise ValueError(f"no provider registered for {indicator.indicator_type}")
```

`enrich()` returns the **first** registered provider's result for a given type (priority order == registration order), matching CLAUDE.md §5's "call each candidate in priority order" — this slice registers exactly one provider (AbuseIPDB) for `IP`, so multi-provider fallback behavior (try provider 2 if provider 1 errors) is a design question for when a second IP-capable provider (e.g. VirusTotal) is actually added, not invented speculatively here.

---

## 8. Error Handling Summary

| Situation | Behavior |
|---|---|
| Cache hit | Return cached `EnrichmentResult`, no network call |
| Rate limit exhausted | Return `EnrichmentResult(verdict=UNKNOWN, error="rate_limited")`, not cached, no exception raised past the registry |
| Provider timeout / auth failure / not found | Same shape, `error=<kind>`, not cached |
| Provider returns a real result | Cached with type-specific TTL, returned normally |
| No provider registered for the indicator's type | `ValueError` — a real programming error (registry misconfiguration), not a runtime data issue, so it's fine for this one to raise |

---

## 9. Testing

- **`AbuseIPDBProvider`**: `respx`-mocked `httpx` responses for the 200/401/404/429/timeout cases, asserting the correct `EnrichmentResult`/`EnrichmentError` for each.
- **`SQLiteEnrichmentCache`**: real SQLite round-trip via `tmp_path`, including an expired-entry-treated-as-miss case, mirroring the Foundation plan's `mode="json"` datetime discipline (add a populated round-trip test up front this time, learning directly from the Foundation plan's Critical finding).
- **`DailyRateLimiter`**: unit tests for exhaustion and window-rollover (the latter needs a way to inject/mock "today" — `freeze_gun` or a small seam, since the plan's Global Constraints should specify one explicitly to avoid each task inventing its own).
- **`EnrichmentRegistry`**: unit tests with a fake in-memory `EnrichmentCache` and a fake provider (no real HTTP), covering cache-hit, rate-limited, provider-error, and happy-path branches.
- **Integration-ish test**: `AbuseIPDBProvider` + real `SQLiteEnrichmentCache` + `EnrichmentRegistry` wired together, still with `respx`-mocked HTTP — confirms the pieces compose, without touching the real network.

---

## Open Items for the Implementation Plan

1. The `CacheMetadata`/separate-metadata mechanism in §4 is a sketch, not a verified SQLModel pattern — the plan must include a task step that proves table isolation with a real test before building on it.
2. Exact field-assembly split between `AbuseIPDBProvider.lookup()` and `EnrichmentRegistry.enrich()` (who sets `queried_at`, `provider_id`, etc. on the returned `EnrichmentResult`) should be nailed down to one consistent approach in the plan's actual code blocks.
3. Verdict thresholds (75/25) should be named constants, not inline magic numbers.
4. A time-mocking approach for `DailyRateLimiter`'s window-rollover test should be picked once and stated in Global Constraints (`freezegun` is already a CLAUDE.md §6 recommendation).
