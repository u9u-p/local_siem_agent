# Enrichment Module Design

**Date:** 09 Aug 2026 (revised: caching deferred)
**Parent design:** `CLAUDE.md` §1.3 (Enrichment module Protocols), §5 (Enrichment Plugin Architecture)
**Depends on:** Foundation subsystem (`app/schemas.py`, `app/config.py`) — already implemented and merged to `main`.

---

## Context

CLAUDE.md's §1.3 and §5 establish the Enrichment module's Protocols and architectural rules at a high level (deterministic routing, no LLM involvement, typed indicators only, cache-before-network, typed error handling). This document works out the concrete implementation: file structure, exact interfaces, and one live provider (AbuseIPDB) — with caching deliberately deferred (see Non-Goals).

Decisions confirmed in brainstorming:

1. **First provider:** AbuseIPDB (IP reputation only) — simplest real integration, generous free-tier limit.
2. **API key:** loaded via an extension to the existing `Settings` class in `app/config.py`, not a separate `SecretsProvider` abstraction.
3. **Rate limiting:** in-memory, per-process token/day-window counter — resets on restart. Acceptable for a POC single long-running process; a restart losing partial daily-quota tracking is a minor, accepted limitation.
4. **Caching: deferred.** See Non-Goals below.

This plan does **not** wire the Enrichment module into the Agentic Analyst's state graph — that's a separate, later subsystem plan (CLAUDE.md §4). This plan produces a working, independently-testable Enrichment module: given an indicator, return an `EnrichmentResult`, rate-limited, with typed error handling.

---

## Non-Goals (this pass)

**`EnrichmentCache` is deferred to a future iteration.** CLAUDE.md §5 specifies checking a cache before any network call; for this prototype pass we're building the core provider/registry/rate-limiting path first and adding caching once that's proven, rather than building persistence for a feature that doesn't exist yet. Concretely, this means:

- No `EnrichmentCache` Protocol implementation, no cache SQLite file, no TTL logic in this plan.
- `EnrichmentRegistry.enrich()` calls the provider directly (after the rate-limit check) on every call — repeated lookups for the same indicator cost real API quota. Acceptable for prototype-scale usage; worth revisiting before any sustained/production use.
- CLAUDE.md §1.3 already defines the `EnrichmentCache` Protocol shape (`get`/`set` keyed on `(provider_id, indicator_type, indicator_value)`, TTL-based) — when caching is added later, that Protocol is the contract to implement against; nothing in this plan needs to change to slot it in (the registry gains a cache-check line at the top of `enrich()` and a cache-write line before returning a fresh result).
- This also *removes* an open technical risk the original version of this doc flagged: whether a second SQLModel table needs its own metadata/engine to stay physically separate from `AlertStore`'s tables. That question doesn't arise until caching comes back.

---

## 1. File Structure

```
app/enrichment/
  __init__.py
  indicators.py      # IPIndicator (validated Pydantic model) + Indicator type alias
  errors.py          # EnrichmentError and its typed variant kinds
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

## 4. Rate Limiter

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

## 5. AbuseIPDB Provider

```python
# app/enrichment/providers/abuseipdb.py
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

        data = response.json()["data"]
        score = float(data["abuseConfidenceScore"])
        verdict = (
            EnrichmentVerdict.MALICIOUS if score > ABUSEIPDB_MALICIOUS_THRESHOLD
            else EnrichmentVerdict.SUSPICIOUS if score > ABUSEIPDB_SUSPICIOUS_THRESHOLD
            else EnrichmentVerdict.CLEAN
        )
        # queried_at/cache_expires_at, indicator_type/indicator_value, provider_id, raw_response
        # are all filled in by the caller (EnrichmentRegistry), per the plan's task breakdown —
        # this method returns the provider-specific parts (score, verdict, raw payload) and the
        # registry assembles the full EnrichmentResult. Exact split finalized in the implementation plan.
        ...
```

`cache_expires_at` remains a required field on `EnrichmentResult` (it's part of the Foundation schema, unchanged) even though nothing reads it in this plan — the registry can set it to a placeholder value (e.g. `queried_at`, meaning "already expired") until caching lands and gives it a real meaning. The implementation plan should make this explicit rather than leaving it implicit.

---

## 6. Registry

```python
# app/enrichment/registry.py
from datetime import datetime, timezone

from app.enrichment.errors import EnrichmentError
from app.enrichment.indicators import Indicator
from app.enrichment.rate_limiter import DailyRateLimiter
from app.schemas import EnrichmentResult, EnrichmentVerdict, IndicatorType

_DAILY_LIMITS = {"abuseipdb": 1000}

class EnrichmentRegistry:
    def __init__(self) -> None:
        self._providers: dict[IndicatorType, list] = {}
        self._limiters: dict[str, DailyRateLimiter] = {}

    def register(self, provider) -> None:
        for t in provider.supported_types:
            self._providers.setdefault(t, []).append(provider)
        self._limiters[provider.provider_id] = DailyRateLimiter(_DAILY_LIMITS[provider.provider_id])

    def providers_for(self, indicator_type: IndicatorType) -> list:
        return list(self._providers.get(indicator_type, []))

    def enrich(self, indicator: Indicator) -> EnrichmentResult:
        for provider in self.providers_for(indicator.indicator_type):
            limiter = self._limiters[provider.provider_id]
            if not limiter.try_acquire():
                return EnrichmentResult(
                    indicator_type=indicator.indicator_type, indicator_value=indicator.value,
                    provider_id=provider.provider_id, queried_at=datetime.now(timezone.utc),
                    verdict=EnrichmentVerdict.UNKNOWN, score=0.0,
                    cache_expires_at=datetime.now(timezone.utc), error="rate_limited",
                )

            try:
                return provider.lookup(indicator)
            except EnrichmentError as exc:
                return EnrichmentResult(
                    indicator_type=indicator.indicator_type, indicator_value=indicator.value,
                    provider_id=provider.provider_id, queried_at=datetime.now(timezone.utc),
                    verdict=EnrichmentVerdict.UNKNOWN, score=0.0,
                    cache_expires_at=datetime.now(timezone.utc), error=exc.kind,
                )

        raise ValueError(f"no provider registered for {indicator.indicator_type}")
```

`enrich()` returns the **first** registered provider's result for a given type (priority order == registration order), matching CLAUDE.md §5's "call each candidate in priority order" — this slice registers exactly one provider (AbuseIPDB) for `IP`, so multi-provider fallback behavior (try provider 2 if provider 1 errors) is a design question for when a second IP-capable provider (e.g. VirusTotal) is actually added, not invented speculatively here.

---

## 7. Error Handling Summary

| Situation | Behavior |
|---|---|
| Rate limit exhausted | Return `EnrichmentResult(verdict=UNKNOWN, error="rate_limited")`, no exception raised past the registry |
| Provider timeout / auth failure / not found | Same shape, `error=<kind>` |
| Provider returns a real result | Returned as-is (no caching in this plan) |
| No provider registered for the indicator's type | `ValueError` — a real programming error (registry misconfiguration), not a runtime data issue, so it's fine for this one to raise |

---

## 8. Testing

- **`AbuseIPDBProvider`**: `respx`-mocked `httpx` responses for the 200/401/404/429/timeout cases, asserting the correct `EnrichmentResult`/`EnrichmentError` for each.
- **`DailyRateLimiter`**: unit tests for exhaustion and window-rollover (the latter needs a way to inject/mock "today" — the plan's Global Constraints should pick one mechanism explicitly, e.g. `freezegun`, so each task doesn't invent its own).
- **`EnrichmentRegistry`**: unit tests with a fake provider (no real HTTP), covering rate-limited, provider-error, and happy-path branches.
- **Integration-ish test**: `AbuseIPDBProvider` + `EnrichmentRegistry` wired together, still with `respx`-mocked HTTP — confirms the pieces compose, without touching the real network.

---

## Open Items for the Implementation Plan

1. Exact field-assembly split between `AbuseIPDBProvider.lookup()` and `EnrichmentRegistry.enrich()` (who sets `queried_at`, `provider_id`, `cache_expires_at`, etc. on the returned `EnrichmentResult`) should be nailed down to one consistent approach in the plan's actual code blocks.
2. Verdict thresholds (75/25) are already named constants above — carry them through as-is.
3. A time-mocking approach for `DailyRateLimiter`'s window-rollover test should be picked once and stated in Global Constraints (`freezegun` is already a CLAUDE.md §6 recommendation).
4. When caching is added later (see Non-Goals), it's a small, separate follow-up plan — not a gap in this one.
