# Enrichment Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Enrichment module's core path — a typed IP indicator, a typed error model, an in-memory per-provider daily rate limiter, a live AbuseIPDB provider, and the registry that wires them together — with caching deliberately deferred to a later plan.

**Architecture:** `EnrichmentRegistry` holds one or more `EnrichmentProvider`-shaped objects per `IndicatorType`, plus one `DailyRateLimiter` per registered provider. `enrich(indicator)` picks the highest-priority provider for that indicator's type, checks its rate limiter, calls `provider.lookup(indicator)`, and returns whatever `EnrichmentResult` comes back — degrading to a synthetic `verdict=UNKNOWN` result (never raising past the registry) on either rate-limit exhaustion or a typed `EnrichmentError` from the provider. `AbuseIPDBProvider` is the one live provider in this plan: it owns its own `httpx.Client`, translates AbuseIPDB's response/HTTP-status shape into `EnrichmentResult`/`EnrichmentError`, and is fully testable against `respx`-mocked HTTP with no real network access or API key.

**Tech Stack:** Python 3.11+, Pydantic v2 (existing), `httpx` (new), `respx` + `freezegun` (new, test-only).

## Global Constraints

- Python >= 3.11 (existing project constraint).
- New dependencies: `httpx>=0.27,<1` (runtime); `respx>=0.21,<1`, `freezegun>=1.4,<2` (dev/test only).
- **Caching is out of scope for this plan.** `EnrichmentRegistry.enrich()` calls its provider on every invocation (after the rate-limit check) — no `EnrichmentCache` Protocol, no cache SQLite file, no TTL logic. This is a deliberate prototype-scoping decision (see `docs/superpowers/specs/2026-08-09-enrichment-module-design.md`), not a gap to fill in this plan.
- **Single-provider, no cross-provider fallback in this plan.** `EnrichmentRegistry` registers providers per `IndicatorType` and always uses the highest-priority (first-registered) one; trying a second provider after the first errors is out of scope until a second IP-capable provider actually exists.
- This is a POC per CLAUDE.md §8 — no real API keys anywhere in code, tests, or fixtures. All provider tests use `respx`-mocked HTTP.
- TDD: every method/model gets a failing test before implementation.
- Commit after each task.
- Test file naming follows the existing flat `tests/` convention (no subpackages) — e.g. `tests/test_enrichment_indicators.py`, matching `tests/test_schemas.py` etc. already in the repo.

---

### Task 1: Add httpx/respx/freezegun dependencies

**Files:**
- Modify: `pyproject.toml`

**Interfaces:**
- Produces: `httpx`, `respx`, `freezegun` importable in the venv — consumed by every later task in this plan.

- [ ] **Step 1: Add the new dependencies**

In `pyproject.toml`, change:

```toml
dependencies = [
    "pydantic>=2.6,<3",
    "pydantic-settings>=2.2,<3",
    "sqlalchemy>=2.0,<3",  # imported directly for IntegrityError; also a sqlmodel dep
    "sqlmodel>=0.0.16,<0.1",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0,<9",
]
```

to:

```toml
dependencies = [
    "pydantic>=2.6,<3",
    "pydantic-settings>=2.2,<3",
    "sqlalchemy>=2.0,<3",  # imported directly for IntegrityError; also a sqlmodel dep
    "sqlmodel>=0.0.16,<0.1",
    "httpx>=0.27,<1",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0,<9",
    "respx>=0.21,<1",
    "freezegun>=1.4,<2",
]
```

- [ ] **Step 2: Reinstall**

```bash
source .venv/bin/activate
pip install -e ".[dev]"
```

- [ ] **Step 3: Verify**

```bash
python -c "import httpx, respx, freezegun; print('ok')"
```

Expected: `ok` printed, no import errors.

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "chore: add httpx/respx/freezegun dependencies for the Enrichment module"
```

---

### Task 2: Indicator typing (`IPIndicator`)

**Files:**
- Create: `app/enrichment/__init__.py`
- Create: `app/enrichment/indicators.py`
- Test: `tests/test_enrichment_indicators.py`

**Interfaces:**
- Consumes: `IndicatorType` (from `app/schemas.py`, existing).
- Produces: `IPIndicator(BaseModel)`, `Indicator` (type alias, currently `= IPIndicator`) — consumed by Tasks 6, 7, 8.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_enrichment_indicators.py
import pytest
from pydantic import ValidationError

from app.enrichment.indicators import IPIndicator
from app.schemas import IndicatorType


def test_valid_ipv4_indicator():
    indicator = IPIndicator(value="192.168.1.1")
    assert indicator.value == "192.168.1.1"
    assert indicator.indicator_type == IndicatorType.IP


def test_rejects_non_numeric_value():
    with pytest.raises(ValidationError):
        IPIndicator(value="abc.def.ghi.jkl")


def test_rejects_too_few_octets():
    with pytest.raises(ValidationError):
        IPIndicator(value="1.2.3")


def test_rejects_out_of_range_octet():
    with pytest.raises(ValidationError):
        IPIndicator(value="256.1.1.1")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mkdir -p app/enrichment
touch app/enrichment/__init__.py
pytest tests/test_enrichment_indicators.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.enrichment.indicators'`

- [ ] **Step 3: Write minimal implementation**

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


Indicator = IPIndicator
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_indicators.py -v
```

Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/__init__.py app/enrichment/indicators.py tests/test_enrichment_indicators.py
git commit -m "feat: add IPIndicator with strict IPv4 validation"
```

---

### Task 3: Typed enrichment errors

**Files:**
- Create: `app/enrichment/errors.py`
- Test: `tests/test_enrichment_errors.py`

**Interfaces:**
- Produces: `EnrichmentError(Exception)` with a `.kind` attribute (`"rate_limited" | "auth_failed" | "not_found" | "timeout"`) — consumed by Tasks 6 and 7.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_enrichment_errors.py
import pytest

from app.enrichment.errors import EnrichmentError


def test_enrichment_error_carries_kind_and_message():
    error = EnrichmentError("rate_limited", "AbuseIPDB rate limit exceeded")
    assert error.kind == "rate_limited"
    assert str(error) == "AbuseIPDB rate limit exceeded"


def test_enrichment_error_is_an_exception():
    with pytest.raises(EnrichmentError):
        raise EnrichmentError("timeout", "took too long")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_enrichment_errors.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.enrichment.errors'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/enrichment/errors.py
class EnrichmentError(Exception):
    def __init__(self, kind: str, message: str):
        self.kind = kind  # "rate_limited" | "auth_failed" | "not_found" | "timeout"
        super().__init__(message)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_errors.py -v
```

Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/errors.py tests/test_enrichment_errors.py
git commit -m "feat: add typed EnrichmentError"
```

---

### Task 4: Config extension — AbuseIPDB API key

**Files:**
- Modify: `app/config.py`
- Modify: `.env.example`
- Modify: `tests/test_config.py`

**Interfaces:**
- Consumes: `Settings` (existing, in `app/config.py`).
- Produces: `Settings.abuseipdb_api_key: str | None` — consumed by Task 6's provider construction (wired up wherever the app composes the registry — outside this plan's scope, but the field must exist and load from `ABUSEIPDB_API_KEY`).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config.py`:

```python
def test_settings_abuseipdb_api_key_defaults_to_none():
    settings = Settings(_env_file=None)
    assert settings.abuseipdb_api_key is None


def test_settings_abuseipdb_api_key_env_override(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key-123")
    settings = Settings(_env_file=None)
    assert settings.abuseipdb_api_key == "test-key-123"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_config.py -v
```

Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'abuseipdb_api_key'`

- [ ] **Step 3: Write minimal implementation**

In `app/config.py`, change:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_path: str = "./data/alerts.db"
    log_level: str = "INFO"
```

to:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_path: str = "./data/alerts.db"
    log_level: str = "INFO"
    abuseipdb_api_key: str | None = None
```

In `.env.example`, change:

```
# Copy to .env and fill in real values. No secrets or real credentials belong in this file.
DATABASE_PATH=./data/alerts.db
LOG_LEVEL=INFO
```

to:

```
# Copy to .env and fill in real values. No secrets or real credentials belong in this file.
DATABASE_PATH=./data/alerts.db
LOG_LEVEL=INFO
ABUSEIPDB_API_KEY=
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_config.py -v
```

Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/config.py .env.example tests/test_config.py
git commit -m "feat: add abuseipdb_api_key to Settings"
```

---

### Task 5: Daily rate limiter

**Files:**
- Create: `app/enrichment/rate_limiter.py`
- Test: `tests/test_enrichment_rate_limiter.py`

**Interfaces:**
- Produces: `DailyRateLimiter(daily_limit: int)` with `.try_acquire() -> bool` — consumed by Task 7.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_enrichment_rate_limiter.py
from freezegun import freeze_time

from app.enrichment.rate_limiter import DailyRateLimiter


def test_allows_up_to_daily_limit():
    limiter = DailyRateLimiter(daily_limit=3)
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False


def test_resets_on_new_day():
    limiter = DailyRateLimiter(daily_limit=2)
    with freeze_time("2026-08-09"):
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is True
        assert limiter.try_acquire() is False

    with freeze_time("2026-08-10"):
        assert limiter.try_acquire() is True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_enrichment_rate_limiter.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.enrichment.rate_limiter'`

- [ ] **Step 3: Write minimal implementation**

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

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_rate_limiter.py -v
```

Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/rate_limiter.py tests/test_enrichment_rate_limiter.py
git commit -m "feat: add in-memory DailyRateLimiter"
```

---

### Task 6: AbuseIPDB provider

**Files:**
- Create: `app/enrichment/providers/__init__.py`
- Create: `app/enrichment/providers/abuseipdb.py`
- Test: `tests/test_enrichment_abuseipdb_provider.py`

**Interfaces:**
- Consumes: `IPIndicator` (Task 2), `EnrichmentError` (Task 3), `EnrichmentResult`/`EnrichmentVerdict`/`IndicatorType` (existing, `app/schemas.py`).
- Produces: `AbuseIPDBProvider(api_key: str, client: httpx.Client | None = None)` with `.provider_id`, `.supported_types`, `.lookup(indicator: IPIndicator) -> EnrichmentResult` — consumed by Tasks 7 and 8.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_enrichment_abuseipdb_provider.py
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mkdir -p app/enrichment/providers
touch app/enrichment/providers/__init__.py
pytest tests/test_enrichment_abuseipdb_provider.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.enrichment.providers.abuseipdb'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/enrichment/providers/abuseipdb.py
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
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_abuseipdb_provider.py -v
```

Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/providers/__init__.py app/enrichment/providers/abuseipdb.py tests/test_enrichment_abuseipdb_provider.py
git commit -m "feat: add AbuseIPDBProvider"
```

---

### Task 7: Enrichment registry

**Files:**
- Create: `app/enrichment/registry.py`
- Test: `tests/test_enrichment_registry.py`

**Interfaces:**
- Consumes: `EnrichmentError` (Task 3), `Indicator`/`IPIndicator` (Task 2), `DailyRateLimiter` (Task 5), `EnrichmentResult`/`EnrichmentVerdict`/`IndicatorType` (existing).
- Produces: `EnrichmentRegistry` with `.register(provider) -> None`, `.providers_for(indicator_type) -> list`, `.enrich(indicator) -> EnrichmentResult` — consumed by Task 8 and by the (out-of-scope-for-this-plan) Agentic Analyst wiring later.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_enrichment_registry.py
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_enrichment_registry.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.enrichment.registry'`

- [ ] **Step 3: Write minimal implementation**

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
        for indicator_type in provider.supported_types:
            self._providers.setdefault(indicator_type, []).append(provider)
        self._limiters[provider.provider_id] = DailyRateLimiter(_DAILY_LIMITS[provider.provider_id])

    def providers_for(self, indicator_type: IndicatorType) -> list:
        return list(self._providers.get(indicator_type, []))

    def enrich(self, indicator: Indicator) -> EnrichmentResult:
        providers = self.providers_for(indicator.indicator_type)
        if not providers:
            raise ValueError(f"no provider registered for {indicator.indicator_type}")

        # Highest-priority (first-registered) provider only — cross-provider fallback
        # on error is out of scope until a second IP-capable provider exists.
        provider = providers[0]
        limiter = self._limiters[provider.provider_id]
        if not limiter.try_acquire():
            return EnrichmentResult(
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                provider_id=provider.provider_id,
                queried_at=datetime.now(timezone.utc),
                verdict=EnrichmentVerdict.UNKNOWN,
                score=0.0,
                cache_expires_at=datetime.now(timezone.utc),
                error="rate_limited",
            )

        try:
            return provider.lookup(indicator)
        except EnrichmentError as exc:
            return EnrichmentResult(
                indicator_type=indicator.indicator_type,
                indicator_value=indicator.value,
                provider_id=provider.provider_id,
                queried_at=datetime.now(timezone.utc),
                verdict=EnrichmentVerdict.UNKNOWN,
                score=0.0,
                cache_expires_at=datetime.now(timezone.utc),
                error=exc.kind,
            )
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_registry.py -v
```

Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/registry.py tests/test_enrichment_registry.py
git commit -m "feat: add EnrichmentRegistry"
```

---

### Task 8: End-to-end composition test

**Files:**
- Test: `tests/test_enrichment_integration.py`

**Interfaces:**
- Consumes: `EnrichmentRegistry` (Task 7), `AbuseIPDBProvider` (Task 6), `IPIndicator` (Task 2) — no new production code, this task only adds a test.

- [ ] **Step 1: Write the test**

```python
# tests/test_enrichment_integration.py
import httpx
import respx

from app.enrichment.indicators import IPIndicator
from app.enrichment.providers.abuseipdb import AbuseIPDBProvider
from app.enrichment.registry import EnrichmentRegistry
from app.schemas import EnrichmentVerdict

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"


@respx.mock
def test_registry_and_provider_compose_end_to_end():
    respx.get(CHECK_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "ipAddress": "203.0.113.5"}})
    )
    registry = EnrichmentRegistry()
    registry.register(AbuseIPDBProvider(api_key="test-key"))

    result = registry.enrich(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.MALICIOUS
    assert result.provider_id == "abuseipdb"


@respx.mock
def test_registry_degrades_gracefully_on_provider_auth_failure():
    respx.get(CHECK_URL).mock(return_value=httpx.Response(401, json={"errors": [{"detail": "invalid key"}]}))
    registry = EnrichmentRegistry()
    registry.register(AbuseIPDBProvider(api_key="bad-key"))

    result = registry.enrich(IPIndicator(value="203.0.113.5"))

    assert result.verdict == EnrichmentVerdict.UNKNOWN
    assert result.error == "auth_failed"
```

- [ ] **Step 2: Run the full test suite**

```bash
pytest -v
```

Expected: PASS — all tests in the repo, old and new (Foundation's 29 plus this plan's new tests).

- [ ] **Step 3: Commit**

```bash
git add tests/test_enrichment_integration.py
git commit -m "test: add end-to-end EnrichmentRegistry + AbuseIPDBProvider composition test"
```
