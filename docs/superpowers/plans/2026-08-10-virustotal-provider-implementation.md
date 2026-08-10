# VirusTotal Provider + Multi-Type Indicators (Phase 2b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `HashIndicator`/`DomainIndicator`/`URLIndicator` and a `VirusTotalProvider` covering `DOMAIN`/`FILE_HASH`/`URL`, so one alert's extracted indicators can be routed by type to their own dedicated provider (`IP → AbuseIPDB`, everything else → VirusTotal) — no reconciliation logic, no registry changes.

**Architecture:** `VirusTotalProvider` mirrors `AbuseIPDBProvider`'s exact shape (constructor, `lookup()`, the same `EnrichmentError` kind vocabulary: `timeout | network_error | auth_failed | rate_limited | not_found | http_error | bad_response`) but branches internally on `indicator.indicator_type` to build the right VirusTotal endpoint path (`/domains/{value}`, `/files/{value}`, or `/urls/{base64_id}`), then derives a verdict from `last_analysis_stats`' absolute engine counts rather than a single confidence score. `EnrichmentRegistry` needs zero code changes — registering a multi-type provider already routes each type to its own list via existing code.

**Tech Stack:** Python 3.11+, `httpx` + `respx` (both already dependencies) — no new dependencies.

## Global Constraints

- No new dependencies.
- Verdict thresholds (`malicious >= 5` → `MALICIOUS`; `malicious >= 1` or `suspicious >= 1` → `SUSPICIOUS`; otherwise `CLEAN`) are this project's own explicit decision — VirusTotal publishes no official recommendation. Do not treat these as vendor guidance if revisiting later.
- `EMAIL` (the fifth `IndicatorType` member) stays unenriched in this plan — no provider covers it, and this plan does not add one.
- `DailyRateLimiter` stays daily-only (no per-minute modeling) — VirusTotal's real ~4/min limit is tighter relative to per-alert call volume than AbuseIPDB's, but fixing that is out of scope here, consistent with Phase 2's existing simplification.
- The domain-validation regex is a deliberately-scoped pattern, not a full RFC 1035 parser — don't over-invest in edge cases (IDN/punycode) beyond rejecting obviously-malformed input.
- No real API keys/credentials anywhere — all tests are `respx`-mocked.
- TDD: every method/model gets a failing test before implementation.
- Commit after each task.

---

### Task 1: New indicator types

**Files:**
- Modify: `app/enrichment/indicators.py`
- Modify: `tests/test_enrichment_indicators.py`

**Interfaces:**
- Consumes: `IndicatorType` (existing, `app/schemas.py`).
- Produces: `HashIndicator`, `DomainIndicator`, `URLIndicator` (all `BaseModel`), and widens `Indicator` to `IPIndicator | HashIndicator | DomainIndicator | URLIndicator` — consumed by Tasks 3-7.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_enrichment_indicators.py`:

```python
from app.enrichment.indicators import DomainIndicator, HashIndicator, URLIndicator


def test_accepts_valid_md5_sha1_sha256_hashes():
    assert HashIndicator(value="a" * 32).value == "a" * 32
    assert HashIndicator(value="a" * 40).value == "a" * 40
    assert HashIndicator(value="a" * 64).value == "a" * 64


def test_hash_indicator_lowercases_value():
    indicator = HashIndicator(value="A" * 32)
    assert indicator.value == "a" * 32
    assert indicator.indicator_type == IndicatorType.FILE_HASH


def test_rejects_wrong_length_hash():
    with pytest.raises(ValidationError):
        HashIndicator(value="a" * 31)


def test_rejects_non_hex_hash():
    with pytest.raises(ValidationError):
        HashIndicator(value="g" * 32)


def test_accepts_valid_domain():
    indicator = DomainIndicator(value="example.com")
    assert indicator.value == "example.com"
    assert indicator.indicator_type == IndicatorType.DOMAIN


def test_domain_indicator_lowercases_value():
    assert DomainIndicator(value="EXAMPLE.COM").value == "example.com"


def test_accepts_subdomain():
    assert DomainIndicator(value="sub.example.co.uk").value == "sub.example.co.uk"


def test_rejects_malformed_domain():
    with pytest.raises(ValidationError):
        DomainIndicator(value="not a domain!")


def test_rejects_domain_starting_with_hyphen():
    with pytest.raises(ValidationError):
        DomainIndicator(value="-example.com")


def test_accepts_valid_https_url():
    indicator = URLIndicator(value="https://example.com/path")
    assert indicator.value == "https://example.com/path"
    assert indicator.indicator_type == IndicatorType.URL


def test_accepts_valid_http_url():
    assert URLIndicator(value="http://example.com").value == "http://example.com"


def test_rejects_non_http_scheme():
    with pytest.raises(ValidationError):
        URLIndicator(value="ftp://example.com")


def test_rejects_url_without_host():
    with pytest.raises(ValidationError):
        URLIndicator(value="https://")
```

Add `import pytest`, `from pydantic import ValidationError`, `from app.schemas import IndicatorType` to the top of the file if not already present (they already are, per the existing `IPIndicator` tests).

- [ ] **Step 2: Run test to verify it fails**

```bash
source .venv/bin/activate
pytest tests/test_enrichment_indicators.py -v
```

Expected: FAIL with `ImportError: cannot import name 'HashIndicator' from 'app.enrichment.indicators'`

- [ ] **Step 3: Write minimal implementation**

Update the import block at the top of `app/enrichment/indicators.py`:

```python
import ipaddress
import re
import urllib.parse

from pydantic import BaseModel, field_validator

from app.schemas import IndicatorType
```

Append to `app/enrichment/indicators.py` (before the existing `Indicator = IPIndicator` line — replace that line as shown in Step 3's last block):

```python
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
```

Replace the final line of the file:

```python
Indicator = IPIndicator
```

with:

```python
Indicator = IPIndicator | HashIndicator | DomainIndicator | URLIndicator
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_indicators.py -v
```

Expected: PASS (20 tests: 8 existing `IPIndicator` + 12 new)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/indicators.py tests/test_enrichment_indicators.py
git commit -m "feat: add HashIndicator, DomainIndicator, URLIndicator"
```

---

### Task 2: VirusTotal config setting

**Files:**
- Modify: `app/config.py`
- Modify: `.env.example`
- Modify: `tests/test_config.py`

**Interfaces:**
- Produces: `Settings.virustotal_api_key: str | None = None` — consumed by Task 3 (`VirusTotalProvider` construction, in a real deployment — not by any test in this plan, matching `abuseipdb_api_key`'s existing pattern of being read only outside the test suite).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config.py`:

```python
def test_settings_virustotal_api_key_defaults_to_none():
    settings = Settings(_env_file=None)
    assert settings.virustotal_api_key is None


def test_settings_virustotal_api_key_env_override(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    settings = Settings(_env_file=None)
    assert settings.virustotal_api_key == "test-vt-key"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_config.py -v
```

Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'virustotal_api_key'`

- [ ] **Step 3: Write minimal implementation**

In `app/config.py`, change:

```python
    abuseipdb_api_key: str | None = None
```

to:

```python
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
```

In `.env.example`, change:

```
ABUSEIPDB_API_KEY=
```

to:

```
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_config.py -v
```

Expected: PASS (all config tests, +2 new)

- [ ] **Step 5: Commit**

```bash
git add app/config.py .env.example tests/test_config.py
git commit -m "feat: add virustotal_api_key to Settings"
```

---

### Task 3: `VirusTotalProvider` — construction and domain lookup

**Files:**
- Create: `app/enrichment/providers/virustotal.py`
- Test: `tests/test_enrichment_virustotal_provider.py`

**Interfaces:**
- Consumes: `EnrichmentError` (existing), `DomainIndicator`/`HashIndicator`/`URLIndicator` (Task 1).
- Produces: `VirusTotalProvider(api_key, client=None)` with `.provider_id`, `.supported_types`, `.lookup()` implemented for the domain happy-path (malicious/suspicious/clean verdict derivation) — consumed by Tasks 4-7.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_enrichment_virustotal_provider.py
import httpx
import respx

from app.enrichment.indicators import DomainIndicator
from app.enrichment.providers.virustotal import VirusTotalProvider
from app.schemas import EnrichmentVerdict

DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/example.com"


def _domain_response(malicious: int, suspicious: int = 0, harmless: int = 10, undetected: int = 5) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "id": "example.com",
                "type": "domain",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                        "timeout": 0,
                    }
                },
            }
        },
    )


@respx.mock
def test_lookup_returns_malicious_verdict_at_five_or_more_engines():
    respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=5))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(DomainIndicator(value="example.com"))

    assert result.verdict == EnrichmentVerdict.MALICIOUS
    assert result.provider_id == "virustotal"
    assert result.indicator_value == "example.com"
    assert result.error is None


@respx.mock
def test_lookup_returns_suspicious_verdict_below_five_malicious():
    respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=2))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(DomainIndicator(value="example.com"))

    assert result.verdict == EnrichmentVerdict.SUSPICIOUS


@respx.mock
def test_lookup_returns_suspicious_verdict_on_suspicious_only():
    respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=0, suspicious=1))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(DomainIndicator(value="example.com"))

    assert result.verdict == EnrichmentVerdict.SUSPICIOUS


@respx.mock
def test_lookup_returns_clean_verdict_when_no_engines_flag_it():
    respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=0, suspicious=0))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(DomainIndicator(value="example.com"))

    assert result.verdict == EnrichmentVerdict.CLEAN
    assert result.score == 0.0


@respx.mock
def test_lookup_sends_api_key_header():
    route = respx.get(DOMAIN_URL).mock(return_value=_domain_response(malicious=0))
    provider = VirusTotalProvider(api_key="test-key")

    provider.lookup(DomainIndicator(value="example.com"))

    assert route.calls.last.request.headers["x-apikey"] == "test-key"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mkdir -p app/enrichment/providers  # already exists from Phase 2, harmless if so
pytest tests/test_enrichment_virustotal_provider.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.enrichment.providers.virustotal'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/enrichment/providers/virustotal.py
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
```

Note: error handling (timeout/network_error/auth_failed/rate_limited/not_found/http_error/bad_response) is deliberately not yet implemented — that's Task 5. This task's `response.json()` etc. will raise raw exceptions on any non-happy-path input; the tests above only exercise the happy path, so this is expected and not a gap in this task's own scope.

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_virustotal_provider.py -v
```

Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/providers/virustotal.py tests/test_enrichment_virustotal_provider.py
git commit -m "feat: add VirusTotalProvider construction and domain lookup"
```

---

### Task 4: `VirusTotalProvider` — file hash and URL lookup

**Files:**
- Modify: `app/enrichment/providers/virustotal.py`
- Modify: `tests/test_enrichment_virustotal_provider.py`

**Interfaces:**
- Produces: `_path_for()` fully implemented for all three types, including URL's base64-ID encoding.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_enrichment_virustotal_provider.py`:

```python
import base64

from app.enrichment.indicators import HashIndicator, URLIndicator

FILE_URL = f"https://www.virustotal.com/api/v3/files/{'a' * 64}"


def _file_response(malicious: int) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "id": "a" * 64,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": 0,
                        "harmless": 10,
                        "undetected": 5,
                        "timeout": 0,
                        "confirmed-timeout": 0,
                        "failure": 0,
                        "type-unsupported": 0,
                    }
                },
            }
        },
    )


@respx.mock
def test_lookup_hash_indicator_queries_files_endpoint():
    respx.get(FILE_URL).mock(return_value=_file_response(malicious=6))
    provider = VirusTotalProvider(api_key="test-key")

    result = provider.lookup(HashIndicator(value="a" * 64))

    assert result.verdict == EnrichmentVerdict.MALICIOUS
    assert result.indicator_value == "a" * 64


def test_url_lookup_uses_unpadded_base64_id():
    raw_url = "https://example.com/malware.exe"
    expected_id = base64.urlsafe_b64encode(raw_url.encode()).decode().rstrip("=")
    url_endpoint = f"https://www.virustotal.com/api/v3/urls/{expected_id}"

    with respx.mock:
        respx.get(url_endpoint).mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": {
                        "id": expected_id,
                        "type": "url",
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 0,
                                "suspicious": 0,
                                "harmless": 10,
                                "undetected": 5,
                                "timeout": 0,
                            }
                        },
                    }
                },
            )
        )
        provider = VirusTotalProvider(api_key="test-key")

        result = provider.lookup(URLIndicator(value=raw_url))

        assert result.verdict == EnrichmentVerdict.CLEAN
        assert result.indicator_value == raw_url
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_enrichment_virustotal_provider.py -v
```

Expected: FAIL — `test_url_lookup_uses_unpadded_base64_id` fails with `NotImplementedError: URL lookup added in Task 4`. `test_lookup_hash_indicator_queries_files_endpoint` should already PASS, since `_path_for`'s `FILE_HASH` branch was written in Task 3 — confirm this rather than assuming; if it unexpectedly fails, investigate before proceeding.

- [ ] **Step 3: Write minimal implementation**

Update the import block at the top of `app/enrichment/providers/virustotal.py`:

```python
import base64
from datetime import datetime, timezone

import httpx

from app.enrichment.errors import EnrichmentError
from app.enrichment.indicators import DomainIndicator, HashIndicator, URLIndicator
from app.schemas import EnrichmentResult, EnrichmentVerdict, IndicatorType
```

Replace the `_path_for` method body:

```python
    def _path_for(self, indicator: DomainIndicator | HashIndicator | URLIndicator) -> str:
        if indicator.indicator_type == IndicatorType.DOMAIN:
            return f"/domains/{indicator.value}"
        if indicator.indicator_type == IndicatorType.FILE_HASH:
            return f"/files/{indicator.value}"
        url_id = base64.urlsafe_b64encode(indicator.value.encode()).decode().rstrip("=")
        return f"/urls/{url_id}"
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_virustotal_provider.py -v
```

Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/providers/virustotal.py tests/test_enrichment_virustotal_provider.py
git commit -m "feat: implement VirusTotalProvider file hash and URL lookup paths"
```

---

### Task 5: `VirusTotalProvider` — error mapping

**Files:**
- Modify: `app/enrichment/providers/virustotal.py`
- Modify: `tests/test_enrichment_virustotal_provider.py`

**Interfaces:**
- Produces: full `EnrichmentError` mapping matching `AbuseIPDBProvider`'s vocabulary — `timeout`, `network_error`, `auth_failed`, `rate_limited`, `not_found`, `http_error`, `bad_response`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_enrichment_virustotal_provider.py`:

```python
import pytest

from app.enrichment.errors import EnrichmentError


@respx.mock
def test_lookup_raises_auth_failed_on_401():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(401, json={"error": {"code": "WrongCredentialsError"}}))
    provider = VirusTotalProvider(api_key="bad-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "auth_failed"


@respx.mock
def test_lookup_raises_not_found_on_404():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(404, json={"error": {"code": "NotFoundError"}}))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "not_found"


@respx.mock
def test_lookup_raises_rate_limited_on_429():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(429, json={"error": {"code": "QuotaExceededError"}}))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "rate_limited"


@respx.mock
def test_lookup_raises_http_error_on_500():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(500, text="internal server error"))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "http_error"


@respx.mock
def test_lookup_raises_timeout_on_client_timeout():
    respx.get(DOMAIN_URL).mock(side_effect=httpx.TimeoutException("timed out"))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "timeout"


@respx.mock
def test_lookup_raises_network_error_on_connect_error():
    respx.get(DOMAIN_URL).mock(side_effect=httpx.ConnectError("connection refused"))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "network_error"


@respx.mock
def test_lookup_raises_bad_response_on_malformed_body():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(200, json={"unexpected": "shape"}))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "bad_response"


@respx.mock
def test_lookup_raises_bad_response_on_non_json_body():
    respx.get(DOMAIN_URL).mock(return_value=httpx.Response(200, text="<html>not json</html>"))
    provider = VirusTotalProvider(api_key="test-key")

    with pytest.raises(EnrichmentError) as exc_info:
        provider.lookup(DomainIndicator(value="example.com"))
    assert exc_info.value.kind == "bad_response"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_enrichment_virustotal_provider.py -v
```

Expected: FAIL — all 8 new tests fail because `lookup()` currently has no exception handling at all (raw `httpx`/`json` exceptions, or no exception at all for status codes it doesn't check).

- [ ] **Step 3: Write minimal implementation**

Replace the `lookup` method body in `app/enrichment/providers/virustotal.py`:

```python
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
```

(`json.JSONDecodeError` is a `ValueError` subclass, so the non-JSON-body test is covered by the same `except` clause as the malformed-body test — matching `AbuseIPDBProvider`'s established pattern exactly.)

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_virustotal_provider.py -v
```

Expected: PASS (15 tests)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/providers/virustotal.py tests/test_enrichment_virustotal_provider.py
git commit -m "feat: add full EnrichmentError mapping to VirusTotalProvider"
```

---

### Task 6: Registry wiring

**Files:**
- Modify: `app/enrichment/registry.py`
- Modify: `tests/test_enrichment_registry.py`

**Interfaces:**
- Produces: `_DAILY_LIMITS["virustotal"] = 500`; a test proving the registry routes multiple distinct indicator types to their own single provider each, with zero other registry code changes.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_enrichment_registry.py`:

```python
class _FakeVirusTotalProvider:
    provider_id = "virustotal"
    supported_types = frozenset({IndicatorType.DOMAIN, IndicatorType.FILE_HASH, IndicatorType.URL})

    def lookup(self, indicator):
        raise AssertionError("not exercised in this test")


def test_registering_two_providers_routes_each_type_to_its_own_provider():
    ip_provider = _FakeProvider(result=_make_result())
    vt_provider = _FakeVirusTotalProvider()
    registry = EnrichmentRegistry()
    registry.register(ip_provider)
    registry.register(vt_provider)

    assert registry.providers_for(IndicatorType.IP) == [ip_provider]
    assert registry.providers_for(IndicatorType.DOMAIN) == [vt_provider]
    assert registry.providers_for(IndicatorType.FILE_HASH) == [vt_provider]
    assert registry.providers_for(IndicatorType.URL) == [vt_provider]
    assert registry.providers_for(IndicatorType.EMAIL) == []
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_enrichment_registry.py -v
```

Expected: FAIL — `KeyError: 'virustotal'` from `DailyRateLimiter(_DAILY_LIMITS[provider.provider_id])` inside `register()`, since `_DAILY_LIMITS` doesn't have a `"virustotal"` entry yet.

- [ ] **Step 3: Write minimal implementation**

In `app/enrichment/registry.py`, change:

```python
_DAILY_LIMITS = {"abuseipdb": 1000}
```

to:

```python
_DAILY_LIMITS = {"abuseipdb": 1000, "virustotal": 500}
```

Also update the stale comment above the `provider = providers[0]` line in `enrich()` — change:

```python
        # Highest-priority (first-registered) provider only — cross-provider fallback
        # on error is out of scope until a second IP-capable provider exists.
```

to:

```python
        # Highest-priority (first-registered) provider only — this project's design
        # keeps exactly one provider per indicator type (routing is by type, not by
        # competing providers within a type), so this is always the sole registered
        # provider for indicator.indicator_type, not an arbitrary "first of many" pick.
```

(Comment-only change — no behavior difference, just correcting language that predated this plan's clarified design.)

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_enrichment_registry.py -v
```

Expected: PASS (all registry tests, +1 new)

- [ ] **Step 5: Commit**

```bash
git add app/enrichment/registry.py tests/test_enrichment_registry.py
git commit -m "feat: register VirusTotal's daily rate limit, clarify one-provider-per-type comment"
```

---

### Task 7: End-to-end multi-type enrichment scenario

**Files:**
- Modify: `tests/test_enrichment_integration.py`

**Interfaces:**
- Consumes: `VirusTotalProvider` (Tasks 3-5), `HashIndicator` (Task 1), `EnrichmentRegistry` (existing + Task 6) — no new production code, this task only adds a test.

- [ ] **Step 1: Write the test**

Append to `tests/test_enrichment_integration.py`:

```python
from app.enrichment.indicators import HashIndicator
from app.enrichment.providers.virustotal import VirusTotalProvider

FILE_URL = f"https://www.virustotal.com/api/v3/files/{'b' * 64}"


@respx.mock
def test_registry_routes_ip_and_hash_indicators_to_their_own_providers():
    respx.get(CHECK_URL).mock(
        return_value=httpx.Response(200, json={"data": {"abuseConfidenceScore": 90, "ipAddress": "203.0.113.5"}})
    )
    respx.get(FILE_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "id": "b" * 64,
                    "type": "file",
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 6,
                            "suspicious": 0,
                            "harmless": 10,
                            "undetected": 5,
                            "timeout": 0,
                        }
                    },
                }
            },
        )
    )
    registry = EnrichmentRegistry()
    registry.register(AbuseIPDBProvider(api_key="test-key"))
    registry.register(VirusTotalProvider(api_key="test-vt-key"))

    ip_result = registry.enrich(IPIndicator(value="203.0.113.5"))
    hash_result = registry.enrich(HashIndicator(value="b" * 64))

    assert ip_result.provider_id == "abuseipdb"
    assert ip_result.verdict == EnrichmentVerdict.MALICIOUS
    assert hash_result.provider_id == "virustotal"
    assert hash_result.verdict == EnrichmentVerdict.MALICIOUS
```

- [ ] **Step 2: Run the full test suite**

```bash
source .venv/bin/activate
pytest -v
```

Expected: PASS — all tests in the repo, old and new (this plan's Tasks 1-6 plus everything from Foundation/Enrichment/Integration/LLMClient).

- [ ] **Step 3: Commit**

```bash
git add tests/test_enrichment_integration.py
git commit -m "test: add end-to-end IP + hash multi-type enrichment scenario"
```
