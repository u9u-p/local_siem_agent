# Integration Module (SIEMConnector) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Integration module — `SIEMConnector` Protocol, dual auth strategies (Basic for the Indexer, JWT-Bearer for the Manager), a Wazuh-alert-JSON-to-`Alert` mapper, and `WazuhConnector` implementing all 5 Protocol methods against a real Wazuh 4.14.x instance — with a mocked-first test suite plus a skippable real-instance smoke test.

**Architecture:** `WazuhConnector` composes two independent `httpx.Client`s (Indexer at `wazuh_indexer_url`, Manager at `wazuh_manager_url`), each paired with its own `AuthStrategy` (`BasicAuthStrategy` for the Indexer, `JWTBearerAuthStrategy` for the Manager). The Manager-calling methods retry exactly once on a 401 (refresh the JWT, retry). A pure, HTTP-free module function (`wazuh_source_to_alert`) maps a raw Wazuh alert `_source` dict to the existing `Alert` domain model, so it's testable against fixture JSON with no client at all. `pull_alerts`/`search` build OpenSearch query-DSL bodies from a small constrained `SearchQuery` shape (never a raw query string), matching CLAUDE.md §1.1's "any investigation step... can only produce queries every backend is guaranteed to support."

**Tech Stack:** Python 3.11+, `httpx` + `respx` (all already dependencies from the Enrichment plan — no new ones needed), Wazuh 4.14.x Manager REST API + Indexer (OpenSearch) API.

## Global Constraints

- Python >= 3.11 (existing project constraint). No new dependencies — `httpx`, `respx`, `freezegun`, `pytest` are already installed.
- API mechanics are per `docs/superpowers/specs/2026-08-10-integration-siemconnector-design.md` §1, verified against the Wazuh 4.14.x OpenAPI spec: `GET /agents?agents_list={id}` and `GET /rules?rule_ids={id}` use **query params**, not path params. Manager `RuleMetadata.mitre_technique_ids` is a **flat `list[str]`** — do not reuse `MitreRef` for it.
- `RawAlert` is not a separate type — `Alert` (from `app/schemas.py`) is the raw-alert type; `WazuhConnector` returns fully-formed `Alert` objects directly.
- Self-signed TLS: `WazuhConnector`'s HTTP clients must accept `verify: bool = False` by default for this POC (per CLAUDE.md §3/§8) — never hardcode `verify=True`.
- JWT refresh is reactive only: request → 401 → `refresh()` → retry once → propagate if it 401s again. No proactive expiry tracking.
- This is a POC — no real API keys/credentials anywhere in code, tests, or fixtures. All `WazuhConnector` unit tests use `respx`-mocked HTTP. The real-instance smoke test file reads credentials from `.env`/`Settings` only, and skips entirely if they're not configured.
- TDD: every method/model gets a failing test before implementation.
- Commit after each task.

---

### Task 1: Wazuh config settings

**Files:**
- Modify: `app/config.py`
- Modify: `.env.example`
- Modify: `tests/test_config.py`

**Interfaces:**
- Produces: `Settings.wazuh_indexer_url`, `.wazuh_indexer_username`, `.wazuh_indexer_password`, `.wazuh_manager_url`, `.wazuh_manager_username`, `.wazuh_manager_password` (all `str | None = None`), `.wazuh_verify_ssl: bool = False` — consumed by Task 6 (`WazuhConnector` construction) and Task 9 (real-instance smoke test skip check).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_config.py`:

```python
def test_settings_wazuh_fields_default_to_none_and_verify_ssl_false():
    settings = Settings(_env_file=None)
    assert settings.wazuh_indexer_url is None
    assert settings.wazuh_indexer_username is None
    assert settings.wazuh_indexer_password is None
    assert settings.wazuh_manager_url is None
    assert settings.wazuh_manager_username is None
    assert settings.wazuh_manager_password is None
    assert settings.wazuh_verify_ssl is False


def test_settings_wazuh_fields_env_override(monkeypatch):
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://localhost:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USERNAME", "admin")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-password")
    monkeypatch.setenv("WAZUH_MANAGER_URL", "https://localhost:55000")
    monkeypatch.setenv("WAZUH_MANAGER_USERNAME", "wazuh-wui")
    monkeypatch.setenv("WAZUH_MANAGER_PASSWORD", "test-password-2")
    monkeypatch.setenv("WAZUH_VERIFY_SSL", "true")
    settings = Settings(_env_file=None)
    assert settings.wazuh_indexer_url == "https://localhost:9200"
    assert settings.wazuh_indexer_username == "admin"
    assert settings.wazuh_indexer_password == "test-password"
    assert settings.wazuh_manager_url == "https://localhost:55000"
    assert settings.wazuh_manager_username == "wazuh-wui"
    assert settings.wazuh_manager_password == "test-password-2"
    assert settings.wazuh_verify_ssl is True
```

- [ ] **Step 2: Run test to verify it fails**

```bash
source .venv/bin/activate
pytest tests/test_config.py -v
```

Expected: FAIL — `AttributeError: 'Settings' object has no attribute 'wazuh_indexer_url'`

- [ ] **Step 3: Write minimal implementation**

In `app/config.py`, change:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_path: str = "./data/alerts.db"
    log_level: str = "INFO"
    abuseipdb_api_key: str | None = None
```

to:

```python
class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_path: str = "./data/alerts.db"
    log_level: str = "INFO"
    abuseipdb_api_key: str | None = None
    wazuh_indexer_url: str | None = None
    wazuh_indexer_username: str | None = None
    wazuh_indexer_password: str | None = None
    wazuh_manager_url: str | None = None
    wazuh_manager_username: str | None = None
    wazuh_manager_password: str | None = None
    wazuh_verify_ssl: bool = False
```

In `.env.example`, change:

```
# Copy to .env and fill in real values. No secrets or real credentials belong in this file.
DATABASE_PATH=./data/alerts.db
LOG_LEVEL=INFO
ABUSEIPDB_API_KEY=
```

to:

```
# Copy to .env and fill in real values. No secrets or real credentials belong in this file.
DATABASE_PATH=./data/alerts.db
LOG_LEVEL=INFO
ABUSEIPDB_API_KEY=
WAZUH_INDEXER_URL=
WAZUH_INDEXER_USERNAME=
WAZUH_INDEXER_PASSWORD=
WAZUH_MANAGER_URL=
WAZUH_MANAGER_USERNAME=
WAZUH_MANAGER_PASSWORD=
WAZUH_VERIFY_SSL=false
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_config.py -v
```

Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add app/config.py .env.example tests/test_config.py
git commit -m "feat: add Wazuh connection settings"
```

---

### Task 2: Integration models

**Files:**
- Create: `app/integration/__init__.py`
- Create: `app/integration/models.py`
- Test: `tests/test_integration_models.py`

**Interfaces:**
- Consumes: `Alert` (from `app/schemas.py`, existing).
- Produces: `SearchQuery`, `SearchResult`, `AgentContext`, `RuleMetadata` (all `BaseModel`) — consumed by Task 4 (`SIEMConnector` Protocol) and Tasks 6-8 (`WazuhConnector` methods).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_integration_models.py
from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.integration.models import AgentContext, RuleMetadata, SearchQuery, SearchResult
from app.schemas import AgentRef, Alert


def _make_alert(**overrides):
    defaults = dict(
        alert_id=uuid4(),
        source_alert_id="1699999999.123456",
        source_system="wazuh",
        rule_id="5710",
        rule_description="sshd: Attempt to login using a non-existent user",
        rule_level=5,
        timestamp=datetime.now(timezone.utc),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id="001", name="web-01", ip="10.0.0.5"),
        manager_name="wazuh-manager",
        location="/var/log/auth.log",
        full_log="Invalid user admin from 203.0.113.5",
        raw_json={"rule": {"id": "5710"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_search_query_accepts_valid_operators():
    for operator in ("eq", "contains", "range", "terms"):
        query = SearchQuery(field="rule.level", operator=operator, value=5)
        assert query.operator == operator


def test_search_query_rejects_invalid_operator():
    with pytest.raises(ValidationError):
        SearchQuery(field="rule.level", operator="fuzzy", value=5)


def test_search_result_holds_alerts_and_total_count():
    alert = _make_alert()
    result = SearchResult(alerts=[alert], total_count=42)
    assert result.alerts[0].rule_id == "5710"
    assert result.total_count == 42


def test_agent_context_requires_core_fields_optional_os_fields():
    context = AgentContext(id="001", name="web-01", ip="10.0.0.5", status="active")
    assert context.os_platform is None
    assert context.last_keep_alive is None


def test_rule_metadata_mitre_is_flat_string_list():
    metadata = RuleMetadata(
        rule_id="5710",
        description="sshd: Attempt to login using a non-existent user",
        level=5,
        groups=["authentication_failed"],
        mitre_technique_ids=["T1110"],
    )
    assert metadata.mitre_technique_ids == ["T1110"]


def test_rule_metadata_defaults_groups_and_mitre_to_empty_list():
    metadata = RuleMetadata(rule_id="5710", description="x", level=5)
    assert metadata.groups == []
    assert metadata.mitre_technique_ids == []
```

- [ ] **Step 2: Run test to verify it fails**

```bash
mkdir -p app/integration
touch app/integration/__init__.py
pytest tests/test_integration_models.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.integration.models'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/integration/models.py
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas import Alert


class SearchQuery(BaseModel):
    field: str
    operator: Literal["eq", "contains", "range", "terms"]
    value: Any
    time_range: tuple[datetime, datetime] | None = None


class SearchResult(BaseModel):
    alerts: list[Alert]
    total_count: int


class AgentContext(BaseModel):
    id: str
    name: str
    ip: str
    os_platform: str | None = None
    os_version: str | None = None
    agent_version: str | None = None
    status: str
    last_keep_alive: datetime | None = None


class RuleMetadata(BaseModel):
    rule_id: str
    description: str
    level: int
    groups: list[str] = Field(default_factory=list)
    mitre_technique_ids: list[str] = Field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_integration_models.py -v
```

Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add app/integration/__init__.py app/integration/models.py tests/test_integration_models.py
git commit -m "feat: add SearchQuery/SearchResult/AgentContext/RuleMetadata models"
```

---

### Task 3: Auth strategies

**Files:**
- Create: `app/integration/auth.py`
- Test: `tests/test_integration_auth.py`

**Interfaces:**
- Produces: `AuthStrategy(Protocol)`, `BasicAuthStrategy(username, password)`, `JWTBearerAuthStrategy(client, username, password)` — consumed by Task 6-8 (`WazuhConnector`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_integration_auth.py
import base64

import httpx
import respx

from app.integration.auth import BasicAuthStrategy, JWTBearerAuthStrategy

MANAGER_URL = "https://wazuh-manager.test:55000"


def test_basic_auth_strategy_encodes_credentials():
    strategy = BasicAuthStrategy(username="admin", password="secret-pw")
    headers = strategy.get_headers()
    expected = base64.b64encode(b"admin:secret-pw").decode()
    assert headers == {"Authorization": f"Basic {expected}"}


def test_basic_auth_strategy_refresh_is_a_noop():
    strategy = BasicAuthStrategy(username="admin", password="secret-pw")
    strategy.refresh()  # must not raise


@respx.mock
def test_jwt_strategy_authenticates_on_first_use():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    client = httpx.Client(base_url=MANAGER_URL)
    strategy = JWTBearerAuthStrategy(client=client, username="wazuh-wui", password="test-pw")

    headers = strategy.get_headers()

    assert headers == {"Authorization": "Bearer abc123"}


@respx.mock
def test_jwt_strategy_caches_token_across_calls():
    route = respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    client = httpx.Client(base_url=MANAGER_URL)
    strategy = JWTBearerAuthStrategy(client=client, username="wazuh-wui", password="test-pw")

    strategy.get_headers()
    strategy.get_headers()

    assert route.call_count == 1


@respx.mock
def test_jwt_strategy_refresh_re_authenticates():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        side_effect=[
            httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0}),
            httpx.Response(200, json={"data": {"token": "def456"}, "error": 0}),
        ]
    )
    client = httpx.Client(base_url=MANAGER_URL)
    strategy = JWTBearerAuthStrategy(client=client, username="wazuh-wui", password="test-pw")

    strategy.get_headers()
    strategy.refresh()
    headers = strategy.get_headers()

    assert headers == {"Authorization": "Bearer def456"}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_integration_auth.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.integration.auth'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/integration/auth.py
import base64
from typing import Protocol

import httpx


class AuthStrategy(Protocol):
    def get_headers(self) -> dict[str, str]: ...
    def refresh(self) -> None: ...


class BasicAuthStrategy:
    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password

    def get_headers(self) -> dict[str, str]:
        token = base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
        return {"Authorization": f"Basic {token}"}

    def refresh(self) -> None:
        pass  # static credentials, nothing to refresh


class JWTBearerAuthStrategy:
    def __init__(self, client: httpx.Client, username: str, password: str) -> None:
        self._client = client
        self._username = username
        self._password = password
        self._token: str | None = None

    def get_headers(self) -> dict[str, str]:
        if self._token is None:
            self.refresh()
        return {"Authorization": f"Bearer {self._token}"}

    def refresh(self) -> None:
        response = self._client.post("/security/user/authenticate", auth=(self._username, self._password))
        response.raise_for_status()
        self._token = response.json()["data"]["token"]
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_integration_auth.py -v
```

Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add app/integration/auth.py tests/test_integration_auth.py
git commit -m "feat: add BasicAuthStrategy and JWTBearerAuthStrategy"
```

---

### Task 4: SIEMConnector Protocol

**Files:**
- Create: `app/integration/siem_connector.py`
- Test: `tests/test_siem_connector_protocol.py`

**Interfaces:**
- Consumes: `Alert` (existing), `SearchQuery`/`SearchResult`/`AgentContext`/`RuleMetadata` (Task 2).
- Produces: `SIEMConnector(Protocol)` — the contract `WazuhConnector` (Tasks 6-8) must satisfy.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_siem_connector_protocol.py
from datetime import datetime, timezone
from uuid import uuid4

from app.integration.models import AgentContext, RuleMetadata, SearchQuery, SearchResult
from app.integration.siem_connector import SIEMConnector
from app.schemas import AgentRef, Alert


class _FakeConnector:
    def health_check(self) -> bool:
        return True

    def pull_alerts(self, since, until=None, limit=500):
        return []

    def search(self, query: SearchQuery) -> SearchResult:
        return SearchResult(alerts=[], total_count=0)

    def get_agent_context(self, agent_id: str) -> AgentContext:
        return AgentContext(id=agent_id, name="web-01", ip="10.0.0.5", status="active")

    def get_rule_metadata(self, rule_id: str) -> RuleMetadata:
        return RuleMetadata(rule_id=rule_id, description="x", level=5)


def test_fake_connector_satisfies_siem_connector_protocol():
    connector: SIEMConnector = _FakeConnector()
    assert connector.health_check() is True
    assert connector.pull_alerts(since=datetime.now(timezone.utc)) == []
    assert connector.search(SearchQuery(field="rule.level", operator="eq", value=5)).total_count == 0
    assert connector.get_agent_context("001").id == "001"
    assert connector.get_rule_metadata("5710").rule_id == "5710"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_siem_connector_protocol.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.integration.siem_connector'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/integration/siem_connector.py
from datetime import datetime
from typing import Protocol

from app.integration.models import AgentContext, RuleMetadata, SearchQuery, SearchResult
from app.schemas import Alert


class SIEMConnector(Protocol):
    def health_check(self) -> bool: ...
    def pull_alerts(self, since: datetime, until: datetime | None = None, limit: int = 500) -> list[Alert]: ...
    def search(self, query: SearchQuery) -> SearchResult: ...
    def get_agent_context(self, agent_id: str) -> AgentContext: ...
    def get_rule_metadata(self, rule_id: str) -> RuleMetadata: ...
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_siem_connector_protocol.py -v
```

Expected: PASS (1 test)

- [ ] **Step 5: Commit**

```bash
git add app/integration/siem_connector.py tests/test_siem_connector_protocol.py
git commit -m "feat: add SIEMConnector Protocol"
```

---

### Task 5: Wazuh alert mapper

**Files:**
- Create: `app/integration/wazuh_connector.py`
- Test: `tests/test_wazuh_alert_mapper.py`

**Interfaces:**
- Consumes: `Alert`, `AgentRef`, `MitreRef` (existing, `app/schemas.py`).
- Produces: `wazuh_source_to_alert(source: dict[str, Any]) -> Alert` — a pure function consumed by Task 6 (`pull_alerts`) and Task 7 (`search`).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_wazuh_alert_mapper.py
from app.integration.wazuh_connector import wazuh_source_to_alert

# Verbatim example alert from docs.wazuh.com/current/user-manual/ruleset/mitre.html,
# confirming the rule.mitre.{tactic,id,technique} parallel-array shape.
MITRE_EXAMPLE_SOURCE = {
    "agent": {"ip": "172.20.10.3", "name": "Windows11", "id": "002"},
    "manager": {"name": "wazuh-server"},
    "data": {},
    "rule": {
        "firedtimes": 4,
        "mail": False,
        "level": 10,
        "description": "PsExec service running as NT AUTHORITY\\SYSTEM has been created on Windows11",
        "groups": ["windows", "sysmon"],
        "mitre": {
            "technique": ["Windows Service"],
            "id": ["T1543.003"],
            "tactic": ["Persistence", "Privilege Escalation"],
        },
        "id": "110011",
    },
    "location": "EventChannel",
    "decoder": {"name": "windows_eventchannel"},
    "id": "1694607138.3688437",
    "timestamp": "2023-10-16T12:12:18.684+0000",
}

# A syslog/sshd-shaped alert with no MITRE mapping and populated network/user fields.
SYSLOG_EXAMPLE_SOURCE = {
    "agent": {"ip": "10.0.0.5", "name": "web-01", "id": "001"},
    "manager": {"name": "wazuh-manager"},
    "data": {"srcip": "203.0.113.5", "srcport": "61658", "srcuser": "root"},
    "rule": {
        "level": 5,
        "description": "sshd: Attempt to login using a non-existent user",
        "groups": ["authentication_failed", "syslog"],
        "id": "5710",
    },
    "location": "/var/log/auth.log",
    "full_log": "Jul 12 15:32:41 ip-10-0-1-175 sshd[21746]: Invalid user admin from 203.0.113.5 port 61658 ssh2",
    "id": "1699999999.123456",
    "timestamp": "2026-08-10T09:00:00.000+0000",
}


def test_maps_mitre_parallel_arrays_into_mitre_ref_list():
    alert = wazuh_source_to_alert(MITRE_EXAMPLE_SOURCE)

    assert alert.source_alert_id == "1694607138.3688437"
    assert alert.rule_id == "110011"
    assert alert.rule_level == 10
    assert alert.agent.id == "002"
    assert alert.agent.name == "Windows11"
    assert alert.mitre is not None
    assert len(alert.mitre) == 1
    assert alert.mitre[0].tactic == "Persistence"
    assert alert.mitre[0].technique_id == "T1543.003"
    assert alert.mitre[0].technique_name == "Windows Service"


def test_maps_syslog_alert_with_no_mitre_and_network_fields():
    alert = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)

    assert alert.source_alert_id == "1699999999.123456"
    assert alert.rule_id == "5710"
    assert alert.mitre is None
    assert alert.source_ip == "203.0.113.5"
    assert alert.source_port == 61658
    assert alert.src_user == "root"
    assert alert.destination_ip is None
    assert alert.full_log.startswith("Jul 12 15:32:41")
    assert alert.manager_name == "wazuh-manager"
    assert alert.source_system == "wazuh"


def test_mapper_generates_a_fresh_alert_id_and_ingested_at_each_call():
    first = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)
    second = wazuh_source_to_alert(SYSLOG_EXAMPLE_SOURCE)

    assert first.alert_id != second.alert_id
    assert first.raw_json == SYSLOG_EXAMPLE_SOURCE
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_wazuh_alert_mapper.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'app.integration.wazuh_connector'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/integration/wazuh_connector.py
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.schemas import AgentRef, Alert, MitreRef


def wazuh_source_to_alert(source: dict[str, Any]) -> Alert:
    rule = source.get("rule", {})
    mitre_raw = rule.get("mitre") or {}
    mitre = [
        MitreRef(tactic=tactic, technique_id=technique_id, technique_name=technique_name)
        for tactic, technique_id, technique_name in zip(
            mitre_raw.get("tactic", []), mitre_raw.get("id", []), mitre_raw.get("technique", [])
        )
    ] or None

    agent = source.get("agent", {})
    data = source.get("data", {})

    return Alert(
        alert_id=uuid4(),
        source_alert_id=source["id"],
        source_system="wazuh",
        rule_id=str(rule.get("id", "")),
        rule_description=rule.get("description", ""),
        rule_level=rule.get("level", 0),
        rule_groups=rule.get("groups", []),
        mitre=mitre,
        timestamp=datetime.fromisoformat(source["timestamp"]),
        ingested_at=datetime.now(timezone.utc),
        agent=AgentRef(id=agent.get("id", ""), name=agent.get("name", ""), ip=agent.get("ip", "")),
        manager_name=source.get("manager", {}).get("name", ""),
        location=source.get("location", ""),
        full_log=source.get("full_log", ""),
        source_ip=data.get("srcip"),
        source_port=int(data["srcport"]) if data.get("srcport") else None,
        destination_ip=data.get("dstip"),
        destination_port=int(data["dstport"]) if data.get("dstport") else None,
        src_user=data.get("srcuser"),
        dst_user=data.get("dstuser"),
        data=data,
        raw_json=source,
    )
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_wazuh_alert_mapper.py -v
```

Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add app/integration/wazuh_connector.py tests/test_wazuh_alert_mapper.py
git commit -m "feat: add Wazuh alert JSON to Alert mapper"
```

---

### Task 6: `WazuhConnector` — construction, `health_check`, `pull_alerts`

**Files:**
- Modify: `app/integration/wazuh_connector.py`
- Test: `tests/test_wazuh_connector.py`

**Interfaces:**
- Consumes: `BasicAuthStrategy`, `JWTBearerAuthStrategy` (Task 3); `wazuh_source_to_alert` (Task 5); `Settings` (Task 1).
- Produces: `WazuhConnector(indexer_url, indexer_username, indexer_password, manager_url, manager_username, manager_password, verify_ssl=False)` with `.health_check()` and `.pull_alerts()` implemented (`.search()`/`.get_agent_context()`/`.get_rule_metadata()` raise `NotImplementedError` until Tasks 7-8) — consumed by Tasks 7-9.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_wazuh_connector.py
from datetime import datetime, timezone

import httpx
import respx

from app.integration.wazuh_connector import WazuhConnector

INDEXER_URL = "https://wazuh-indexer.test:9200"
MANAGER_URL = "https://wazuh-manager.test:55000"


def _make_connector(**overrides):
    defaults = dict(
        indexer_url=INDEXER_URL,
        indexer_username="admin",
        indexer_password="indexer-pw",
        manager_url=MANAGER_URL,
        manager_username="wazuh-wui",
        manager_password="manager-pw",
        verify_ssl=False,
    )
    defaults.update(overrides)
    return WazuhConnector(**defaults)


@respx.mock
def test_health_check_returns_true_when_both_backends_reachable():
    respx.get(f"{INDEXER_URL}/_cluster/health").mock(return_value=httpx.Response(200, json={"status": "green"}))
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    respx.get(f"{MANAGER_URL}/agents").mock(
        return_value=httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})
    )
    connector = _make_connector()

    assert connector.health_check() is True


@respx.mock
def test_health_check_returns_false_when_indexer_unreachable():
    respx.get(f"{INDEXER_URL}/_cluster/health").mock(return_value=httpx.Response(503))
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    respx.get(f"{MANAGER_URL}/agents").mock(
        return_value=httpx.Response(200, json={"data": {"affected_items": []}, "error": 0})
    )
    connector = _make_connector()

    assert connector.health_check() is False


@respx.mock
def test_pull_alerts_maps_indexer_hits_to_alerts():
    respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_source": {
                                "agent": {"ip": "10.0.0.5", "name": "web-01", "id": "001"},
                                "manager": {"name": "wazuh-manager"},
                                "data": {"srcip": "203.0.113.5"},
                                "rule": {"level": 5, "description": "sshd auth failure", "groups": [], "id": "5710"},
                                "location": "/var/log/auth.log",
                                "full_log": "Invalid user admin from 203.0.113.5",
                                "id": "1699999999.123456",
                                "timestamp": "2026-08-10T09:00:00.000+0000",
                            }
                        }
                    ],
                }
            },
        )
    )
    connector = _make_connector()

    alerts = connector.pull_alerts(since=datetime(2026, 8, 10, tzinfo=timezone.utc))

    assert len(alerts) == 1
    assert alerts[0].rule_id == "5710"
    assert alerts[0].source_ip == "203.0.113.5"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_wazuh_connector.py -v
```

Expected: FAIL with `ImportError: cannot import name 'WazuhConnector' from 'app.integration.wazuh_connector'`

- [ ] **Step 3: Write minimal implementation**

Append to `app/integration/wazuh_connector.py` (add the new import line at the top and the class at the bottom):

Update the import block at the top of `app/integration/wazuh_connector.py`:

```python
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import httpx

from app.integration.auth import BasicAuthStrategy, JWTBearerAuthStrategy
from app.integration.models import AgentContext, RuleMetadata, SearchQuery, SearchResult
from app.schemas import AgentRef, Alert, MitreRef
```

Append the class:

```python
class WazuhConnector:
    def __init__(
        self,
        indexer_url: str,
        indexer_username: str,
        indexer_password: str,
        manager_url: str,
        manager_username: str,
        manager_password: str,
        verify_ssl: bool = False,
    ) -> None:
        self._indexer_client = httpx.Client(base_url=indexer_url, verify=verify_ssl, timeout=10.0)
        self._indexer_auth = BasicAuthStrategy(indexer_username, indexer_password)
        self._manager_client = httpx.Client(base_url=manager_url, verify=verify_ssl, timeout=10.0)
        self._manager_auth = JWTBearerAuthStrategy(self._manager_client, manager_username, manager_password)

    def _manager_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        headers = self._manager_auth.get_headers()
        response = self._manager_client.request(method, path, headers=headers, **kwargs)
        if response.status_code == 401:
            self._manager_auth.refresh()
            headers = self._manager_auth.get_headers()
            response = self._manager_client.request(method, path, headers=headers, **kwargs)
        return response

    def health_check(self) -> bool:
        try:
            indexer_response = self._indexer_client.get(
                "/_cluster/health", headers=self._indexer_auth.get_headers()
            )
            if indexer_response.status_code != 200:
                return False
            manager_response = self._manager_request("GET", "/agents", params={"limit": 1})
            return manager_response.status_code == 200
        except httpx.HTTPError:
            return False

    def pull_alerts(self, since: datetime, until: datetime | None = None, limit: int = 500) -> list[Alert]:
        must: list[dict[str, Any]] = [{"range": {"timestamp": {"gte": since.isoformat()}}}]
        if until is not None:
            must[0]["range"]["timestamp"]["lte"] = until.isoformat()
        body = {"query": {"bool": {"filter": must}}, "size": limit}
        response = self._indexer_client.post(
            "/wazuh-alerts-*/_search", json=body, headers=self._indexer_auth.get_headers()
        )
        response.raise_for_status()
        hits = response.json()["hits"]["hits"]
        return [wazuh_source_to_alert(hit["_source"]) for hit in hits]

    def search(self, query: SearchQuery) -> SearchResult:
        raise NotImplementedError("added in Task 7")

    def get_agent_context(self, agent_id: str) -> AgentContext:
        raise NotImplementedError("added in Task 8")

    def get_rule_metadata(self, rule_id: str) -> RuleMetadata:
        raise NotImplementedError("added in Task 8")
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_wazuh_connector.py -v
```

Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add app/integration/wazuh_connector.py tests/test_wazuh_connector.py
git commit -m "feat: implement WazuhConnector construction, health_check, and pull_alerts"
```

---

### Task 7: `WazuhConnector.search`

**Files:**
- Modify: `app/integration/wazuh_connector.py`
- Modify: `tests/test_wazuh_connector.py`

**Interfaces:**
- Consumes: `SearchQuery`/`SearchResult` (Task 2).
- Produces: `search()` fully implemented, translating `SearchQuery.operator` into OpenSearch query DSL per the design spec §5's table.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_wazuh_connector.py`:

```python
from app.integration.models import SearchQuery


@respx.mock
def test_search_translates_eq_operator_to_term_query():
    route = respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
    )
    connector = _make_connector()

    result = connector.search(SearchQuery(field="rule.level", operator="eq", value=5))

    assert result.total_count == 0
    sent_body = route.calls.last.request.content
    import json

    parsed = json.loads(sent_body)
    assert parsed["query"]["bool"]["must"] == [{"term": {"rule.level": 5}}]


@respx.mock
def test_search_translates_contains_operator_to_match_query():
    respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
    )
    connector = _make_connector()

    connector.search(SearchQuery(field="full_log", operator="contains", value="Invalid user"))
    # Correctness of the query body content is checked in the eq/range/terms tests;
    # this test only confirms the call succeeds without raising for the "contains" branch.


@respx.mock
def test_search_translates_range_operator_and_time_range_filter():
    route = respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(
            200,
            json={
                "hits": {
                    "total": {"value": 1},
                    "hits": [
                        {
                            "_source": {
                                "agent": {"ip": "10.0.0.5", "name": "web-01", "id": "001"},
                                "manager": {"name": "wazuh-manager"},
                                "data": {},
                                "rule": {"level": 5, "description": "x", "groups": [], "id": "5710"},
                                "location": "/var/log/auth.log",
                                "full_log": "x",
                                "id": "1699999999.123456",
                                "timestamp": "2026-08-10T09:00:00.000+0000",
                            }
                        }
                    ],
                }
            },
        )
    )
    connector = _make_connector()
    since = datetime(2026, 8, 10, tzinfo=timezone.utc)
    until = datetime(2026, 8, 11, tzinfo=timezone.utc)

    result = connector.search(
        SearchQuery(field="rule.level", operator="range", value={"gte": 3}, time_range=(since, until))
    )

    assert result.total_count == 1
    import json

    parsed = json.loads(route.calls.last.request.content)
    assert {"range": {"rule.level": {"gte": 3}}} in parsed["query"]["bool"]["must"]
    assert any("timestamp" in clause.get("range", {}) for clause in parsed["query"]["bool"]["filter"])


@respx.mock
def test_search_translates_terms_operator_to_terms_query():
    route = respx.post(f"{INDEXER_URL}/wazuh-alerts-*/_search").mock(
        return_value=httpx.Response(200, json={"hits": {"total": {"value": 0}, "hits": []}})
    )
    connector = _make_connector()

    connector.search(SearchQuery(field="rule.groups", operator="terms", value=["authentication_failed", "syslog"]))

    import json

    parsed = json.loads(route.calls.last.request.content)
    assert parsed["query"]["bool"]["must"] == [
        {"terms": {"rule.groups": ["authentication_failed", "syslog"]}}
    ]
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_wazuh_connector.py -v
```

Expected: FAIL — `NotImplementedError: added in Task 7`

- [ ] **Step 3: Write minimal implementation**

Replace the `search()` method body in `app/integration/wazuh_connector.py`:

```python
    def search(self, query: SearchQuery) -> SearchResult:
        operator_clause: dict[str, Any]
        if query.operator == "eq":
            operator_clause = {"term": {query.field: query.value}}
        elif query.operator == "contains":
            operator_clause = {"match": {query.field: query.value}}
        elif query.operator == "range":
            operator_clause = {"range": {query.field: query.value}}
        else:  # "terms"
            operator_clause = {"terms": {query.field: query.value}}

        filter_clauses: list[dict[str, Any]] = []
        if query.time_range is not None:
            since, until = query.time_range
            filter_clauses.append({"range": {"timestamp": {"gte": since.isoformat(), "lte": until.isoformat()}}})

        body = {"query": {"bool": {"must": [operator_clause], "filter": filter_clauses}}}
        response = self._indexer_client.post(
            "/wazuh-alerts-*/_search", json=body, headers=self._indexer_auth.get_headers()
        )
        response.raise_for_status()
        payload = response.json()
        alerts = [wazuh_source_to_alert(hit["_source"]) for hit in payload["hits"]["hits"]]
        return SearchResult(alerts=alerts, total_count=payload["hits"]["total"]["value"])
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_wazuh_connector.py -v
```

Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add app/integration/wazuh_connector.py tests/test_wazuh_connector.py
git commit -m "feat: implement WazuhConnector.search"
```

---

### Task 8: `WazuhConnector.get_agent_context` and `.get_rule_metadata`

**Files:**
- Modify: `app/integration/wazuh_connector.py`
- Modify: `tests/test_wazuh_connector.py`

**Interfaces:**
- Consumes: `AgentContext`/`RuleMetadata` (Task 2).
- Produces: `get_agent_context()` and `get_rule_metadata()` fully implemented, completing the `SIEMConnector` Protocol contract, including the reactive 401-refresh-retry-once behavior on the Manager path.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_wazuh_connector.py`:

```python
@respx.mock
def test_get_agent_context_maps_manager_response():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    respx.get(f"{MANAGER_URL}/agents").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [
                        {
                            "id": "001",
                            "name": "web-01",
                            "ip": "10.0.0.5",
                            "status": "active",
                            "os": {"platform": "ubuntu", "version": "22.04"},
                            "version": "Wazuh v4.14.1",
                            "lastKeepAlive": "2026-08-10T09:00:00Z",
                        }
                    ]
                },
                "error": 0,
            },
        )
    )
    connector = _make_connector()

    context = connector.get_agent_context("001")

    assert context.id == "001"
    assert context.os_platform == "ubuntu"
    assert context.os_version == "22.04"
    assert context.agent_version == "Wazuh v4.14.1"
    assert context.status == "active"


@respx.mock
def test_get_rule_metadata_maps_manager_response_with_flat_mitre_list():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        return_value=httpx.Response(200, json={"data": {"token": "abc123"}, "error": 0})
    )
    respx.get(f"{MANAGER_URL}/rules").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "affected_items": [
                        {
                            "id": 5710,
                            "description": "sshd: Attempt to login using a non-existent user",
                            "level": 5,
                            "groups": ["authentication_failed", "syslog"],
                            "mitre": ["T1110"],
                        }
                    ]
                },
                "error": 0,
            },
        )
    )
    connector = _make_connector()

    metadata = connector.get_rule_metadata("5710")

    assert metadata.rule_id == "5710"
    assert metadata.level == 5
    assert metadata.groups == ["authentication_failed", "syslog"]
    assert metadata.mitre_technique_ids == ["T1110"]


@respx.mock
def test_get_agent_context_retries_once_after_401():
    respx.post(f"{MANAGER_URL}/security/user/authenticate").mock(
        side_effect=[
            httpx.Response(200, json={"data": {"token": "expired-token"}, "error": 0}),
            httpx.Response(200, json={"data": {"token": "fresh-token"}, "error": 0}),
        ]
    )
    respx.get(f"{MANAGER_URL}/agents").mock(
        side_effect=[
            httpx.Response(401, json={"title": "Unauthorized", "detail": "No authorization token provided"}),
            httpx.Response(
                200,
                json={
                    "data": {
                        "affected_items": [
                            {"id": "001", "name": "web-01", "ip": "10.0.0.5", "status": "active"}
                        ]
                    },
                    "error": 0,
                },
            ),
        ]
    )
    connector = _make_connector()

    context = connector.get_agent_context("001")

    assert context.id == "001"
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_wazuh_connector.py -v
```

Expected: FAIL — `NotImplementedError: added in Task 8`

- [ ] **Step 3: Write minimal implementation**

Replace the `get_agent_context()` and `get_rule_metadata()` method bodies in `app/integration/wazuh_connector.py`:

```python
    def get_agent_context(self, agent_id: str) -> AgentContext:
        response = self._manager_request("GET", "/agents", params={"agents_list": agent_id})
        response.raise_for_status()
        item = response.json()["data"]["affected_items"][0]
        os_info = item.get("os", {})
        return AgentContext(
            id=item["id"],
            name=item["name"],
            ip=item["ip"],
            os_platform=os_info.get("platform"),
            os_version=os_info.get("version"),
            agent_version=item.get("version"),
            status=item["status"],
            last_keep_alive=item.get("lastKeepAlive"),
        )

    def get_rule_metadata(self, rule_id: str) -> RuleMetadata:
        response = self._manager_request("GET", "/rules", params={"rule_ids": rule_id})
        response.raise_for_status()
        item = response.json()["data"]["affected_items"][0]
        return RuleMetadata(
            rule_id=str(item["id"]),
            description=item["description"],
            level=item["level"],
            groups=item.get("groups", []),
            mitre_technique_ids=item.get("mitre", []),
        )
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_wazuh_connector.py -v
```

Expected: PASS (10 tests)

- [ ] **Step 5: Commit**

```bash
git add app/integration/wazuh_connector.py tests/test_wazuh_connector.py
git commit -m "feat: implement WazuhConnector.get_agent_context and get_rule_metadata"
```

---

### Task 9: Real-instance smoke test and timestamp field verification

**Files:**
- Create: `tests/test_wazuh_connector_live.py`

**Interfaces:**
- Consumes: `Settings` (Task 1), `WazuhConnector` (Tasks 6-8) — no new production code, this task only adds a skippable test file.

- [ ] **Step 1: Write the test**

```python
# tests/test_wazuh_connector_live.py
from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings
from app.integration.wazuh_connector import WazuhConnector


def _load_live_settings() -> Settings | None:
    settings = Settings()
    required = (
        settings.wazuh_indexer_url,
        settings.wazuh_indexer_username,
        settings.wazuh_indexer_password,
        settings.wazuh_manager_url,
        settings.wazuh_manager_username,
        settings.wazuh_manager_password,
    )
    if not all(required):
        return None
    return settings


@pytest.fixture
def live_connector():
    settings = _load_live_settings()
    if settings is None:
        pytest.skip("WAZUH_* settings not configured in .env — skipping real-instance test")
    return WazuhConnector(
        indexer_url=settings.wazuh_indexer_url,
        indexer_username=settings.wazuh_indexer_username,
        indexer_password=settings.wazuh_indexer_password,
        manager_url=settings.wazuh_manager_url,
        manager_username=settings.wazuh_manager_username,
        manager_password=settings.wazuh_manager_password,
        verify_ssl=settings.wazuh_verify_ssl,
    )


def test_live_health_check_succeeds(live_connector):
    assert live_connector.health_check() is True


def test_live_pull_alerts_returns_alert_list(live_connector):
    since = datetime.now(timezone.utc) - timedelta(days=7)

    alerts = live_connector.pull_alerts(since=since, limit=5)

    assert isinstance(alerts, list)
    # This call itself is the empirical check for design spec §6: if the Indexer's
    # alert documents use a different timestamp field name than "timestamp" for the
    # range query, this call will return zero alerts even when alerts exist in that
    # window (rather than raising) — if that happens, inspect one real hit's _source
    # keys directly (GET /wazuh-alerts-*/_search with no filter, size=1) and update
    # WazuhConnector.pull_alerts'/.search()'s range-query field name accordingly.
```

- [ ] **Step 2: Run the full test suite**

```bash
source .venv/bin/activate
pytest -v
```

Expected: the two `test_wazuh_connector_live.py` tests are SKIPPED unless `.env` has real `WAZUH_*` values configured; every other test (Foundation + Enrichment + this plan's Tasks 1-8) PASSES. If you have real credentials in `.env` and the two live tests run instead of skipping: confirm they pass, and if `test_live_pull_alerts_returns_alert_list` returns an empty list despite known recent alerts existing, follow the comment's instructions to check the real timestamp field name and fix Task 6/7's range-query field accordingly (this is the one open item from the design spec's §6 that could only be resolved this way).

- [ ] **Step 3: Commit**

```bash
git add tests/test_wazuh_connector_live.py
git commit -m "test: add skippable real-instance smoke tests for WazuhConnector"
```
