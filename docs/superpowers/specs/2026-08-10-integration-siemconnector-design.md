# Integration Module (SIEMConnector) Design

**Date:** 10 Aug 2026
**Parent design:** `CLAUDE.md` §1.1 (`SIEMConnector`/`AuthStrategy` Protocols), §3 (Wazuh Integration Specifics)
**Depends on:** Foundation subsystem (`app/schemas.py`) — merged to `main`.
**Wazuh version targeted:** 4.14.x. API mechanics below are verified against the official OpenAPI spec at git tag `v4.14.1` (`api/api/spec/spec.yaml`) and docs.wazuh.com, not general/possibly-stale knowledge — citations inline. Two items are flagged as needing live-instance confirmation rather than guessed (see §6).

---

## Context

CLAUDE.md §1.1 and §3 establish the `SIEMConnector` Protocol and the two-backend architecture (Indexer for alerts/search, Manager for host/rule metadata) at a high level. This document works out the concrete implementation against a real, reachable Wazuh 4.14.x all-in-one instance (self-signed TLS, confirmed by you as your test environment) and resolves two Protocol-signature ambiguities the parent doc left implicit:

1. **`RawAlert` is `Alert`.** CLAUDE.md's own §2.1 heading — "`Alert` (raw, informed by Wazuh's alert JSON shape)" — treats `Alert` as already being the raw-alert type. `WazuhConnector` therefore owns the Wazuh-JSON→`Alert` mapping internally and returns fully-formed `Alert` objects from `pull_alerts()`/`search()`; no separate `RawAlert` type is introduced.
2. **`SearchQuery`/`SearchResult`/`AgentContext`/`RuleMetadata` are new types**, defined below, since nothing in the codebase has them yet.

Decisions confirmed in brainstorming:

- **Testing:** hybrid — respx-mocked unit tests for every method (primary, always-green suite) plus a small skippable real-instance smoke-test file that only runs when `WAZUH_*` settings are configured in `.env`.
- **Scope:** all 5 `SIEMConnector` methods in this one plan (`health_check`, `pull_alerts`, `search`, `get_agent_context`, `get_rule_metadata`).
- **JWT refresh:** reactive — make the request, and only on a 401 call `refresh()` and retry exactly once. No proactive expiry tracking.
- **Topology:** all-in-one Wazuh (Indexer + Manager + Dashboard on one host), self-signed TLS — matches CLAUDE.md §3/§8's stated assumption.

---

## 1. Confirmed Wazuh 4.14.x API mechanics

### Manager (Server) API — port 55000

| Concern | Detail | Source |
|---|---|---|
| Auth | `POST /security/user/authenticate`, HTTP Basic credentials in the request, JWT returned at `data.token` | OpenAPI spec `api.controllers.security_controller.login_user`; docs.wazuh.com/current/user-manual/api/getting-started.html |
| Token expiry | Default **900s** (`auth_token_exp_timeout`, `SecurityConfiguration` schema, `minimum: 30`) | spec `info.description` + `SecurityConfiguration` schema |
| Expired/missing/invalid token | **401**, generic `RequestError`-shaped body (`{"title": "Unauthorized", "detail": "..."}`) on every protected endpoint | spec `UnauthorizedResponse` |
| Agent lookup | `GET /agents?agents_list={id}` — **query param, not a path param** | spec `/agents` GET parameters |
| Agent response | `data.affected_items[0]`, fields include `id`, `name`, `ip`, `status`, `os.platform`, `os.version`, `version`, `lastKeepAlive` | spec `Agent` schema |
| Rule lookup | `GET /rules?rule_ids={id}` — **query param, not a path param** | spec `rule_ids` parameter, `/rules` GET |
| Rule response | `data.affected_items[0]`, fields include `id`, `description`, `level`, `groups`, `mitre` — **`mitre` here is a flat `list[str]` of technique IDs, not a nested object** | spec `Rule` schema + example (`mitre: []`) |

### Indexer API (OpenSearch) — port 9200

| Concern | Detail | Source |
|---|---|---|
| Access | Standard OpenSearch REST search: `POST /wazuh-alerts-*/_search` with a JSON query-DSL body | docs.wazuh.com/current/user-manual/indexer-api/getting-started.html |
| Auth | HTTP Basic against the OpenSearch security plugin | same |
| Alert document shape | `_source.rule.{id, description, level, groups, mitre: {id, tactic, technique}}` (parallel arrays), `_source.agent.{id, name, ip}`, `_source.manager.name`, `_source.location`, `_source.data.{...free-form}`, `_source.full_log`, `_source.id` (native `<epoch>.<counter>` format), `_source.timestamp` (ISO 8601 with UTC offset, e.g. `"2023-10-16T12:12:18.684+0000"`) | verbatim example alert, docs.wazuh.com/current/user-manual/ruleset/mitre.html |
| Range query shape | `{"query": {"range": {"<timestamp-field>": {"gt": "<ISO8601>"}}}}` | docs.wazuh.com/current/user-manual/indexer-api/getting-started.html |

### TLS

All-in-one demo installs generate self-signed certs via `wazuh-certs-tool.sh`; every official example against both ports uses `curl -k`. Client needs an explicit `verify=False` (or custom CA bundle) option — flagged, tightened before any non-demo use, per CLAUDE.md §3/§8.

---

## 2. File Structure

```
app/integration/
  __init__.py
  models.py            # SearchQuery, SearchResult, AgentContext, RuleMetadata
  auth.py               # AuthStrategy Protocol, BasicAuthStrategy, JWTBearerAuthStrategy
  siem_connector.py     # SIEMConnector Protocol
  wazuh_connector.py    # WazuhConnector + Wazuh-JSON-to-Alert mapper
```

`app/config.py` gains `wazuh_indexer_url`, `wazuh_indexer_username`, `wazuh_indexer_password`, `wazuh_manager_url`, `wazuh_manager_username`, `wazuh_manager_password`, `wazuh_verify_ssl: bool = False` — all `str | None` except the bool, so the mocked test suite never needs real values.

---

## 3. New Types (`app/integration/models.py`)

```python
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel

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
    groups: list[str] = []
    mitre_technique_ids: list[str] = []
```

`RuleMetadata.mitre_technique_ids` is a flat list (per §1's confirmed `GET /rules` shape) — deliberately **not** `list[MitreRef]`. The rich `{tactic, technique_id, technique_name}` mapping already lives on `Alert.mitre`, sourced from Indexer alert documents where that structure actually exists.

---

## 4. Auth (`app/integration/auth.py`)

```python
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
        self._client = client  # the Manager's httpx.Client, base_url already set
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

`WazuhConnector`'s Manager-calling methods wrap each request: attach `auth_strategy.get_headers()`; on a 401 response, call `refresh()` once and retry the request exactly once; a second 401 propagates (not silently retried forever).

---

## 5. `WazuhConnector` (`app/integration/wazuh_connector.py`)

Composes two `httpx.Client`s (Indexer, Manager), each with its own `AuthStrategy`, `verify=settings.wazuh_verify_ssl`, and a reasonable timeout.

**`health_check() -> bool`** — checks both backends are reachable (e.g. Indexer `GET /_cluster/health`, Manager `GET /` or a lightweight authenticated call); returns `True` only if both succeed.

**`pull_alerts(since, until=None, limit=500) -> list[Alert]`** — Indexer `_search` with a `range` query on the timestamp field (see §6 for the field-name check) bounded by `since`/`until`, mapped through the alert-to-`Alert` converter below.

**`search(query: SearchQuery) -> SearchResult`** — translates the constrained `SearchQuery` into Indexer query DSL:

| `operator` | DSL |
|---|---|
| `eq` | `{"term": {field: value}}` |
| `contains` | `{"match": {field: value}}` |
| `range` | `{"range": {field: value}}` (value is a `{"gte": ..., "lte": ...}`-shaped dict) |
| `terms` | `{"terms": {field: value}}` (value is a list) |

`time_range`, if set, is ANDed into a `bool.filter` range clause on the timestamp field regardless of `operator`. Returns `SearchResult(alerts=[...], total_count=<hits.total.value>)`.

**`get_agent_context(agent_id) -> AgentContext`** — `GET /agents?agents_list={agent_id}` against the Manager, reads `data.affected_items[0]`, maps `os.platform`→`os_platform`, `os.version`→`os_version`, `version`→`agent_version`, `lastKeepAlive`→`last_keep_alive`.

**`get_rule_metadata(rule_id) -> RuleMetadata`** — `GET /rules?rule_ids={rule_id}` against the Manager, reads `data.affected_items[0]`, maps directly (`mitre` stays a flat list, per §1/§3).

**Wazuh alert → `Alert` mapper** (module-level function, not a method — pure transformation, easy to unit test on fixture JSON without an `httpx.Client`):

```python
def wazuh_source_to_alert(source: dict[str, Any]) -> Alert:
    rule = source.get("rule", {})
    mitre_raw = rule.get("mitre") or {}
    mitre = [
        MitreRef(tactic=tactic, technique_id=tid, technique_name=tname)
        for tactic, tid, tname in zip(
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

`datetime.fromisoformat` handles the confirmed `"...+0000"` offset format natively on Python 3.11+ (its ISO-8601 parsing was relaxed in 3.11) — no manual offset-string massaging needed.

---

## 6. Open item requiring live-instance confirmation

**Timestamp field name for range queries.** Official docs show both `timestamp` (inside `_source`, per the verbatim alert example in §1) and `@timestamp` (in a separate range-query example) — these may be the same underlying field indexed two ways (raw + Filebeat-processed), or genuinely different fields depending on index template. **Before finalizing `pull_alerts`'s range query, run one real query against the live instance** (`GET /wazuh-alerts-*/_search` with a small `size` and no filter, inspect one hit's `_source` keys directly) to confirm which field name is actually present and queryable, and use that — do not assume from docs alone. This is exactly what the real-instance smoke test (§7) should do first, before anything else depends on it.

---

## 7. Testing

- **Auth** (`tests/test_wazuh_auth.py`): `BasicAuthStrategy` header format; `JWTBearerAuthStrategy` — first call triggers `refresh()`, token cached and reused, `refresh()` re-authenticates (respx-mocked `/security/user/authenticate`).
- **`WazuhConnector` methods** (`tests/test_wazuh_connector.py`): respx-mocked Indexer/Manager responses for all 5 methods, including a 401-then-refresh-then-retry-succeeds test and a 401-then-refresh-then-401-again-propagates test for the Manager path.
- **Alert mapper** (`tests/test_wazuh_alert_mapper.py`): pure unit tests against fixture JSON (using the verbatim example alert from §1's source, plus a syslog/sshd-shaped variant with `full_log` populated) — no HTTP involved at all.
- **Real-instance smoke test** (`tests/test_wazuh_connector_live.py`): a fixture checks `Settings().wazuh_indexer_url` etc. are all set; if not, `pytest.skip("WAZUH_* settings not configured")`. If configured, runs `health_check()` and a small real `pull_alerts()`/`search()` call, and is exactly where the §6 timestamp-field check gets resolved empirically.

---

## Open Items for the Implementation Plan

1. Resolve §6 (timestamp field name) empirically against the live instance as an early task step — this affects `pull_alerts`'s and `search()`'s range-query construction.
2. The exact 401 error-body `detail` text for an *expired* (vs. missing/invalid) token isn't confirmed in official docs (only generic examples) — the retry-on-401 logic should key off the status code alone, not the error message, so this doesn't block anything, but worth a one-line note in the plan so nobody adds message-string matching later.
3. `health_check()`'s Manager-side call is settled as a lightweight authenticated call (e.g. `GET /agents?limit=1`, per §5) rather than a bare unauthenticated `GET /` — this also incidentally verifies the auth flow works, not just that the port is open. Carry this into the plan's code as-is, not as an open "or."
