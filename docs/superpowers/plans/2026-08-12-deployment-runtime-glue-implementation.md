# Deployment / Runtime Glue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire Phases 1-4's modules into a runnable `typer` CLI: pull alerts from Wazuh, investigate them, browse the results — all one-shot commands over the real `SQLiteAlertStore`.

**Architecture:** A single wiring module (`app/wiring.py`) turns a `Settings` instance into concrete Protocol implementations; a `typer` CLI (`app/cli.py`) exposes seven one-shot commands, each a thin shell around a directly-testable logic function; a small `app/report_export.py` writes each investigated report to disk as JSON, alongside the SQLite persistence `AgenticAnalyst.investigate()` already does internally.

**Tech Stack:** `typer` (new dependency), the existing `pydantic-settings`/`SQLModel`/`httpx` stack — nothing else new.

## Global Constraints

- **One-shot commands only** — no background thread, no polling loop, no in-process queue, nothing to gracefully shut down. Each command does its one job and exits.
- **CLI only** — no FastAPI viewer in this plan.
- **`wazuh_deployment/` is untouched** — no changes to the Wazuh docker-compose config in this plan.
- `WazuhConnector.pull_alerts`'s `since` filter is inclusive (`gte`) — reusing the latest stored alert's own timestamp as the next call's `since` will re-fetch that alert every time. `pull-alerts` must catch `DuplicateAlertError` per alert and continue, not treat it as fatal.
- `SIEMConnector` and `LLMClient` are `@runtime_checkable` Protocols; `AlertStore` and `EnrichmentProvider` are plain `Protocol` (not runtime-checkable) — `isinstance()` against the latter two raises `TypeError`, not a clean pass/fail. Tests must assert on concrete types or behavior for `AlertStore`/`EnrichmentProvider`, and may use `isinstance()` freely for `SIEMConnector`/`LLMClient`.
- `add-alert`'s input file is a raw Wazuh `_source` document (the shape `wazuh_source_to_alert()` already expects — the same shape a real Wazuh indexer document's `_source` field has), never this project's internal `Alert` JSON shape.
- Every CLI command that can fail on bad input (not-found IDs, malformed files, invalid `--status`/`--min-severity` values) must print a one-line friendly message to stderr and exit with code 1 — never let a raw Python traceback reach the terminal for an expected failure mode.
- `build_analyst(settings, alert_store=None)` must accept an already-built `AlertStore` and use it instead of building a second one, so a CLI command that needs both the analyst and direct `AlertStore` access (`investigate-all`/`investigate-one`) shares one `SQLiteAlertStore`/engine instance rather than opening two separate SQLite connections to the same file in one process.

---

### Task 1: `Settings.reports_dir` + `.env.example` + `typer` dependency

**Files:**
- Modify: `app/config.py`
- Modify: `.env.example`
- Modify: `pyproject.toml`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `Settings.reports_dir: str` (default `"./data/reports"`) — consumed by Task 3 (`write_report_file`) and Task 5 (`investigate-all`/`investigate-one`).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_config.py`:

```python
def test_settings_reports_dir_defaults_and_env_override(monkeypatch):
    settings = Settings(_env_file=None)
    assert settings.reports_dir == "./data/reports"

    monkeypatch.setenv("REPORTS_DIR", "/tmp/custom-reports")
    settings = Settings(_env_file=None)
    assert settings.reports_dir == "/tmp/custom-reports"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py -k reports_dir -v`
Expected: FAIL with `AttributeError: 'Settings' object has no attribute 'reports_dir'`.

- [ ] **Step 3: Add the field**

In `app/config.py`, add to the `Settings` class (after `database_path: str = "./data/alerts.db"`):

```python
    reports_dir: str = "./data/reports"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py -k reports_dir -v`
Expected: PASS.

- [ ] **Step 5: Update `.env.example`**

Add, right after the `DATABASE_PATH=./data/alerts.db` line in `.env.example`:

```
REPORTS_DIR=./data/reports
```

- [ ] **Step 6: Add the `typer` dependency and console-script entry point**

In `pyproject.toml`, add `"typer>=0.12,<1"` to the `[project]` `dependencies` list (alongside `pydantic`, `httpx`, etc. — it's a runtime dependency, the CLI needs it to run, not just `dev`):

```toml
dependencies = [
    "pydantic>=2.6,<3",
    "pydantic-settings>=2.2,<3",
    "sqlalchemy>=2.0,<3",  # imported directly for IntegrityError; also a sqlmodel dep
    "sqlmodel>=0.0.16,<0.1",
    "httpx>=0.27,<1",
    "openai>=1.50,<2",
    "typer>=0.12,<1",
]
```

Add a `[project.scripts]` table (new, right after `[project.optional-dependencies]`):

```toml
[project.scripts]
agent = "app.cli:main"
```

- [ ] **Step 7: Install the new dependency**

Run: `pip install -e ".[dev]"`
Expected: `typer` installs without error (this is required before Task 4's tests can import `app.cli`, but Task 4 doesn't exist as a module yet — this step just confirms the dependency resolves cleanly now).

- [ ] **Step 8: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS (this task only adds a config field and a dependency — nothing else changes).

- [ ] **Step 9: Commit**

```bash
git add app/config.py .env.example pyproject.toml tests/test_config.py
git commit -m "feat: add Settings.reports_dir and the typer dependency"
```

---

### Task 2: `app/wiring.py`

**Files:**
- Create: `app/wiring.py`
- Test: `tests/test_wiring.py`

**Interfaces:**
- Consumes: `Settings` (Task 1's `reports_dir` isn't used here, but `database_path`, `wazuh_*`, `llm_*`, `abuseipdb_api_key`, `virustotal_api_key` all are — all pre-existing `Settings` fields).
- Produces: `build_siem_connector(settings) -> SIEMConnector`, `build_llm_client(settings) -> LLMClient`, `build_alert_store(settings) -> AlertStore`, `build_enrichment_registry(settings) -> EnrichmentRegistry`, `build_analyst(settings, alert_store=None) -> AgenticAnalyst` — all consumed by Task 4/5/6's CLI commands.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_wiring.py`:

```python
from app.config import Settings
from app.enrichment.providers.abuseipdb import AbuseIPDBProvider
from app.enrichment.providers.virustotal import VirusTotalProvider
from app.integration.siem_connector import SIEMConnector
from app.integration.wazuh_connector import WazuhConnector
from app.llm.client import LLMClient
from app.llm.ollama_client import OllamaClient
from app.schemas import IndicatorType
from app.storage.sqlite_alert_store import SQLiteAlertStore
from app.wiring import (
    build_alert_store,
    build_analyst,
    build_enrichment_registry,
    build_llm_client,
    build_siem_connector,
)


def _wazuh_settings(**overrides) -> Settings:
    defaults = dict(
        wazuh_indexer_url="https://localhost:9200",
        wazuh_indexer_username="admin",
        wazuh_indexer_password="pw",
        wazuh_manager_url="https://localhost:55000",
        wazuh_manager_username="wazuh-wui",
        wazuh_manager_password="pw2",
        _env_file=None,
    )
    defaults.update(overrides)
    return Settings(**defaults)


def test_build_siem_connector_returns_a_wazuh_connector():
    connector = build_siem_connector(_wazuh_settings())
    assert isinstance(connector, WazuhConnector)
    assert isinstance(connector, SIEMConnector)


def test_build_siem_connector_raises_on_missing_settings():
    settings = Settings(_env_file=None)  # no wazuh_* fields set
    try:
        build_siem_connector(settings)
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "WAZUH_INDEXER_URL" in str(exc)


def test_build_llm_client_returns_an_ollama_client():
    client = build_llm_client(Settings(_env_file=None))
    assert isinstance(client, OllamaClient)
    assert isinstance(client, LLMClient)


def test_build_alert_store_returns_a_sqlite_alert_store(tmp_path):
    settings = Settings(database_path=str(tmp_path / "test.db"), _env_file=None)
    store = build_alert_store(settings)
    assert isinstance(store, SQLiteAlertStore)


def test_build_enrichment_registry_registers_nothing_when_no_keys_set():
    registry = build_enrichment_registry(Settings(_env_file=None))
    assert registry.providers_for(IndicatorType.IP) == []
    assert registry.providers_for(IndicatorType.DOMAIN) == []


def test_build_enrichment_registry_registers_abuseipdb_when_key_set():
    registry = build_enrichment_registry(Settings(abuseipdb_api_key="key123", _env_file=None))
    providers = registry.providers_for(IndicatorType.IP)
    assert len(providers) == 1
    assert isinstance(providers[0], AbuseIPDBProvider)


def test_build_enrichment_registry_registers_virustotal_when_key_set():
    registry = build_enrichment_registry(Settings(virustotal_api_key="key456", _env_file=None))
    providers = registry.providers_for(IndicatorType.DOMAIN)
    assert len(providers) == 1
    assert isinstance(providers[0], VirusTotalProvider)


def test_build_analyst_reuses_a_passed_in_alert_store(tmp_path):
    settings = Settings(database_path=str(tmp_path / "test.db"), _env_file=None)
    alert_store = build_alert_store(settings)
    from app.agent.state_graph import AgenticAnalyst

    analyst = build_analyst(settings, alert_store=alert_store)
    assert isinstance(analyst, AgenticAnalyst)
    assert analyst._alert_store is alert_store


def test_build_analyst_builds_its_own_alert_store_when_none_given(tmp_path):
    settings = Settings(database_path=str(tmp_path / "test.db"), _env_file=None)
    from app.agent.state_graph import AgenticAnalyst

    analyst = build_analyst(settings)
    assert isinstance(analyst, AgenticAnalyst)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_wiring.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.wiring'`.

- [ ] **Step 3: Write `app/wiring.py`**

```python
from app.agent.state_graph import AgenticAnalyst
from app.config import Settings
from app.enrichment.providers.abuseipdb import AbuseIPDBProvider
from app.enrichment.providers.virustotal import VirusTotalProvider
from app.enrichment.registry import EnrichmentRegistry
from app.integration.siem_connector import SIEMConnector
from app.integration.wazuh_connector import WazuhConnector
from app.llm.client import LLMClient
from app.llm.ollama_client import OllamaClient
from app.storage.alert_store import AlertStore
from app.storage.db import get_engine, init_db
from app.storage.sqlite_alert_store import SQLiteAlertStore


def build_siem_connector(settings: Settings) -> SIEMConnector:
    required = [
        ("WAZUH_INDEXER_URL", settings.wazuh_indexer_url),
        ("WAZUH_INDEXER_USERNAME", settings.wazuh_indexer_username),
        ("WAZUH_INDEXER_PASSWORD", settings.wazuh_indexer_password),
        ("WAZUH_MANAGER_URL", settings.wazuh_manager_url),
        ("WAZUH_MANAGER_USERNAME", settings.wazuh_manager_username),
        ("WAZUH_MANAGER_PASSWORD", settings.wazuh_manager_password),
    ]
    missing = [name for name, value in required if not value]
    if missing:
        raise RuntimeError(f"Missing required Wazuh settings: {', '.join(missing)}")
    return WazuhConnector(
        indexer_url=settings.wazuh_indexer_url,
        indexer_username=settings.wazuh_indexer_username,
        indexer_password=settings.wazuh_indexer_password,
        manager_url=settings.wazuh_manager_url,
        manager_username=settings.wazuh_manager_username,
        manager_password=settings.wazuh_manager_password,
        verify_ssl=settings.wazuh_verify_ssl,
    )


def build_llm_client(settings: Settings) -> LLMClient:
    return OllamaClient(
        base_url=settings.llm_base_url,
        model=settings.llm_model,
        timeout_seconds=settings.llm_timeout_seconds,
    )


def build_alert_store(settings: Settings) -> AlertStore:
    engine = get_engine(settings.database_path)
    init_db(engine)
    return SQLiteAlertStore(engine)


def build_enrichment_registry(settings: Settings) -> EnrichmentRegistry:
    registry = EnrichmentRegistry()
    if settings.abuseipdb_api_key:
        registry.register(AbuseIPDBProvider(api_key=settings.abuseipdb_api_key))
    if settings.virustotal_api_key:
        registry.register(VirusTotalProvider(api_key=settings.virustotal_api_key))
    return registry


def build_analyst(settings: Settings, alert_store: AlertStore | None = None) -> AgenticAnalyst:
    return AgenticAnalyst(
        siem=build_siem_connector(settings),
        alert_store=alert_store if alert_store is not None else build_alert_store(settings),
        enrichment_registry=build_enrichment_registry(settings),
        llm_client=build_llm_client(settings),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_wiring.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add app/wiring.py tests/test_wiring.py
git commit -m "feat: add app/wiring.py building real dependencies from Settings"
```

---

### Task 3: `app/report_export.py`

**Files:**
- Create: `app/report_export.py`
- Test: `tests/test_report_export.py`

**Interfaces:**
- Consumes: `Report` (existing, `app.schemas`).
- Produces: `write_report_file(report: Report, reports_dir: Path) -> Path` — consumed by Task 5's `investigate-all`/`investigate-one`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_report_export.py`:

```python
from pathlib import Path

from tests.test_schemas import _make_report
from app.report_export import write_report_file
from app.schemas import Report


def test_write_report_file_creates_directory_and_writes_json(tmp_path):
    reports_dir = tmp_path / "reports"
    report = _make_report()

    written_path = write_report_file(report, reports_dir)

    assert reports_dir.exists()
    assert written_path == reports_dir / f"{report.report_id}.json"
    assert written_path.exists()


def test_write_report_file_round_trips(tmp_path):
    reports_dir = tmp_path / "reports"
    report = _make_report()

    written_path = write_report_file(report, reports_dir)

    loaded = Report.model_validate_json(written_path.read_text())
    assert loaded == report


def test_write_report_file_works_when_directory_already_exists(tmp_path):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    report = _make_report()

    written_path = write_report_file(report, reports_dir)

    assert written_path.exists()
```

`tests/test_schemas.py`'s `_make_report` is importable directly (it's a module-level function, not a class) — no changes needed there.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_report_export.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.report_export'`.

- [ ] **Step 3: Write `app/report_export.py`**

```python
from pathlib import Path

from app.schemas import Report


def write_report_file(report: Report, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{report.report_id}.json"
    path.write_text(report.model_dump_json(indent=2))
    return path
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_report_export.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add app/report_export.py tests/test_report_export.py
git commit -m "feat: add app/report_export.py for file-based report artefacts"
```

---

### Task 4: `app/cli.py` scaffold + `pull-alerts` + `add-alert`

**Files:**
- Create: `app/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `build_siem_connector`, `build_alert_store` (Task 2); `AlertStore`/`SIEMConnector` Protocols (existing); `wazuh_source_to_alert` (existing, `app.integration.wazuh_connector`); `DuplicateAlertError` (existing, `app.storage.sqlite_alert_store`).
- Produces: the `typer.Typer()` app instance (module-level `app` in `app/cli.py`) and `main()` entry point — both Task 5 and Task 6 add more `@app.command()`-decorated functions to this same file/app object. Also produces `_resolve_since(alert_store) -> datetime` and the test fakes `_FakeSIEMConnector`/`_FakeAlertStore` in `tests/test_cli.py` — Tasks 5 and 6 extend both fakes' configurability as needed and reuse them.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cli.py`:

```python
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from typer.testing import CliRunner

from app.schemas import Alert, AgentRef
from app.storage.sqlite_alert_store import DuplicateAlertError
from app.cli import _add_alert, _pull_alerts, _resolve_since, app


runner = CliRunner()


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


class _FakeSIEMConnector:
    def __init__(self, pull_alerts_result=None):
        self._pull_alerts_result = pull_alerts_result or []
        self.pull_alerts_calls = []

    def health_check(self):
        return True

    def pull_alerts(self, since, until=None, limit=500):
        self.pull_alerts_calls.append((since, until, limit))
        return self._pull_alerts_result

    def search(self, query):
        raise NotImplementedError

    def get_agent_context(self, agent_id):
        raise NotImplementedError

    def get_rule_metadata(self, rule_id):
        raise NotImplementedError


class _FakeAlertStore:
    def __init__(self, alerts=None, duplicate_alert_ids=None, reports=None):
        self._alerts_by_id = {str(a.alert_id): a for a in (alerts or [])}
        self._duplicate_alert_ids = duplicate_alert_ids or set()
        self._reports_by_id = {str(r.report_id): r for r in (reports or [])}
        self.saved_alerts = []
        self.status_updates = []

    def save_raw_alert(self, alert):
        if str(alert.alert_id) in self._duplicate_alert_ids:
            raise DuplicateAlertError(str(alert.alert_id))
        self.saved_alerts.append(alert)
        self._alerts_by_id[str(alert.alert_id)] = alert
        return str(alert.alert_id)

    def get_alert(self, alert_id):
        from app.storage.sqlite_alert_store import AlertNotFoundError

        if alert_id not in self._alerts_by_id:
            raise AlertNotFoundError(alert_id)
        return self._alerts_by_id[alert_id]

    def list_alerts(self, status=None, since=None, limit=100):
        alerts = list(self._alerts_by_id.values())
        if status is not None:
            alerts = [a for a in alerts if a.status == status]
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return alerts[:limit]

    def update_alert_status(self, alert_id, status):
        self.status_updates.append((alert_id, status))

    def save_report(self, report):
        self._reports_by_id[str(report.report_id)] = report
        return str(report.report_id)

    def get_report(self, report_id):
        from app.storage.sqlite_alert_store import ReportNotFoundError

        if report_id not in self._reports_by_id:
            raise ReportNotFoundError(report_id)
        return self._reports_by_id[report_id]

    def get_report_for_alert(self, alert_id):
        return None

    def list_reports(self, since=None, min_severity=None):
        return list(self._reports_by_id.values())


def test_resolve_since_uses_latest_stored_alert_timestamp():
    latest = _make_alert(timestamp=datetime(2026, 8, 1, tzinfo=timezone.utc))
    older = _make_alert(alert_id=uuid4(), timestamp=datetime(2026, 7, 1, tzinfo=timezone.utc))
    store = _FakeAlertStore(alerts=[latest, older])

    resolved = _resolve_since(store)

    assert resolved == datetime(2026, 8, 1, tzinfo=timezone.utc)


def test_resolve_since_falls_back_to_24h_ago_when_store_empty():
    store = _FakeAlertStore()

    resolved = _resolve_since(store)

    assert (datetime.now(timezone.utc) - resolved) < timedelta(hours=24, minutes=1)
    assert (datetime.now(timezone.utc) - resolved) > timedelta(hours=23, minutes=59)


def test_pull_alerts_saves_new_alerts_and_counts_duplicates():
    alert_a = _make_alert()
    alert_b = _make_alert(alert_id=uuid4())
    siem = _FakeSIEMConnector(pull_alerts_result=[alert_a, alert_b])
    store = _FakeAlertStore(duplicate_alert_ids={str(alert_b.alert_id)})

    new_count, duplicate_count, resolved_since = _pull_alerts(
        siem, store, since=datetime(2026, 1, 1, tzinfo=timezone.utc), limit=500
    )

    assert new_count == 1
    assert duplicate_count == 1
    assert resolved_since == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert store.saved_alerts == [alert_a]


def test_pull_alerts_command_prints_summary(monkeypatch):
    alert_a = _make_alert()
    siem = _FakeSIEMConnector(pull_alerts_result=[alert_a])
    store = _FakeAlertStore()

    monkeypatch.setattr("app.cli.build_siem_connector", lambda settings: siem)
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["pull-alerts", "--since", "2026-01-01T00:00:00+00:00"])

    assert result.exit_code == 0
    assert "Pulled 1 new alert(s), skipped 0 already-stored" in result.stdout


def test_add_alert_saves_alert_from_wazuh_shaped_file(tmp_path):
    store = _FakeAlertStore()
    source = {
        "id": "1699999999.123456",
        "rule": {"id": "5710", "description": "sshd brute force", "level": 5, "groups": ["authentication_failed"]},
        "timestamp": "2026-08-01T00:00:00+00:00",
        "agent": {"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        "manager": {"name": "wazuh-manager"},
        "location": "/var/log/auth.log",
        "full_log": "Invalid user admin from 203.0.113.5",
        "data": {},
    }
    file_path = tmp_path / "alert.json"
    file_path.write_text(json.dumps(source))

    alert = _add_alert(store, file_path)

    assert alert.rule_id == "5710"
    assert store.saved_alerts == [alert]


def test_add_alert_command_reports_malformed_file(tmp_path, monkeypatch):
    store = _FakeAlertStore()
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)
    file_path = tmp_path / "bad.json"
    file_path.write_text("not json at all")

    result = runner.invoke(app, ["add-alert", str(file_path)])

    assert result.exit_code == 1
    assert "Could not add alert" in result.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.cli'`.

- [ ] **Step 3: Write `app/cli.py`**

```python
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import typer

from app.config import get_settings
from app.integration.siem_connector import SIEMConnector
from app.integration.wazuh_connector import wazuh_source_to_alert
from app.storage.alert_store import AlertStore
from app.storage.sqlite_alert_store import DuplicateAlertError
from app.wiring import build_alert_store, build_siem_connector

app = typer.Typer()


def _resolve_since(alert_store: AlertStore) -> datetime:
    latest = alert_store.list_alerts(limit=1)
    if latest:
        return latest[0].timestamp
    return datetime.now(timezone.utc) - timedelta(hours=24)


def _pull_alerts(
    siem: SIEMConnector, alert_store: AlertStore, since: datetime | None, limit: int
) -> tuple[int, int, datetime]:
    resolved_since = since if since is not None else _resolve_since(alert_store)
    alerts = siem.pull_alerts(since=resolved_since, until=None, limit=limit)
    new_count = 0
    duplicate_count = 0
    for alert in alerts:
        try:
            alert_store.save_raw_alert(alert)
            new_count += 1
        except DuplicateAlertError:
            duplicate_count += 1
    return new_count, duplicate_count, resolved_since


@app.command(name="pull-alerts")
def pull_alerts_cmd(
    since: str = typer.Option(
        None, "--since", help="ISO-8601 timestamp; defaults to the latest stored alert's time, or 24h ago if empty."
    ),
    limit: int = typer.Option(500, "--limit"),
) -> None:
    settings = get_settings()
    siem = build_siem_connector(settings)
    alert_store = build_alert_store(settings)
    parsed_since = datetime.fromisoformat(since) if since else None
    new_count, duplicate_count, resolved_since = _pull_alerts(siem, alert_store, parsed_since, limit)
    typer.echo(
        f"Pulled {new_count} new alert(s), skipped {duplicate_count} already-stored, "
        f"since {resolved_since.isoformat()}."
    )


def _add_alert(alert_store: AlertStore, file_path: Path):
    raw = json.loads(file_path.read_text())
    alert = wazuh_source_to_alert(raw)
    alert_store.save_raw_alert(alert)
    return alert


@app.command(name="add-alert")
def add_alert_cmd(file: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    settings = get_settings()
    alert_store = build_alert_store(settings)
    try:
        alert = _add_alert(alert_store, file)
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as exc:
        typer.echo(f"Could not add alert from {file}: {exc}", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"Saved alert {alert.alert_id} (rule {alert.rule_id}).")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
```

`typer.Argument(..., exists=True, readable=True)` already rejects a missing/unreadable file with a clean usage error before `add_alert_cmd`'s body runs — no separate `FileNotFoundError` handling needed.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add app/cli.py tests/test_cli.py
git commit -m "feat: add CLI scaffold with pull-alerts and add-alert commands"
```

---

### Task 5: `investigate-all` + `investigate-one`

**Files:**
- Modify: `app/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `build_analyst` (Task 2); `write_report_file` (Task 3); `app`, `_FakeSIEMConnector`, `_FakeAlertStore`, `_make_alert` (Task 4, same file — read the current state of `tests/test_cli.py` before editing, don't redefine these).
- Produces: `_investigate_alert(analyst, alert, reports_dir) -> Report`, `_summary_line(report) -> str` — not consumed by any later task, but keep both as module-level functions in `app/cli.py` for Task 6's reviewer to find easily if it needs the same summary format (it doesn't, but consistency matters).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py` (after the existing `add-alert` tests). A fake analyst is needed — the CLI layer only depends on `AgenticAnalyst.investigate(alert) -> Report`, not its internals, so a minimal stand-in is enough (no need to construct a real `AgenticAnalyst` with four nested fakes):

```python
from tests.test_schemas import _make_report
from app.schemas import AlertStatus


class _FakeAnalyst:
    def __init__(self, report):
        self._report = report
        self.investigated_alerts = []

    def investigate(self, alert):
        self.investigated_alerts.append(alert)
        return self._report


def test_investigate_alert_calls_analyst_and_writes_report_file(tmp_path):
    from app.cli import _investigate_alert

    alert = _make_alert()
    report = _make_report(alert_id=alert.alert_id)
    analyst = _FakeAnalyst(report)
    reports_dir = tmp_path / "reports"

    result = _investigate_alert(analyst, alert, reports_dir)

    assert result == report
    assert analyst.investigated_alerts == [alert]
    assert (reports_dir / f"{report.report_id}.json").exists()


def test_investigate_all_command_prints_no_alerts_message(monkeypatch):
    store = _FakeAlertStore()
    monkeypatch.setattr("app.cli.build_analyst", lambda settings, alert_store=None: _FakeAnalyst(_make_report()))
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["investigate-all"])

    assert result.exit_code == 0
    assert "No new alerts to investigate." in result.stdout


def test_investigate_all_command_investigates_each_new_alert(monkeypatch, tmp_path):
    new_alert = _make_alert(status=AlertStatus.NEW)
    closed_alert = _make_alert(alert_id=uuid4(), status=AlertStatus.CLOSED)
    store = _FakeAlertStore(alerts=[new_alert, closed_alert])
    report = _make_report(alert_id=new_alert.alert_id)
    analyst = _FakeAnalyst(report)

    monkeypatch.setattr("app.cli.build_analyst", lambda settings, alert_store=None: analyst)
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))

    result = runner.invoke(app, ["investigate-all"])

    assert result.exit_code == 0
    assert analyst.investigated_alerts == [new_alert]
    assert str(report.report_id) in result.stdout


def test_investigate_one_command_reports_not_found(monkeypatch):
    store = _FakeAlertStore()
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)
    monkeypatch.setattr("app.cli.build_analyst", lambda settings, alert_store=None: _FakeAnalyst(_make_report()))

    result = runner.invoke(app, ["investigate-one", "nonexistent-id"])

    assert result.exit_code == 1
    assert "No alert found with id nonexistent-id" in result.stdout


def test_investigate_one_command_investigates_the_named_alert(monkeypatch, tmp_path):
    alert = _make_alert()
    store = _FakeAlertStore(alerts=[alert])
    report = _make_report(alert_id=alert.alert_id)
    analyst = _FakeAnalyst(report)

    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)
    monkeypatch.setattr("app.cli.build_analyst", lambda settings, alert_store=None: analyst)
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path / "reports"))

    result = runner.invoke(app, ["investigate-one", str(alert.alert_id)])

    assert result.exit_code == 0
    assert analyst.investigated_alerts == [alert]
    assert str(report.report_id) in result.stdout
```

`tests/test_schemas.py`'s `_make_report` is reused the same way Task 3 already reuses it. `monkeypatch.setenv("REPORTS_DIR", ...)` is used rather than trying to patch `Settings.reports_dir` directly — Pydantic v2 reads field defaults from `model_fields`, not a plain class attribute, so `monkeypatch.setattr(Settings, "reports_dir", ...)` would silently have no effect on `Settings()` construction. Environment variables are pydantic-settings' standard override mechanism (already used this way throughout `tests/test_config.py`) and take priority over any real `.env` file a developer's machine might have, so this is also the correct fix for a subtler, codebase-wide risk: `get_settings()` is called fresh inside every CLI command with no `_env_file=None`, so it reads a real `.env` if one exists. This doesn't affect most of this plan's tests (they monkeypatch `build_alert_store`/`build_analyst`/`build_siem_connector` themselves, which ignore whatever `Settings` object they're handed), but it matters here because `investigate-all`/`investigate-one` read `settings.reports_dir` directly, not through a mocked builder.

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -k investigate -v`
Expected: FAIL — `_investigate_alert` doesn't exist yet, and `investigate-all`/`investigate-one` aren't registered commands.

- [ ] **Step 3: Add the commands to `app/cli.py`**

Add these imports to the existing import block:

```python
from app.report_export import write_report_file
from app.schemas import AlertStatus, Report
from app.storage.sqlite_alert_store import AlertNotFoundError
from app.wiring import build_analyst
```

Add, after `add_alert_cmd` and before `def main()`:

```python
def _investigate_alert(analyst, alert, reports_dir: Path) -> Report:
    report = analyst.investigate(alert)
    write_report_file(report, reports_dir)
    return report


def _summary_line(report: Report) -> str:
    return f"{report.report_id} | {report.risk_assessment.severity.value:8} | {report.status.value}"


@app.command(name="investigate-all")
def investigate_all_cmd() -> None:
    settings = get_settings()
    alert_store = build_alert_store(settings)
    analyst = build_analyst(settings, alert_store=alert_store)
    reports_dir = Path(settings.reports_dir)

    alerts = alert_store.list_alerts(status=AlertStatus.NEW)
    if not alerts:
        typer.echo("No new alerts to investigate.")
        return

    for alert in alerts:
        report = _investigate_alert(analyst, alert, reports_dir)
        typer.echo(_summary_line(report))


@app.command(name="investigate-one")
def investigate_one_cmd(alert_id: str = typer.Argument(...)) -> None:
    settings = get_settings()
    alert_store = build_alert_store(settings)
    analyst = build_analyst(settings, alert_store=alert_store)
    reports_dir = Path(settings.reports_dir)

    try:
        alert = alert_store.get_alert(alert_id)
    except AlertNotFoundError:
        typer.echo(f"No alert found with id {alert_id}.", err=True)
        raise typer.Exit(code=1)

    report = _investigate_alert(analyst, alert, reports_dir)
    typer.echo(_summary_line(report))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add app/cli.py tests/test_cli.py
git commit -m "feat: add investigate-all and investigate-one CLI commands"
```

---

### Task 6: `list-alerts` + `list-reports` + `show-report`

**Files:**
- Modify: `app/cli.py`
- Modify: `tests/test_cli.py`

**Interfaces:**
- Consumes: `app`, `_FakeAlertStore`, `_make_alert`, `_make_report` (Tasks 4/5, same files — read current state before editing).
- Produces: nothing consumed by a later task (this is the last task in the plan).

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_cli.py`:

```python
def test_list_alerts_command_prints_table(monkeypatch):
    alert = _make_alert()
    store = _FakeAlertStore(alerts=[alert])
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["list-alerts"])

    assert result.exit_code == 0
    assert str(alert.alert_id) in result.stdout
    assert alert.rule_id in result.stdout


def test_list_alerts_command_prints_empty_message(monkeypatch):
    store = _FakeAlertStore()
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["list-alerts"])

    assert result.exit_code == 0
    assert "No alerts found." in result.stdout


def test_list_alerts_command_rejects_invalid_status(monkeypatch):
    store = _FakeAlertStore()
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["list-alerts", "--status", "not-a-real-status"])

    assert result.exit_code == 1
    assert "Invalid status" in result.stdout


def test_list_reports_command_prints_table(monkeypatch):
    report = _make_report()
    store = _FakeAlertStore(reports=[report])
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["list-reports"])

    assert result.exit_code == 0
    assert str(report.report_id) in result.stdout


def test_list_reports_command_rejects_invalid_severity(monkeypatch):
    store = _FakeAlertStore()
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["list-reports", "--min-severity", "not-a-real-severity"])

    assert result.exit_code == 1
    assert "Invalid severity" in result.stdout


def test_show_report_command_reports_not_found(monkeypatch):
    store = _FakeAlertStore()
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["show-report", "nonexistent-id"])

    assert result.exit_code == 1
    assert "No report found with id nonexistent-id" in result.stdout


def test_show_report_command_prints_human_readable_detail(monkeypatch):
    report = _make_report(
        recommended_actions=["Block the source IP at the network perimeter"],
        uncertainty_notes="no MITRE ATT&CK mapping available for this alert",
    )
    store = _FakeAlertStore(reports=[report])
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["show-report", str(report.report_id)])

    assert result.exit_code == 0
    assert report.alert_summary in result.stdout
    assert "Block the source IP at the network perimeter" in result.stdout
    assert "no MITRE ATT&CK mapping available for this alert" in result.stdout


def test_show_report_command_json_output(monkeypatch):
    report = _make_report()
    store = _FakeAlertStore(reports=[report])
    monkeypatch.setattr("app.cli.build_alert_store", lambda settings: store)

    result = runner.invoke(app, ["show-report", str(report.report_id), "--json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["report_id"] == str(report.report_id)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py -k "list_alerts or list_reports or show_report" -v`
Expected: FAIL — none of these three commands exist yet.

- [ ] **Step 3: Add the commands to `app/cli.py`**

Add to the existing import block:

```python
from app.schemas import AlertStatus, Report, Severity
from app.storage.sqlite_alert_store import ReportNotFoundError
```

(`AlertStatus`/`Report` are already imported from Task 5 — only add `Severity` and `ReportNotFoundError` if not already present.)

Add, after `investigate_one_cmd` and before `def main()`:

```python
def _parse_status(value: str | None) -> AlertStatus | None:
    if value is None:
        return None
    try:
        return AlertStatus(value.lower())
    except ValueError:
        valid = ", ".join(s.value for s in AlertStatus)
        typer.echo(f"Invalid status {value!r}. Must be one of: {valid}", err=True)
        raise typer.Exit(code=1)


def _parse_severity(value: str | None) -> Severity | None:
    if value is None:
        return None
    try:
        return Severity(value.lower())
    except ValueError:
        valid = ", ".join(s.value for s in Severity)
        typer.echo(f"Invalid severity {value!r}. Must be one of: {valid}", err=True)
        raise typer.Exit(code=1)


def _format_alerts_table(alerts) -> str:
    if not alerts:
        return "No alerts found."
    lines = ["alert_id | rule_id | rule_description | level | status | timestamp"]
    for a in alerts:
        lines.append(
            f"{a.alert_id} | {a.rule_id} | {a.rule_description} | {a.rule_level} | "
            f"{a.status.value} | {a.timestamp.isoformat()}"
        )
    return "\n".join(lines)


@app.command(name="list-alerts")
def list_alerts_cmd(
    status: str = typer.Option(None, "--status"),
    limit: int = typer.Option(100, "--limit"),
) -> None:
    settings = get_settings()
    alert_store = build_alert_store(settings)
    parsed_status = _parse_status(status)
    alerts = alert_store.list_alerts(status=parsed_status, limit=limit)
    typer.echo(_format_alerts_table(alerts))


def _format_reports_table(reports) -> str:
    if not reports:
        return "No reports found."
    lines = ["report_id | alert_id | severity | status | generated_at"]
    for r in reports:
        lines.append(
            f"{r.report_id} | {r.alert_id} | {r.risk_assessment.severity.value} | "
            f"{r.status.value} | {r.generated_at.isoformat()}"
        )
    return "\n".join(lines)


@app.command(name="list-reports")
def list_reports_cmd(
    since: str = typer.Option(None, "--since"),
    min_severity: str = typer.Option(None, "--min-severity"),
) -> None:
    settings = get_settings()
    alert_store = build_alert_store(settings)
    parsed_since = datetime.fromisoformat(since) if since else None
    parsed_min_severity = _parse_severity(min_severity)
    reports = alert_store.list_reports(since=parsed_since, min_severity=parsed_min_severity)
    typer.echo(_format_reports_table(reports))


def _format_report_detail(report: Report) -> str:
    lines = [
        f"Report {report.report_id} (alert {report.alert_id})",
        f"Status: {report.status.value}",
        f"Generated: {report.generated_at.isoformat()}",
        "",
        "Summary:",
        report.alert_summary,
        "",
        f"Risk: severity={report.risk_assessment.severity.value}, confidence={report.risk_assessment.confidence.value}",
        report.risk_assessment.rationale,
        "",
        "Recommended actions:",
        *[f"  - {a}" for a in report.recommended_actions],
        "",
        f"Uncertainty notes: {report.uncertainty_notes or '(none)'}",
        "",
        "Timeline:",
        *[f"  - {s.step_name}: {s.action}" for s in report.investigation_timeline],
    ]
    return "\n".join(lines)


@app.command(name="show-report")
def show_report_cmd(
    report_id: str = typer.Argument(...),
    as_json: bool = typer.Option(False, "--json"),
) -> None:
    settings = get_settings()
    alert_store = build_alert_store(settings)
    try:
        report = alert_store.get_report(report_id)
    except ReportNotFoundError:
        typer.echo(f"No report found with id {report_id}.", err=True)
        raise typer.Exit(code=1)
    if as_json:
        typer.echo(report.model_dump_json(indent=2))
    else:
        typer.echo(_format_report_detail(report))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py -v`
Expected: all PASS.

- [ ] **Step 5: Run the full test suite**

Run: `pytest tests/ -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add app/cli.py tests/test_cli.py
git commit -m "feat: add list-alerts, list-reports, and show-report CLI commands"
```

---

## Self-Review Notes (for the plan author, not a task)

- **Spec coverage:** §1 (file structure) → Tasks 1-4 (each new file/setting named in the spec has a task). §2 (all 7 CLI commands) → Task 4 (`pull-alerts`, `add-alert`), Task 5 (`investigate-all`, `investigate-one`), Task 6 (`list-alerts`, `list-reports`, `show-report`). §3 (testing approach) → every task's Step 1/Step 2 pair, using fakes defined once in Task 4 and reused in Tasks 5-6.
- **Deviation from the spec, resolved during planning:** the spec's testing section suggested reusing `tests/test_state_graph.py`'s `_FakeSIEMConnector`/`_FakeAlertStore` "rather than writing a third copy." Re-reading those fakes closely (they hardcode `pull_alerts` to always return `[]`, `list_alerts`/`list_reports` to always return `[]`, and `get_alert`/`get_report` to always raise `NotImplementedError`) showed they're single-purpose fixtures for Phase 4's own tests, not configurable enough for this phase's CLI tests (which need controllable return values and typed not-found/duplicate errors). Task 4 instead defines new, purpose-built fakes directly in `tests/test_cli.py`, reusing only the two genuinely reusable pure functions from other test files (`_make_alert`-equivalent defined locally since the original lives in a file this phase doesn't otherwise touch; `_make_report` imported directly from `tests/test_schemas.py`).
- **Type consistency check:** `build_analyst(settings, alert_store=None)`'s signature (Task 2) is used identically in Task 5's `investigate_all_cmd`/`investigate_one_cmd` and in Task 5's/Task 2's own tests (`build_analyst(settings, alert_store=alert_store)`). `_investigate_alert(analyst, alert, reports_dir)`'s return type (`Report`, Task 5) matches what `_summary_line(report)` (also Task 5) consumes. `write_report_file(report, reports_dir)`'s signature (Task 3) matches its call site inside `_investigate_alert` (Task 5) exactly.
