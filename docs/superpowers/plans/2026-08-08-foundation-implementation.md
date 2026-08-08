# Foundation (Schemas + Config + AlertStore) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundational, dependency-free layer of the Local SIEM Alert Investigation Agent — the `Alert`/`Report`/`EnrichmentResult` domain schemas, typed config loading, and a SQLite-backed `AlertStore` — so every later subsystem (Enrichment, Integration, Agentic Analyst) has a stable base to build against.

**Architecture:** Pure Pydantic domain models (`app/schemas.py`) are used everywhere in application code and have no SQLAlchemy dependency. A parallel, separate set of SQLModel table classes (`app/storage/models.py`) exists only for persistence; nested structures are stored as JSON columns as plain `dict`/`list[dict]`, and `SQLiteAlertStore` (`app/storage/sqlite_alert_store.py`) is the only code that converts between the two. This avoids the SQLModel gotcha of trying to store nested Pydantic model instances directly in a JSON column, and keeps domain code free of persistence concerns.

**Tech Stack:** Python 3.11+, Pydantic v2, SQLModel (SQLAlchemy + Pydantic), pydantic-settings, pytest, SQLite.

## Global Constraints

- Python >= 3.11 (per `X | None` union syntax used throughout CLAUDE.md's Protocol definitions).
- Dependencies per CLAUDE.md §6 Tech Stack Recommendation: `pydantic`, `pydantic-settings`, `sqlmodel`.
- Storage is SQLite only in this plan (CLAUDE.md's Context item 4: "designed so it can be swapped for Postgres later" — that swap is a future `AlertStore` implementation, not in scope here).
- Alembic migrations (also named in §6) are deferred until the schema needs to evolve post-deployment — this plan uses `SQLModel.metadata.create_all()` for the initial schema. Introducing migration tooling before there's a second schema version is premature per YAGNI.
- This is a POC per CLAUDE.md §8 — no production data, no real Wazuh credentials anywhere in code, tests, or fixtures.
- TDD: every method/model gets a failing test before implementation.
- Commit after each task.

---

### Task 1: Project scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `app/__init__.py`
- Create: `app/storage/__init__.py`
- Create: `tests/__init__.py`

**Interfaces:**
- Produces: an installable `app` package and a working `pytest` command, used by every subsequent task.

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "wazuh-local-agent"
version = "0.1.0"
description = "Local SIEM alert investigation agent"
requires-python = ">=3.11"
dependencies = [
    "pydantic>=2.6,<3",
    "pydantic-settings>=2.2,<3",
    "sqlmodel>=0.0.16,<0.1",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0,<9",
]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
include = ["app*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
```

- [ ] **Step 2: Write `.gitignore`**

```
.venv/
__pycache__/
*.pyc
.env
data/
*.db
.pytest_cache/
*.egg-info/
```

- [ ] **Step 3: Create empty package files**

```bash
mkdir -p app/storage tests
touch app/__init__.py app/storage/__init__.py tests/__init__.py
```

- [ ] **Step 4: Create venv and install**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

- [ ] **Step 5: Verify package and test discovery work**

```bash
python -c "import app; print('ok')"
pytest --collect-only
```

Expected: `ok` printed, and pytest reports 0 tests collected with no errors.

- [ ] **Step 6: Initialize git and commit**

```bash
git init
git add pyproject.toml .gitignore app tests
git commit -m "chore: scaffold project structure"
```

---

### Task 2: Enums and simple value objects

**Files:**
- Create: `app/schemas.py`
- Test: `tests/test_schemas.py`

**Interfaces:**
- Produces: `AlertStatus`, `ReportStatus`, `Severity`, `Confidence`, `IndicatorType`, `EnrichmentVerdict` (all `str, Enum`), `AgentRef`, `MitreRef` (both `BaseModel`) — consumed by every later task in this plan.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_schemas.py
import pytest
from pydantic import ValidationError

from app.schemas import (
    AgentRef,
    AlertStatus,
    Confidence,
    EnrichmentVerdict,
    IndicatorType,
    MitreRef,
    ReportStatus,
    Severity,
)


def test_alert_status_members():
    assert {s.value for s in AlertStatus} == {"new", "in_progress", "investigated", "closed"}


def test_report_status_members():
    assert {s.value for s in ReportStatus} == {"draft", "complete", "needs_human_review"}


def test_severity_members():
    assert {s.value for s in Severity} == {"low", "medium", "high", "critical"}


def test_confidence_members():
    assert {s.value for s in Confidence} == {"low", "medium", "high"}


def test_indicator_type_members():
    assert {s.value for s in IndicatorType} == {"ip", "domain", "url", "file_hash", "email"}


def test_enrichment_verdict_members():
    assert {s.value for s in EnrichmentVerdict} == {"malicious", "suspicious", "clean", "unknown"}


def test_agent_ref_requires_all_fields():
    agent = AgentRef(id="001", name="web-01", ip="10.0.0.5")
    assert agent.id == "001"
    with pytest.raises(ValidationError):
        AgentRef(id="001", name="web-01")


def test_mitre_ref_requires_all_fields():
    ref = MitreRef(tactic="Initial Access", technique_id="T1190", technique_name="Exploit Public-Facing Application")
    assert ref.technique_id == "T1190"
    with pytest.raises(ValidationError):
        MitreRef(tactic="Initial Access", technique_id="T1190")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.schemas'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/schemas.py
from enum import Enum

from pydantic import BaseModel


class AlertStatus(str, Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    INVESTIGATED = "investigated"
    CLOSED = "closed"


class ReportStatus(str, Enum):
    DRAFT = "draft"
    COMPLETE = "complete"
    NEEDS_HUMAN_REVIEW = "needs_human_review"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"


class EnrichmentVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    CLEAN = "clean"
    UNKNOWN = "unknown"


class AgentRef(BaseModel):
    id: str
    name: str
    ip: str


class MitreRef(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_schemas.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add app/schemas.py tests/test_schemas.py
git commit -m "feat: add enums and AgentRef/MitreRef value objects"
```

---

### Task 3: `Alert` domain model

**Files:**
- Modify: `app/schemas.py`
- Modify: `tests/test_schemas.py`

**Interfaces:**
- Consumes: `AlertStatus`, `AgentRef`, `MitreRef` (Task 2).
- Produces: `Alert(BaseModel)` — consumed by Task 6 (`AlertRecord`), Task 7 (`SQLiteAlertStore`), and every later subsystem plan.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_schemas.py`:

```python
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from app.schemas import Alert


def _make_alert(**overrides: Any) -> Alert:
    defaults: dict[str, Any] = dict(
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
        full_log="Nov 10 12:00:00 web-01 sshd[123]: Invalid user admin from 203.0.113.5",
        raw_json={"rule": {"id": "5710"}},
    )
    defaults.update(overrides)
    return Alert(**defaults)


def test_alert_defaults_status_to_new():
    alert = _make_alert()
    assert alert.status == AlertStatus.NEW
    assert alert.rule_groups == []
    assert alert.data == {}
    assert alert.mitre is None


def test_alert_rejects_non_integer_rule_level():
    with pytest.raises(ValidationError):
        _make_alert(rule_level="not-a-number")


def test_alert_accepts_optional_network_fields():
    alert = _make_alert(source_ip="203.0.113.5", source_port=51820)
    assert alert.source_ip == "203.0.113.5"
    assert alert.destination_ip is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL with `ImportError: cannot import name 'Alert' from 'app.schemas'`

- [ ] **Step 3: Write minimal implementation**

Update the import block at the top of `app/schemas.py`:

```python
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field
```

Append to `app/schemas.py`:

```python
class Alert(BaseModel):
    alert_id: UUID
    source_alert_id: str
    source_system: str
    rule_id: str
    rule_description: str
    rule_level: int
    rule_groups: list[str] = Field(default_factory=list)
    mitre: list[MitreRef] | None = None
    timestamp: datetime
    ingested_at: datetime
    agent: AgentRef
    manager_name: str
    location: str
    full_log: str
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    src_user: str | None = None
    dst_user: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    raw_json: dict[str, Any]
    status: AlertStatus = AlertStatus.NEW
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_schemas.py -v`
Expected: PASS (11 tests)

- [ ] **Step 5: Commit**

```bash
git add app/schemas.py tests/test_schemas.py
git commit -m "feat: add Alert domain model"
```

---

### Task 4: `EnrichmentResult`, `Report`, and their nested value objects

**Files:**
- Modify: `app/schemas.py`
- Modify: `tests/test_schemas.py`

**Interfaces:**
- Consumes: `IndicatorType`, `EnrichmentVerdict`, `Severity`, `Confidence`, `ReportStatus` (Task 2).
- Produces: `EnrichmentResult`, `InvestigationStep`, `RiskAssessment`, `ModelMetadata`, `Report` (all `BaseModel`) — consumed by Task 6 (`ReportRecord`), Task 8 (`SQLiteAlertStore`), and later the Agentic Analyst plan.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_schemas.py`:

```python
from app.schemas import (
    Confidence,
    EnrichmentResult,
    EnrichmentVerdict,
    IndicatorType,
    InvestigationStep,
    ModelMetadata,
    Report,
    ReportStatus,
    RiskAssessment,
    Severity,
)


def _make_report(**overrides: Any) -> Report:
    defaults: dict[str, Any] = dict(
        report_id=uuid4(),
        alert_id=uuid4(),
        generated_at=datetime.now(timezone.utc),
        alert_summary="Repeated SSH login failures from an external IP against a single host.",
        risk_assessment=RiskAssessment(severity=Severity.MEDIUM, confidence=Confidence.HIGH, rationale="3 failed logins in 5 minutes from an unrecognised IP."),
        model_metadata=ModelMetadata(model_name="qwen2.5-7b-instruct", model_version="q4_0", prompt_version="v1"),
    )
    defaults.update(overrides)
    return Report(**defaults)


def test_enrichment_result_requires_score_in_range():
    result = EnrichmentResult(
        indicator_type=IndicatorType.IP,
        indicator_value="203.0.113.5",
        provider_id="abuseipdb",
        queried_at=datetime.now(timezone.utc),
        verdict=EnrichmentVerdict.SUSPICIOUS,
        score=42.0,
        cache_expires_at=datetime.now(timezone.utc),
    )
    assert result.raw_response == {}
    with pytest.raises(ValidationError):
        EnrichmentResult(
            indicator_type=IndicatorType.IP,
            indicator_value="203.0.113.5",
            provider_id="abuseipdb",
            queried_at=datetime.now(timezone.utc),
            verdict=EnrichmentVerdict.SUSPICIOUS,
            score=142.0,
            cache_expires_at=datetime.now(timezone.utc),
        )


def test_report_defaults():
    report = _make_report()
    assert report.status == ReportStatus.DRAFT
    assert report.investigation_timeline == []
    assert report.enrichment_findings == []
    assert report.recommended_actions_freeform_experimental is None
    assert report.uncertainty_notes == ""


def test_report_accepts_nested_investigation_step_and_enrichment_finding():
    step = InvestigationStep(
        step_name="correlate",
        action="run_canonical_searches",
        output_summary="12 related alerts found for this src_ip in 24h",
        timestamp=datetime.now(timezone.utc),
    )
    finding = EnrichmentResult(
        indicator_type=IndicatorType.IP,
        indicator_value="203.0.113.5",
        provider_id="abuseipdb",
        queried_at=datetime.now(timezone.utc),
        verdict=EnrichmentVerdict.SUSPICIOUS,
        score=42.0,
        cache_expires_at=datetime.now(timezone.utc),
    )
    report = _make_report(investigation_timeline=[step], enrichment_findings=[finding])
    assert report.investigation_timeline[0].step_name == "correlate"
    assert report.enrichment_findings[0].verdict == EnrichmentVerdict.SUSPICIOUS
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_schemas.py -v`
Expected: FAIL with `ImportError: cannot import name 'EnrichmentResult' from 'app.schemas'`

- [ ] **Step 3: Write minimal implementation**

Append to `app/schemas.py`:

```python
class EnrichmentResult(BaseModel):
    indicator_type: IndicatorType
    indicator_value: str
    provider_id: str
    queried_at: datetime
    verdict: EnrichmentVerdict
    score: float = Field(ge=0, le=100)
    raw_response: dict[str, Any] = Field(default_factory=dict)
    cache_expires_at: datetime
    error: str | None = None


class InvestigationStep(BaseModel):
    step_name: str
    action: str
    tool_used: str | None = None
    input: dict[str, Any] | None = None
    output_summary: str
    timestamp: datetime


class RiskAssessment(BaseModel):
    severity: Severity
    confidence: Confidence
    rationale: str


class ModelMetadata(BaseModel):
    model_name: str
    model_version: str
    prompt_version: str


class Report(BaseModel):
    report_id: UUID
    alert_id: UUID
    generated_at: datetime
    alert_summary: str
    investigation_timeline: list[InvestigationStep] = Field(default_factory=list)
    enrichment_findings: list[EnrichmentResult] = Field(default_factory=list)
    risk_assessment: RiskAssessment
    recommended_actions: list[str] = Field(default_factory=list)
    recommended_actions_freeform_experimental: list[str] | None = None
    uncertainty_notes: str = ""
    status: ReportStatus = ReportStatus.DRAFT
    model_metadata: ModelMetadata
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_schemas.py -v`
Expected: PASS (14 tests)

- [ ] **Step 5: Commit**

```bash
git add app/schemas.py tests/test_schemas.py
git commit -m "feat: add EnrichmentResult and Report domain models"
```

---

### Task 5: Typed config loading

**Files:**
- Create: `app/config.py`
- Create: `.env.example`
- Test: `tests/test_config.py`

**Interfaces:**
- Produces: `Settings(BaseSettings)` with `database_path: str` and `log_level: str`, and `get_settings() -> Settings` — consumed by Task 6 (`get_engine(settings.database_path)`) and every later subsystem that needs config.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
from app.config import Settings


def test_settings_defaults():
    settings = Settings(_env_file=None)
    assert settings.database_path == "./data/alerts.db"
    assert settings.log_level == "INFO"


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", "/tmp/custom.db")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    settings = Settings(_env_file=None)
    assert settings.database_path == "/tmp/custom.db"
    assert settings.log_level == "DEBUG"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.config'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_path: str = "./data/alerts.db"
    log_level: str = "INFO"


def get_settings() -> Settings:
    return Settings()
```

```
# .env.example
# Copy to .env and fill in real values. No secrets or real credentials belong in this file.
DATABASE_PATH=./data/alerts.db
LOG_LEVEL=INFO
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_config.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add app/config.py .env.example tests/test_config.py
git commit -m "feat: add typed settings loading via pydantic-settings"
```

---

### Task 6: SQLModel persistence records and DB bootstrap

**Files:**
- Create: `app/storage/models.py`
- Create: `app/storage/db.py`
- Test: `tests/test_storage_models.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (deliberately plain `dict`/`list[dict]` typed, not the domain models) — this is the persistence-only layer described in the Architecture note above.
- Produces: `AlertRecord`, `ReportRecord` (SQLModel `table=True` classes), `get_engine(database_path: str)`, `init_db(engine) -> None`, `get_session(engine) -> Session` — consumed by Task 7 and Task 8.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_storage_models.py
from sqlmodel import select

from app.storage.db import get_engine, get_session, init_db
from app.storage.models import AlertRecord


def test_init_db_creates_alerts_table(tmp_path):
    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)

    record = AlertRecord(
        alert_id="11111111-1111-1111-1111-111111111111",
        source_alert_id="1699999999.123456",
        source_system="wazuh",
        rule_id="5710",
        rule_description="sshd: Attempt to login using a non-existent user",
        rule_level=5,
        timestamp="2026-08-08T12:00:00",
        ingested_at="2026-08-08T12:00:05",
        agent={"id": "001", "name": "web-01", "ip": "10.0.0.5"},
        manager_name="wazuh-manager",
        location="/var/log/auth.log",
        full_log="Invalid user admin from 203.0.113.5",
        raw_json={"rule": {"id": "5710"}},
    )
    with get_session(engine) as session:
        session.add(record)
        session.commit()

    with get_session(engine) as session:
        loaded = session.exec(select(AlertRecord)).first()
        assert loaded.rule_id == "5710"
        assert loaded.agent["name"] == "web-01"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_storage_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.storage.models'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/storage/models.py
from datetime import datetime
from typing import Any

from sqlmodel import JSON, Column, Field, SQLModel


class AlertRecord(SQLModel, table=True):
    __tablename__ = "alerts"

    alert_id: str = Field(primary_key=True)
    source_alert_id: str
    source_system: str
    rule_id: str
    rule_description: str
    rule_level: int
    rule_groups: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    mitre: list[dict[str, Any]] | None = Field(default=None, sa_column=Column(JSON))
    timestamp: datetime
    ingested_at: datetime
    agent: dict[str, Any] = Field(sa_column=Column(JSON))
    manager_name: str
    location: str
    full_log: str
    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    src_user: str | None = None
    dst_user: str | None = None
    data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    raw_json: dict[str, Any] = Field(sa_column=Column(JSON))
    status: str = Field(default="new", index=True)


class ReportRecord(SQLModel, table=True):
    __tablename__ = "reports"

    report_id: str = Field(primary_key=True)
    alert_id: str = Field(index=True)
    generated_at: datetime
    alert_summary: str
    investigation_timeline: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    enrichment_findings: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    risk_assessment: dict[str, Any] = Field(sa_column=Column(JSON))
    recommended_actions: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    recommended_actions_freeform_experimental: list[str] | None = Field(default=None, sa_column=Column(JSON))
    uncertainty_notes: str = ""
    status: str = Field(default="draft")
    model_metadata: dict[str, Any] = Field(sa_column=Column(JSON))
```

```python
# app/storage/db.py
from sqlmodel import Session, SQLModel, create_engine

from app.storage import models  # noqa: F401  (registers table metadata on import)


def get_engine(database_path: str):
    return create_engine(f"sqlite:///{database_path}")


def init_db(engine) -> None:
    SQLModel.metadata.create_all(engine)


def get_session(engine) -> Session:
    return Session(engine)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_storage_models.py -v`
Expected: PASS (1 test)

- [ ] **Step 5: Commit**

```bash
git add app/storage/models.py app/storage/db.py tests/test_storage_models.py
git commit -m "feat: add SQLModel persistence records and DB bootstrap"
```

---

### Task 7: `SQLiteAlertStore` — alert-side methods

**Files:**
- Create: `app/storage/alert_store.py`
- Create: `app/storage/sqlite_alert_store.py`
- Test: `tests/test_sqlite_alert_store.py`

**Interfaces:**
- Consumes: `Alert`, `AlertStatus`, `Report`, `Severity` (Task 2–4); `AlertRecord`, `ReportRecord`, `get_engine`, `get_session`, `init_db` (Task 6).
- Produces: `AlertStore(Protocol)`; `AlertNotFoundError`, `ReportNotFoundError`; `SQLiteAlertStore` with `save_raw_alert`, `get_alert`, `list_alerts`, `update_alert_status` implemented (report-side methods raise `NotImplementedError` until Task 8) — consumed by Task 8 and every later subsystem that reads/writes alerts.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_sqlite_alert_store.py
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import pytest

from app.schemas import AgentRef, Alert, AlertStatus
from app.storage.db import get_engine, init_db
from app.storage.sqlite_alert_store import AlertNotFoundError, SQLiteAlertStore


def _make_alert(**overrides: Any) -> Alert:
    defaults: dict[str, Any] = dict(
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


@pytest.fixture
def store(tmp_path):
    engine = get_engine(str(tmp_path / "test.db"))
    init_db(engine)
    return SQLiteAlertStore(engine)


def test_save_and_get_alert_round_trips(store):
    alert = _make_alert()
    store.save_raw_alert(alert)

    loaded = store.get_alert(str(alert.alert_id))
    assert loaded.rule_id == "5710"
    assert loaded.agent.name == "web-01"
    assert loaded.status == AlertStatus.NEW


def test_get_alert_raises_when_missing(store):
    with pytest.raises(AlertNotFoundError):
        store.get_alert(str(uuid4()))


def test_update_alert_status(store):
    alert = _make_alert()
    store.save_raw_alert(alert)

    store.update_alert_status(str(alert.alert_id), AlertStatus.IN_PROGRESS)

    loaded = store.get_alert(str(alert.alert_id))
    assert loaded.status == AlertStatus.IN_PROGRESS


def test_list_alerts_filters_by_status(store):
    a1 = _make_alert()
    a2 = _make_alert(alert_id=uuid4())
    store.save_raw_alert(a1)
    store.save_raw_alert(a2)
    store.update_alert_status(str(a1.alert_id), AlertStatus.CLOSED)

    new_alerts = store.list_alerts(status=AlertStatus.NEW)
    assert len(new_alerts) == 1
    assert new_alerts[0].alert_id == a2.alert_id
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_sqlite_alert_store.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.storage.sqlite_alert_store'`

- [ ] **Step 3: Write minimal implementation**

```python
# app/storage/alert_store.py
from datetime import datetime
from typing import Protocol

from app.schemas import Alert, AlertStatus, Report, Severity


class AlertStore(Protocol):
    def save_raw_alert(self, alert: Alert) -> str: ...
    def get_alert(self, alert_id: str) -> Alert: ...
    def list_alerts(
        self, status: AlertStatus | None, since: datetime | None, limit: int = 100
    ) -> list[Alert]: ...
    def update_alert_status(self, alert_id: str, status: AlertStatus) -> None: ...
    def save_report(self, report: Report) -> str: ...
    def get_report(self, report_id: str) -> Report: ...
    def get_report_for_alert(self, alert_id: str) -> Report | None: ...
    def list_reports(
        self, since: datetime | None, min_severity: Severity | None
    ) -> list[Report]: ...
```

```python
# app/storage/sqlite_alert_store.py
from datetime import datetime

from sqlmodel import Session, select

from app.schemas import Alert, AlertStatus, Report, Severity
from app.storage.models import AlertRecord, ReportRecord


class AlertNotFoundError(Exception):
    pass


class ReportNotFoundError(Exception):
    pass


def _alert_to_record(alert: Alert) -> AlertRecord:
    return AlertRecord(
        alert_id=str(alert.alert_id),
        source_alert_id=alert.source_alert_id,
        source_system=alert.source_system,
        rule_id=alert.rule_id,
        rule_description=alert.rule_description,
        rule_level=alert.rule_level,
        rule_groups=alert.rule_groups,
        mitre=[m.model_dump() for m in alert.mitre] if alert.mitre else None,
        timestamp=alert.timestamp,
        ingested_at=alert.ingested_at,
        agent=alert.agent.model_dump(),
        manager_name=alert.manager_name,
        location=alert.location,
        full_log=alert.full_log,
        source_ip=alert.source_ip,
        source_port=alert.source_port,
        destination_ip=alert.destination_ip,
        destination_port=alert.destination_port,
        src_user=alert.src_user,
        dst_user=alert.dst_user,
        data=alert.data,
        raw_json=alert.raw_json,
        status=alert.status.value,
    )


def _record_to_alert(record: AlertRecord) -> Alert:
    return Alert(
        alert_id=record.alert_id,
        source_alert_id=record.source_alert_id,
        source_system=record.source_system,
        rule_id=record.rule_id,
        rule_description=record.rule_description,
        rule_level=record.rule_level,
        rule_groups=record.rule_groups,
        mitre=record.mitre,
        timestamp=record.timestamp,
        ingested_at=record.ingested_at,
        agent=record.agent,
        manager_name=record.manager_name,
        location=record.location,
        full_log=record.full_log,
        source_ip=record.source_ip,
        source_port=record.source_port,
        destination_ip=record.destination_ip,
        destination_port=record.destination_port,
        src_user=record.src_user,
        dst_user=record.dst_user,
        data=record.data,
        raw_json=record.raw_json,
        status=AlertStatus(record.status),
    )


class SQLiteAlertStore:
    def __init__(self, engine) -> None:
        self._engine = engine

    def save_raw_alert(self, alert: Alert) -> str:
        record = _alert_to_record(alert)
        with Session(self._engine) as session:
            session.add(record)
            session.commit()
        return str(alert.alert_id)

    def get_alert(self, alert_id: str) -> Alert:
        with Session(self._engine) as session:
            record = session.get(AlertRecord, alert_id)
            if record is None:
                raise AlertNotFoundError(alert_id)
            return _record_to_alert(record)

    def list_alerts(
        self, status: AlertStatus | None = None, since: datetime | None = None, limit: int = 100
    ) -> list[Alert]:
        with Session(self._engine) as session:
            query = select(AlertRecord)
            if status is not None:
                query = query.where(AlertRecord.status == status.value)
            if since is not None:
                query = query.where(AlertRecord.timestamp >= since)
            query = query.order_by(AlertRecord.timestamp.desc()).limit(limit)
            records = session.exec(query).all()
            return [_record_to_alert(r) for r in records]

    def update_alert_status(self, alert_id: str, status: AlertStatus) -> None:
        with Session(self._engine) as session:
            record = session.get(AlertRecord, alert_id)
            if record is None:
                raise AlertNotFoundError(alert_id)
            record.status = status.value
            session.add(record)
            session.commit()

    def save_report(self, report: Report) -> str:
        raise NotImplementedError("added in Task 8")

    def get_report(self, report_id: str) -> Report:
        raise NotImplementedError("added in Task 8")

    def get_report_for_alert(self, alert_id: str) -> Report | None:
        raise NotImplementedError("added in Task 8")

    def list_reports(
        self, since: datetime | None = None, min_severity: Severity | None = None
    ) -> list[Report]:
        raise NotImplementedError("added in Task 8")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_sqlite_alert_store.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add app/storage/alert_store.py app/storage/sqlite_alert_store.py tests/test_sqlite_alert_store.py
git commit -m "feat: implement AlertStore Protocol and alert-side SQLiteAlertStore methods"
```

---

### Task 8: `SQLiteAlertStore` — report-side methods

**Files:**
- Modify: `app/storage/sqlite_alert_store.py`
- Modify: `tests/test_sqlite_alert_store.py`

**Interfaces:**
- Consumes: `Report`, `ReportStatus`, `RiskAssessment`, `ModelMetadata`, `Confidence`, `Severity` (Task 4); `ReportRecord` (Task 6); `_make_alert`, `store` fixture (Task 7's test file).
- Produces: `save_report`, `get_report`, `get_report_for_alert`, `list_reports` fully implemented — completing the `AlertStore` Protocol contract used by every later subsystem.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_sqlite_alert_store.py`:

```python
from app.schemas import Confidence, ModelMetadata, Report, RiskAssessment


def _make_report(alert_id, **overrides: Any) -> Report:
    defaults: dict[str, Any] = dict(
        report_id=uuid4(),
        alert_id=alert_id,
        generated_at=datetime.now(timezone.utc),
        alert_summary="Repeated SSH login failures from an external IP against a single host.",
        risk_assessment=RiskAssessment(severity=Severity.MEDIUM, confidence=Confidence.HIGH, rationale="3 failed logins in 5 minutes."),
        model_metadata=ModelMetadata(model_name="qwen2.5-7b-instruct", model_version="q4_0", prompt_version="v1"),
    )
    defaults.update(overrides)
    return Report(**defaults)


def test_save_and_get_report_round_trips(store):
    alert = _make_alert()
    store.save_raw_alert(alert)
    report = _make_report(alert.alert_id)

    store.save_report(report)

    loaded = store.get_report(str(report.report_id))
    assert loaded.alert_summary == report.alert_summary
    assert loaded.risk_assessment.severity == Severity.MEDIUM


def test_get_report_for_alert(store):
    alert = _make_alert()
    store.save_raw_alert(alert)
    report = _make_report(alert.alert_id)
    store.save_report(report)

    found = store.get_report_for_alert(str(alert.alert_id))
    assert found is not None
    assert found.report_id == report.report_id
    assert store.get_report_for_alert(str(uuid4())) is None


def test_list_reports_filters_by_min_severity(store):
    alert = _make_alert()
    store.save_raw_alert(alert)
    low = _make_report(
        alert.alert_id,
        risk_assessment=RiskAssessment(severity=Severity.LOW, confidence=Confidence.LOW, rationale="x"),
    )
    high = _make_report(
        alert.alert_id,
        report_id=uuid4(),
        risk_assessment=RiskAssessment(severity=Severity.HIGH, confidence=Confidence.HIGH, rationale="y"),
    )
    store.save_report(low)
    store.save_report(high)

    results = store.list_reports(since=None, min_severity=Severity.HIGH)
    assert {r.report_id for r in results} == {high.report_id}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_sqlite_alert_store.py -v`
Expected: FAIL with `NotImplementedError: added in Task 8`

- [ ] **Step 3: Write minimal implementation**

Update the import block at the top of `app/storage/sqlite_alert_store.py`:

```python
from datetime import datetime

from sqlmodel import Session, select

from app.schemas import Alert, AlertStatus, Report, ReportStatus, Severity
from app.storage.models import AlertRecord, ReportRecord
```

Add these two module-level functions to `app/storage/sqlite_alert_store.py` (alongside `_alert_to_record`/`_record_to_alert`):

```python
def _report_to_record(report: Report) -> ReportRecord:
    return ReportRecord(
        report_id=str(report.report_id),
        alert_id=str(report.alert_id),
        generated_at=report.generated_at,
        alert_summary=report.alert_summary,
        investigation_timeline=[s.model_dump() for s in report.investigation_timeline],
        enrichment_findings=[e.model_dump() for e in report.enrichment_findings],
        risk_assessment=report.risk_assessment.model_dump(),
        recommended_actions=report.recommended_actions,
        recommended_actions_freeform_experimental=report.recommended_actions_freeform_experimental,
        uncertainty_notes=report.uncertainty_notes,
        status=report.status.value,
        model_metadata=report.model_metadata.model_dump(),
    )


def _record_to_report(record: ReportRecord) -> Report:
    return Report(
        report_id=record.report_id,
        alert_id=record.alert_id,
        generated_at=record.generated_at,
        alert_summary=record.alert_summary,
        investigation_timeline=record.investigation_timeline,
        enrichment_findings=record.enrichment_findings,
        risk_assessment=record.risk_assessment,
        recommended_actions=record.recommended_actions,
        recommended_actions_freeform_experimental=record.recommended_actions_freeform_experimental,
        uncertainty_notes=record.uncertainty_notes,
        status=ReportStatus(record.status),
        model_metadata=record.model_metadata,
    )
```

Replace the four `NotImplementedError` method bodies in `SQLiteAlertStore` with:

```python
    def save_report(self, report: Report) -> str:
        record = _report_to_record(report)
        with Session(self._engine) as session:
            session.add(record)
            session.commit()
        return str(report.report_id)

    def get_report(self, report_id: str) -> Report:
        with Session(self._engine) as session:
            record = session.get(ReportRecord, report_id)
            if record is None:
                raise ReportNotFoundError(report_id)
            return _record_to_report(record)

    def get_report_for_alert(self, alert_id: str) -> Report | None:
        with Session(self._engine) as session:
            query = select(ReportRecord).where(ReportRecord.alert_id == alert_id)
            record = session.exec(query).first()
            return _record_to_report(record) if record else None

    def list_reports(
        self, since: datetime | None = None, min_severity: Severity | None = None
    ) -> list[Report]:
        with Session(self._engine) as session:
            query = select(ReportRecord)
            if since is not None:
                query = query.where(ReportRecord.generated_at >= since)
            records = session.exec(query).all()
            reports = [_record_to_report(r) for r in records]
            if min_severity is not None:
                order = list(Severity)
                min_index = order.index(min_severity)
                reports = [r for r in reports if order.index(r.risk_assessment.severity) >= min_index]
            return reports
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/ -v`
Expected: PASS (all tests across the whole suite — 3 test files' worth from Tasks 2–8)

- [ ] **Step 5: Commit**

```bash
git add app/storage/sqlite_alert_store.py tests/test_sqlite_alert_store.py
git commit -m "feat: implement report-side SQLiteAlertStore methods"
```
