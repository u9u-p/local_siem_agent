from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest

from app.schemas import (
    AgentRef,
    Alert,
    AlertStatus,
    EnrichmentResult,
    EnrichmentVerdict,
    IndicatorType,
    InvestigationStep,
    Severity,
)
from app.storage.db import get_engine, init_db
from app.storage.sqlite_alert_store import (
    AlertNotFoundError,
    DuplicateAlertError,
    SQLiteAlertStore,
)


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
    assert loaded.timestamp == alert.timestamp
    assert loaded.ingested_at == alert.ingested_at
    assert loaded.timestamp.tzinfo is not None


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
    assert loaded.generated_at == report.generated_at
    assert loaded.generated_at.tzinfo is not None


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


def test_save_report_round_trips_nested_datetimes(store):
    """Nested models carry datetimes; they must survive JSON serialisation."""
    alert = _make_alert()
    store.save_raw_alert(alert)
    queried_at = datetime(2026, 8, 8, 9, 30, 0, tzinfo=timezone.utc)
    step = InvestigationStep(
        step_name="enrich",
        action="lookup_indicator",
        tool_used="abuseipdb",
        input={"indicator": "203.0.113.5"},
        output_summary="AbuseIPDB returned a malicious verdict.",
        timestamp=datetime(2026, 8, 8, 9, 29, 0, tzinfo=timezone.utc),
    )
    finding = EnrichmentResult(
        indicator_type=IndicatorType.IP,
        indicator_value="203.0.113.5",
        provider_id="abuseipdb",
        queried_at=queried_at,
        verdict=EnrichmentVerdict.MALICIOUS,
        score=92.5,
        raw_response={"abuseConfidenceScore": 92},
        cache_expires_at=queried_at + timedelta(hours=24),
    )
    report = _make_report(
        alert.alert_id, investigation_timeline=[step], enrichment_findings=[finding]
    )

    store.save_report(report)

    loaded = store.get_report(str(report.report_id))
    assert len(loaded.investigation_timeline) == 1
    assert loaded.investigation_timeline[0].step_name == "enrich"
    assert loaded.investigation_timeline[0].timestamp == step.timestamp
    assert len(loaded.enrichment_findings) == 1
    assert loaded.enrichment_findings[0].verdict == EnrichmentVerdict.MALICIOUS
    assert loaded.enrichment_findings[0].indicator_type == IndicatorType.IP
    assert loaded.enrichment_findings[0].queried_at == queried_at
    assert loaded.enrichment_findings[0].cache_expires_at == finding.cache_expires_at


def test_datetimes_normalise_to_utc_across_input_timezones(store):
    """Naive and non-UTC-aware inputs must still compare and read back correctly."""
    kl = timezone(timedelta(hours=8))  # Asia/Kuala_Lumpur
    aware_kl = datetime(2026, 8, 8, 20, 0, 0, tzinfo=kl)  # == 12:00 UTC
    naive_utc = datetime(2026, 8, 8, 11, 0, 0)  # treated as 11:00 UTC

    aware_alert = _make_alert(timestamp=aware_kl, ingested_at=aware_kl)
    naive_alert = _make_alert(timestamp=naive_utc, ingested_at=naive_utc)
    store.save_raw_alert(aware_alert)
    store.save_raw_alert(naive_alert)

    loaded = store.get_alert(str(aware_alert.alert_id))
    assert loaded.timestamp.tzinfo is not None
    assert loaded.timestamp == aware_kl
    assert loaded.timestamp == datetime(2026, 8, 8, 12, 0, 0, tzinfo=timezone.utc)

    loaded_naive = store.get_alert(str(naive_alert.alert_id))
    assert loaded_naive.timestamp == datetime(2026, 8, 8, 11, 0, 0, tzinfo=timezone.utc)

    # A caller-supplied `since` in a non-UTC zone must filter on the same instant.
    since_kl = datetime(2026, 8, 8, 19, 30, 0, tzinfo=kl)  # == 11:30 UTC
    recent = store.list_alerts(since=since_kl)
    assert {a.alert_id for a in recent} == {aware_alert.alert_id}

    # And a naive `since` is interpreted as UTC.
    recent_naive_since = store.list_alerts(since=datetime(2026, 8, 8, 11, 30, 0))
    assert {a.alert_id for a in recent_naive_since} == {aware_alert.alert_id}

    report = _make_report(aware_alert.alert_id, generated_at=aware_kl)
    store.save_report(report)
    assert store.get_report(str(report.report_id)).generated_at == aware_kl
    assert {r.report_id for r in store.list_reports(since=since_kl, min_severity=None)} == {
        report.report_id
    }


def test_get_report_for_alert_returns_newest(store):
    alert = _make_alert()
    store.save_raw_alert(alert)
    older = _make_report(
        alert.alert_id, generated_at=datetime(2026, 8, 8, 10, 0, 0, tzinfo=timezone.utc)
    )
    newer = _make_report(
        alert.alert_id, generated_at=datetime(2026, 8, 8, 14, 0, 0, tzinfo=timezone.utc)
    )
    # Saved oldest-first so insertion order would return the wrong one.
    store.save_report(older)
    store.save_report(newer)

    found = store.get_report_for_alert(str(alert.alert_id))
    assert found is not None
    assert found.report_id == newer.report_id


def test_save_raw_alert_rejects_duplicate_alert_id(store):
    alert = _make_alert()
    store.save_raw_alert(alert)

    with pytest.raises(DuplicateAlertError):
        store.save_raw_alert(alert)

    # The store stays usable after the rejected write.
    assert store.get_alert(str(alert.alert_id)).rule_id == "5710"


def test_get_engine_creates_missing_parent_directory(tmp_path):
    db_path = tmp_path / "does-not-exist-yet" / "nested" / "alerts.db"
    assert not db_path.parent.exists()

    engine = get_engine(str(db_path))
    init_db(engine)
    store = SQLiteAlertStore(engine)
    alert = _make_alert()
    store.save_raw_alert(alert)

    assert store.get_alert(str(alert.alert_id)).rule_id == "5710"
    assert db_path.exists()
