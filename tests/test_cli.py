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
    assert "Could not add alert" in result.output
