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
