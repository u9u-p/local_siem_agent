from datetime import datetime

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
        timestamp=datetime.fromisoformat("2026-08-08T12:00:00"),
        ingested_at=datetime.fromisoformat("2026-08-08T12:00:05"),
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
