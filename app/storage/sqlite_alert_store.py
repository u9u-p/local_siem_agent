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
