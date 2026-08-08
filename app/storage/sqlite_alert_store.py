from datetime import datetime

from sqlmodel import Session, select

from app.schemas import Alert, AlertStatus, Report, ReportStatus, Severity
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
