import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import typer

from app.config import get_settings
from app.integration.siem_connector import SIEMConnector
from app.integration.wazuh_connector import wazuh_source_to_alert
from app.report_export import write_report_file
from app.schemas import AlertStatus, Report, Severity
from app.storage.alert_store import AlertStore
from app.storage.sqlite_alert_store import AlertNotFoundError, DuplicateAlertError, ReportNotFoundError
from app.wiring import build_alert_store, build_analyst, build_siem_connector

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


def main() -> None:
    app()


if __name__ == "__main__":
    main()
