import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import typer

from app.agent.state_graph import AgenticAnalyst
from app.config import get_settings
from app.integration.siem_connector import SIEMConnector
from app.integration.wazuh_connector import wazuh_source_to_alert
from app.report_export import write_report_file
from app.report_render import render_text, report_sections
from app.schemas import Alert, AlertStatus, Report, Severity
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
    parsed_since = _parse_since(since)
    settings = get_settings()
    try:
        siem = build_siem_connector(settings)
    except RuntimeError as exc:
        typer.echo(f"Cannot pull alerts: {exc}", err=True)
        raise typer.Exit(code=1)
    alert_store = build_alert_store(settings)
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


def _investigate_alert(analyst: AgenticAnalyst, alert: Alert, reports_dir: Path) -> Report:
    report = analyst.investigate(alert)
    write_report_file(report, reports_dir)
    return report


def _build_analyst_and_view(settings, alert_store: AlertStore, tui: bool):
    """Build the analyst, with a PipelineView wired in via on_step when --tui is set.

    Without --tui, build_analyst is called exactly as before (no on_step argument),
    so the default path is unchanged.
    """
    if not tui:
        return build_analyst(settings, alert_store=alert_store), None
    from app.tui import PipelineView

    view = PipelineView()
    return build_analyst(settings, alert_store=alert_store, on_step=view.on_step), view


def _investigate_with_optional_view(analyst, alert: Alert, reports_dir: Path, view) -> Report:
    if view is None:
        return _investigate_alert(analyst, alert, reports_dir)
    from rich.live import Live

    view.reset(
        title=f"rule {alert.rule_id}: {alert.rule_description}",
        subtitle=alert.full_log[:110],
    )
    with Live(view, refresh_per_second=4):
        return _investigate_alert(analyst, alert, reports_dir)


_TUI_OPTION = typer.Option(False, "--tui", help="Show a live 9-step pipeline view while investigating.")


def _summary_line(report: Report) -> str:
    return f"{report.report_id} | {report.risk_assessment.severity.value:8} | {report.status.value}"


def _configure_verbose_logging(verbose: bool, log_file: Path | None) -> None:
    app_logger = logging.getLogger("app")
    for handler in list(app_logger.handlers):
        app_logger.removeHandler(handler)
    if not verbose and log_file is None:
        return
    app_logger.setLevel(logging.DEBUG)
    handler = logging.FileHandler(log_file, mode="a") if log_file is not None else logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    app_logger.addHandler(handler)


@app.command(name="investigate-all")
def investigate_all_cmd(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Log each pipeline stage's input/output at DEBUG level."
    ),
    log_file: Path = typer.Option(
        None, "--log-file", help="Write verbose logs to this file instead of stdout. Implies --verbose."
    ),
    tui: bool = _TUI_OPTION,
) -> None:
    _configure_verbose_logging(verbose, log_file)
    settings = get_settings()
    alert_store = build_alert_store(settings)

    alerts = alert_store.list_alerts(status=AlertStatus.NEW)
    if not alerts:
        typer.echo("No new alerts to investigate.")
        return

    try:
        analyst, view = _build_analyst_and_view(settings, alert_store, tui)
    except RuntimeError as exc:
        typer.echo(f"Cannot investigate: {exc}", err=True)
        raise typer.Exit(code=1)
    reports_dir = Path(settings.reports_dir)

    for alert in alerts:
        try:
            report = _investigate_with_optional_view(analyst, alert, reports_dir, view)
        except OSError as exc:
            typer.echo(f"Failed to write report for alert {alert.alert_id}: {exc}", err=True)
            continue
        typer.echo(_summary_line(report))


@app.command(name="investigate-one")
def investigate_one_cmd(
    alert_id: str = typer.Argument(...),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Log each pipeline stage's input/output at DEBUG level."
    ),
    log_file: Path = typer.Option(
        None, "--log-file", help="Write verbose logs to this file instead of stdout. Implies --verbose."
    ),
    tui: bool = _TUI_OPTION,
) -> None:
    _configure_verbose_logging(verbose, log_file)
    settings = get_settings()
    alert_store = build_alert_store(settings)

    try:
        alert = alert_store.get_alert(alert_id)
    except AlertNotFoundError:
        typer.echo(f"No alert found with id {alert_id}.", err=True)
        raise typer.Exit(code=1)

    try:
        analyst, view = _build_analyst_and_view(settings, alert_store, tui)
    except RuntimeError as exc:
        typer.echo(f"Cannot investigate: {exc}", err=True)
        raise typer.Exit(code=1)
    reports_dir = Path(settings.reports_dir)

    report = _investigate_with_optional_view(analyst, alert, reports_dir, view)
    typer.echo(_summary_line(report))


def _parse_since(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        typer.echo(f"Invalid --since value {value!r}: must be an ISO-8601 timestamp.", err=True)
        raise typer.Exit(code=1)


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
    parsed_status = _parse_status(status)
    settings = get_settings()
    alert_store = build_alert_store(settings)
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
    parsed_since = _parse_since(since)
    parsed_min_severity = _parse_severity(min_severity)
    settings = get_settings()
    alert_store = build_alert_store(settings)
    reports = alert_store.list_reports(since=parsed_since, min_severity=parsed_min_severity)
    typer.echo(_format_reports_table(reports))


def _format_report_detail(report: Report) -> str:
    return render_text(report_sections(report))


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
