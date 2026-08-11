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
        typer.echo(f"Could not add alert from {file}: {exc}")
        raise typer.Exit(code=1)
    typer.echo(f"Saved alert {alert.alert_id} (rule {alert.rule_id}).")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
