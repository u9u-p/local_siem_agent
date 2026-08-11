from pathlib import Path

from app.schemas import Report


def write_report_file(report: Report, reports_dir: Path) -> Path:
    reports_dir.mkdir(parents=True, exist_ok=True)
    path = reports_dir / f"{report.report_id}.json"
    path.write_text(report.model_dump_json(indent=2))
    return path
