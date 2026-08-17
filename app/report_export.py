from pathlib import Path

from app.report_render import render_markdown, report_sections
from app.schemas import Report


def write_report_file(report: Report, reports_dir: Path) -> tuple[Path, Path]:
    """Write the report as JSON for tooling and as Markdown for a human.

    The Markdown mirrors `show-report` rather than the full JSON: the per-step
    inputs, prompts and call records stay in the JSON, which is where tooling reads
    them, and out of the artefact someone pastes into a ticket.
    """
    reports_dir.mkdir(parents=True, exist_ok=True)
    json_path = reports_dir / f"{report.report_id}.json"
    json_path.write_text(report.model_dump_json(indent=2))
    markdown_path = reports_dir / f"{report.report_id}.md"
    markdown_path.write_text(render_markdown(report, report_sections(report)))
    return json_path, markdown_path
