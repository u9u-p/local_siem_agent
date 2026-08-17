from pathlib import Path

from tests.test_schemas import _make_report
from app.report_export import write_report_file
from app.schemas import Report


def test_write_report_file_writes_both_json_and_markdown(tmp_path):
    reports_dir = tmp_path / "reports"
    report = _make_report()

    json_path, markdown_path = write_report_file(report, reports_dir)

    assert json_path == reports_dir / f"{report.report_id}.json"
    assert markdown_path == reports_dir / f"{report.report_id}.md"
    assert json_path.exists()
    assert markdown_path.exists()


def test_write_report_file_round_trips_the_json(tmp_path):
    report = _make_report()

    json_path, _markdown_path = write_report_file(report, tmp_path / "reports")

    assert Report.model_validate_json(json_path.read_text()) == report


def test_written_markdown_mirrors_the_show_report_sections(tmp_path):
    report = _make_report(recommended_actions=["Escalate to the incident response / Tier 2 team"])

    _json_path, markdown_path = write_report_file(report, tmp_path / "reports")
    content = markdown_path.read_text()

    assert content.startswith(f"# Investigation Report {report.report_id}")
    assert "## Summary" in content
    assert "## Risk" in content
    assert "- Escalate to the incident response / Tier 2 team" in content


def test_write_report_file_works_when_directory_already_exists(tmp_path):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()

    json_path, markdown_path = write_report_file(_make_report(), reports_dir)

    assert json_path.exists()
    assert markdown_path.exists()


def test_only_one_json_file_is_written_per_report(tmp_path):
    """bench/run.py globs *.json and takes files[0]; a second .json would break it."""
    reports_dir = tmp_path / "reports"

    write_report_file(_make_report(), reports_dir)

    assert len(list(reports_dir.glob("*.json"))) == 1
