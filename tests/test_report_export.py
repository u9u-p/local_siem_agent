from pathlib import Path

from tests.test_schemas import _make_report
from app.report_export import write_report_file
from app.schemas import Report


def test_write_report_file_creates_directory_and_writes_json(tmp_path):
    reports_dir = tmp_path / "reports"
    report = _make_report()

    written_path = write_report_file(report, reports_dir)

    assert reports_dir.exists()
    assert written_path == reports_dir / f"{report.report_id}.json"
    assert written_path.exists()


def test_write_report_file_round_trips(tmp_path):
    reports_dir = tmp_path / "reports"
    report = _make_report()

    written_path = write_report_file(report, reports_dir)

    loaded = Report.model_validate_json(written_path.read_text())
    assert loaded == report


def test_write_report_file_works_when_directory_already_exists(tmp_path):
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir()
    report = _make_report()

    written_path = write_report_file(report, reports_dir)

    assert written_path.exists()
