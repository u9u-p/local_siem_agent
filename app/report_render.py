from dataclasses import dataclass, field

from app.schemas import Report


@dataclass
class Section:
    """One block of a rendered report.

    Sections are built once and rendered twice — as terminal text and as Markdown —
    so the two artefacts cannot drift. A section with an empty body and no bullets is
    dropped by both renderers, which is how optional sections are omitted.
    """

    title: str | None = None
    body: list[str] = field(default_factory=list)
    bullets: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.body and not self.bullets


def report_sections(report: Report) -> list[Section]:
    sections = [
        Section(body=[
            f"Report {report.report_id} (alert {report.alert_id})",
            f"Status: {report.status.value}",
            f"Generated: {report.generated_at.isoformat()}",
        ]),
        Section(title="Summary", body=[report.alert_summary]),
        Section(title="Risk", body=[
            f"severity={report.risk_assessment.severity.value}, "
            f"confidence={report.risk_assessment.confidence.value}",
            report.risk_assessment.rationale,
        ]),
        Section(title="Recommended actions", bullets=list(report.recommended_actions)),
    ]

    if report.command_analysis is not None:
        sections.append(Section(
            title="Command analysis",
            body=[f"Command line: {report.command_analysis.command_line or '(none)'}"],
            bullets=[
                f"[{s.encoding}] {s.decoded}" for s in report.command_analysis.decoded_segments
            ],
        ))

    sections.append(Section(
        title="Uncertainty notes", body=[report.uncertainty_notes or "(none)"]
    ))
    sections.append(Section(
        title="Timeline",
        bullets=[f"{s.step_name}: {s.action}" for s in report.investigation_timeline],
    ))
    return [s for s in sections if not s.is_empty()]


def render_text(sections: list[Section]) -> str:
    lines: list[str] = []
    for index, section in enumerate(sections):
        if index:
            lines.append("")
        if section.title == "Risk":
            # The established layout runs the title into its first line rather than
            # putting it on one of its own: "Risk: severity=..., confidence=...".
            lines.append(f"Risk: {section.body[0]}")
            lines.extend(section.body[1:])
            continue
        if section.title == "Uncertainty notes":
            lines.append(f"Uncertainty notes: {section.body[0]}")
            continue
        if section.title:
            lines.append(f"{section.title}:")
        lines.extend(section.body)
        lines.extend(f"  - {bullet}" for bullet in section.bullets)
    return "\n".join(lines)


def render_markdown(report: Report, sections: list[Section]) -> str:
    lines = [f"# Investigation Report {report.report_id}", ""]
    for section in sections:
        if section.title:
            lines.append(f"## {section.title}")
            lines.append("")
        lines.extend(section.body)
        if section.body:
            lines.append("")
        lines.extend(f"- {bullet}" for bullet in section.bullets)
        if section.bullets:
            lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("_Internal — Ryt Bank_")
    return "\n".join(lines) + "\n"
