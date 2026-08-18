from datetime import datetime, timezone

from rich.console import Console

from app.schemas import InvestigationStep
from app.tui import PipelineView


def _render(view: PipelineView) -> str:
    console = Console(record=True, width=120, force_terminal=False)
    console.print(view)
    return console.export_text()


def _step(name: str, action: str = "completed", summary: str = "did the thing") -> InvestigationStep:
    return InvestigationStep(
        step_name=name, action=action, output_summary=summary,
        timestamp=datetime.now(timezone.utc),
    )


def test_fresh_view_lists_all_nine_steps_with_first_running():
    text = _render(PipelineView())

    for name in [
        "ingest_and_parse", "extract_indicators", "enrich", "gather_context", "correlate",
        "risk_assessment", "draft_report", "self_check", "finalize_and_persist",
    ]:
        assert name in text
    ingest_line = next(line for line in text.splitlines() if "ingest_and_parse" in line)
    assert "▶" in ingest_line


def test_landed_step_shows_check_and_summary_and_running_advances_with_schema():
    view = PipelineView()

    view.on_step(_step("ingest_and_parse", summary="alert ingested"))

    text = _render(view)
    ingest_line = next(line for line in text.splitlines() if "ingest_and_parse" in line)
    extract_line = next(line for line in text.splitlines() if "extract_indicators" in line)
    assert "✓" in ingest_line
    assert "alert ingested" in ingest_line
    assert "▶" in extract_line
    assert "ExtractedIndicators" in extract_line


def test_degraded_and_skipped_steps_get_distinct_markers():
    view = PipelineView()
    view.on_step(_step("ingest_and_parse"))
    view.on_step(_step("extract_indicators"))
    view.on_step(_step("enrich", action="skipped", summary="no indicators"))
    view.on_step(_step("gather_context", action="degraded", summary="siem unreachable"))

    text = _render(view)
    enrich_line = next(line for line in text.splitlines() if "enrich" in line)
    context_line = next(line for line in text.splitlines() if "gather_context" in line)
    assert "−" in enrich_line
    assert "⚠" in context_line


def test_reset_clears_landed_steps_for_the_next_alert():
    view = PipelineView()
    view.on_step(_step("ingest_and_parse", summary="first alert"))

    view.reset(title="alert two")

    text = _render(view)
    assert "first alert" not in text
    assert "alert two" in text
