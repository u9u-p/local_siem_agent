from datetime import datetime, timezone

from rich.console import Console

from app.llm.client import LLMCallRecord
from app.schemas import InvestigationStep
from app.tui import PipelineView, _stylize

_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _render(view: PipelineView) -> str:
    console = Console(record=True, width=120, force_terminal=False)
    console.print(view)
    return console.export_text()


def _step(name: str, action: str = "completed", summary: str = "did the thing",
          llm_calls: int = 0) -> InvestigationStep:
    return InvestigationStep(
        step_name=name, action=action, output_summary=summary,
        timestamp=datetime.now(timezone.utc),
        llm_calls=[
            LLMCallRecord(prompt_ref="r", prompt="p", attempts=1, latency_ms=900,
                          prompt_tokens=800, completion_tokens=60)
        ] * llm_calls,
    )


def _line_with(text: str, needle: str) -> str:
    return next(line for line in text.splitlines() if needle in line)


def test_fresh_view_lists_all_nine_steps_with_first_running():
    text = _render(PipelineView())

    for name in [
        "ingest_and_parse", "extract_indicators", "enrich", "gather_context", "correlate",
        "risk_assessment", "draft_report", "self_check", "finalize_and_persist",
    ]:
        assert name in text
    assert any(c in _line_with(text, "ingest_and_parse") for c in _SPINNER_FRAMES)


def test_landed_step_shows_check_and_summary_and_running_advances_with_schema():
    view = PipelineView()

    view.on_step(_step("ingest_and_parse", summary="alert ingested"))

    text = _render(view)
    ingest_line = _line_with(text, "ingest_and_parse")
    extract_line = _line_with(text, "extract_indicators")
    assert "✓" in ingest_line
    assert "alert ingested" in ingest_line
    assert any(c in extract_line for c in _SPINNER_FRAMES)
    assert "ExtractedIndicators" in extract_line


def test_degraded_and_skipped_steps_get_distinct_markers():
    view = PipelineView()
    view.on_step(_step("ingest_and_parse"))
    view.on_step(_step("extract_indicators"))
    view.on_step(_step("enrich", action="skipped", summary="no indicators"))
    view.on_step(_step("gather_context", action="degraded", summary="siem unreachable"))

    text = _render(view)
    assert "−" in _line_with(text, "enrich")
    assert "⚠" in _line_with(text, "gather_context")


def test_reset_clears_landed_steps_for_the_next_alert():
    view = PipelineView()
    view.on_step(_step("ingest_and_parse", summary="first alert"))

    view.reset(title="alert two")

    text = _render(view)
    assert "first alert" not in text
    assert "alert two" in text


def test_header_shows_title_and_subtitle():
    view = PipelineView()
    view.reset(title="rule 5710: sshd non-existent user", subtitle="Invalid user admin from 203.0.113.5")

    text = _render(view)
    assert "rule 5710: sshd non-existent user" in text
    assert "Invalid user admin from 203.0.113.5" in text


def test_footer_tallies_llm_calls_and_tokens_across_landed_steps():
    view = PipelineView()
    view.on_step(_step("ingest_and_parse"))
    view.on_step(_step("extract_indicators", llm_calls=1))
    view.on_step(_step("enrich"))
    view.on_step(_step("gather_context"))
    view.on_step(_step("correlate", llm_calls=2))

    text = _render(view)
    assert "3 LLM calls" in text
    assert "2,580 tok" in text  # 3 calls x (800 prompt + 60 completion)


def test_summary_containing_markup_renders_literally():
    view = PipelineView()
    view.on_step(_step("ingest_and_parse", action="degraded", summary="boom: [SQL: INSERT INTO reports]"))

    text = _render(view)
    assert "[SQL: INSERT INTO reports]" in text


def test_stylize_colors_verdict_and_severity_keywords():
    assert "[red]MALICIOUS[/]" in _stylize("203.0.113.5 -> MALICIOUS")
    assert "[yellow]brute_force[/]" in _stylize("pattern_type=brute_force")
    assert "[green]severity=low[/]" in _stylize("severity=low, confidence=high")
    assert "[red]severity=high[/]" in _stylize("severity=high")
    untouched = "gathered context for agent 000"
    assert _stylize(untouched) == untouched
