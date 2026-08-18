"""Live terminal view of an investigation, fed by AgenticAnalyst's on_step hook.

Render with rich's Live (see cli.py): pass the PipelineView instance as the
renderable; each auto-refresh calls __rich__ again, so the running step's
elapsed timer, spinner, and footer tally tick without any thread of our own.
"""
import re
import time

from rich.console import Group
from rich.markup import escape
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from app.agent.state_graph import Step
from app.schemas import InvestigationStep

# Which schema each step's LLM call enforces — shown while the step runs.
_STEP_SCHEMAS = {
    Step.EXTRACT_INDICATORS.value: "ExtractedIndicators",
    Step.CORRELATE.value: "CorrelationDecision",
    Step.RISK_ASSESSMENT.value: "RiskAssessment",
    Step.DRAFT_REPORT.value: "DraftReportCanonical + DraftReportExperimental",
    Step.SELF_CHECK.value: "SelfCheckResult",
}

_GLYPHS = {"completed": "[green]✓[/]", "skipped": "[dim]−[/]", "degraded": "[yellow]⚠[/]"}

_KEYWORD_STYLES = {
    "MALICIOUS": "red", "SUSPICIOUS": "yellow", "CLEAN": "green",
    "brute_force": "yellow", "scanning": "yellow", "lateral_movement": "red",
    "severity=critical": "red", "severity=high": "red",
    "severity=medium": "yellow", "severity=low": "green",
}
_KEYWORD_RE = re.compile("|".join(re.escape(k) for k in _KEYWORD_STYLES))


def _stylize(summary: str) -> str:
    """Escape rich markup in the raw summary, then color known verdict keywords."""
    return _KEYWORD_RE.sub(
        lambda m: f"[{_KEYWORD_STYLES[m.group()]}]{m.group()}[/]", escape(summary)
    )


class PipelineView:
    def __init__(self, title: str = "", subtitle: str = "") -> None:
        self.reset(title, subtitle)

    def reset(self, title: str = "", subtitle: str = "") -> None:
        self._title = title
        self._subtitle = subtitle
        self._landed: dict[str, InvestigationStep] = {}
        self._durations: dict[str, float] = {}
        self._run_started = time.monotonic()
        self._step_started = self._run_started

    def on_step(self, step: InvestigationStep) -> None:
        now = time.monotonic()
        self._landed[step.step_name] = step
        self._durations[step.step_name] = now - self._step_started
        self._step_started = now

    def _footer(self) -> Text:
        calls = [c for s in self._landed.values() for c in s.llm_calls]
        tokens = sum((c.prompt_tokens or 0) + (c.completion_tokens or 0) for c in calls)
        return Text(
            f"elapsed {time.monotonic() - self._run_started:.0f}s · "
            f"{len(calls)} LLM calls · {tokens:,} tok",
            style="dim",
        )

    # ponytail: mutated by the investigate thread while Live's refresh thread renders;
    # plain dict reads/writes are safe enough under the GIL for a demo view.
    def __rich__(self) -> Group:
        table = Table(expand=True)
        table.add_column("", width=2)
        table.add_column("step", no_wrap=True)
        table.add_column("elapsed", justify="right", width=8)
        table.add_column("result", overflow="ellipsis", no_wrap=True, ratio=1)

        running_found = False
        for step in Step:
            landed = self._landed.get(step.value)
            if landed is not None:
                calls = f" [dim][{len(landed.llm_calls)} LLM call(s)][/]" if landed.llm_calls else ""
                table.add_row(
                    _GLYPHS.get(landed.action, escape(landed.action)),
                    step.value,
                    f"{self._durations[step.value]:.1f}s",
                    f"{_stylize(landed.output_summary)}{calls}",
                )
            elif not running_found:
                running_found = True
                schema = _STEP_SCHEMAS.get(step.value)
                detail = f"[cyan]enforcing {schema}[/]" if schema else "[dim]running…[/]"
                table.add_row(
                    Spinner("dots", style="cyan"),
                    step.value,
                    f"{time.monotonic() - self._step_started:.0f}s",
                    detail,
                )
            else:
                table.add_row("[dim]·[/]", f"[dim]{step.value}[/]", "", "")

        parts = []
        if self._title:
            parts.append(Text(self._title, style="bold"))
        if self._subtitle:
            parts.append(Text(self._subtitle, style="dim"))
        parts.extend([table, self._footer()])
        return Group(*parts)
