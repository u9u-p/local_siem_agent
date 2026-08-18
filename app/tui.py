"""Live terminal view of an investigation, fed by AgenticAnalyst's on_step hook.

Render with rich's Live (see cli.py): pass the PipelineView instance as the
renderable; each auto-refresh calls __rich__ again, so the running step's
elapsed timer ticks without any thread of our own.
"""
import time

from rich.table import Table

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


class PipelineView:
    def __init__(self, title: str = "") -> None:
        self.reset(title)

    def reset(self, title: str = "") -> None:
        self._title = title
        self._landed: dict[str, InvestigationStep] = {}
        self._durations: dict[str, float] = {}
        self._step_started = time.monotonic()

    def on_step(self, step: InvestigationStep) -> None:
        now = time.monotonic()
        self._landed[step.step_name] = step
        self._durations[step.step_name] = now - self._step_started
        self._step_started = now

    # ponytail: mutated by the investigate thread while Live's refresh thread renders;
    # plain dict reads/writes are safe enough under the GIL for a demo view.
    def __rich__(self) -> Table:
        table = Table(title=self._title or None, expand=True)
        table.add_column("", width=2)
        table.add_column("step", no_wrap=True)
        table.add_column("elapsed", justify="right", width=8)
        table.add_column("result", overflow="ellipsis", no_wrap=True, ratio=1)

        running_found = False
        for step in Step:
            landed = self._landed.get(step.value)
            if landed is not None:
                calls = f" [{len(landed.llm_calls)} LLM call(s)]" if landed.llm_calls else ""
                table.add_row(
                    _GLYPHS.get(landed.action, landed.action),
                    step.value,
                    f"{self._durations[step.value]:.1f}s",
                    f"{landed.output_summary}{calls}",
                )
            elif not running_found:
                running_found = True
                schema = _STEP_SCHEMAS.get(step.value)
                detail = f"[cyan]enforcing {schema}[/]" if schema else "[dim]running…[/]"
                table.add_row("[cyan]▶[/]", step.value, f"{time.monotonic() - self._step_started:.0f}s", detail)
            else:
                table.add_row("[dim]·[/]", f"[dim]{step.value}[/]", "", "")
        return table
