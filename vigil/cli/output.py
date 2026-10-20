import json
from datetime import datetime

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from vigil.core.models import AgentResult

console = Console()


def print_json(value) -> None:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    text = json.dumps(value, indent=2, default=str)
    console.print(Syntax(text, "json", word_wrap=True))


def _duration(started_at: datetime, completed_at: datetime) -> str:
    seconds = max((completed_at - started_at).total_seconds(), 0)
    return f"{seconds:.1f}s"


def _section(title: str, items: list[str], *, empty: str | None = None) -> Group | None:
    if not items and not empty:
        return None
    lines = [Text(title, style="bold")]
    for item in items:
        line = Text("  - ", style="bright_black")
        line.append(str(item))
        lines.append(line)
    if not items and empty:
        lines.append(Text(f"  {empty}", style="bright_black"))
    return Group(*lines)


def print_agent_result(result: AgentResult, *, target: Console | None = None) -> None:
    """Render an investigation for a human-oriented interactive session."""
    target = target or console
    status_styles = {"completed": "green", "partial": "yellow", "failed": "red"}
    assessment_styles = {"suspicious": "red", "benign": "green", "unknown": "yellow", "inconclusive": "yellow"}

    summary = Table.grid(expand=True, padding=(0, 2))
    summary.add_column(style="bright_black", no_wrap=True)
    summary.add_column(ratio=1)
    summary.add_row("Status", Text(result.run_status.value.upper(), style=status_styles.get(result.run_status.value, "white")))
    summary.add_row("Assessment", Text(result.security_assessment.value.upper(), style=assessment_styles.get(result.security_assessment.value, "white")))
    summary.add_row("Case", result.case_id)
    summary.add_row("Model", f"{result.model_provider} / {result.model_id}")
    summary.add_row("Evidence", f"{len(result.evidence_refs)} record(s)  |  {len(result.tool_calls)} tool call(s)  |  {_duration(result.started_at, result.completed_at)}")

    sections = [
        _section("Findings", [fact.statement for fact in result.observed_facts], empty="No supported findings were produced."),
        _section("Evidence gaps", result.evidence_gaps),
        _section("Recommended next steps", result.recommendations),
        _section("Limitations", result.limitations),
    ]
    body: list[object] = [summary]
    for section in sections:
        if section is not None:
            body.extend((Text(""), section))

    target.print(Panel(Group(*body), title=f"[bold]VIGIL  {result.agent_id.title()}[/bold]", border_style=status_styles.get(result.run_status.value, "cyan"), padding=(1, 2)))
    if result.analyst_review_required:
        target.print("[bright_black]Analyst review required. VIGIL did not execute remediation.[/bright_black]")


def print_case_history(cases: list[dict], *, target: Console | None = None) -> None:
    target = target or console
    if not cases:
        target.print("[bright_black]No investigation history yet.[/bright_black]")
        return
    table = Table(title="Recent investigations", box=None, header_style="bold cyan")
    table.add_column("Case")
    table.add_column("Alert")
    table.add_column("Status")
    table.add_column("Updated")
    for case in cases:
        updated = str(case.get("updated_at", "")).replace("T", " ")[:19]
        table.add_row(str(case.get("case_id", "")), str(case.get("alert_id", "")), str(case.get("status", "")), updated)
    target.print(table)

