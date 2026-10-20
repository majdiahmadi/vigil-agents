from __future__ import annotations

from dataclasses import dataclass
from getpass import getpass
from math import ceil
from typing import Callable

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vigil.cli.terminal_menu import MenuOption, choose_option, is_interactive, read_key
from vigil.llm.capabilities import tool_capability
from vigil.llm.model_catalog import ModelCatalogError, ModelInfo
from vigil.llm.provider_registry import PROVIDERS

console = Console()
AGENTS = ("orchestrator", "triage", "malware", "hunter")
OFFLINE_MODEL = "deterministic-readonly-v1"


@dataclass(slots=True)
class CatalogState:
    models: list[ModelInfo]
    page_size: int = 12
    query: str = ""
    cursor: int = 0
    number_buffer: str = ""

    @property
    def filtered(self) -> list[ModelInfo]:
        needle = self.query.casefold().strip()
        if not needle:
            return self.models
        return [model for model in self.models if needle in model.model_id.casefold() or needle in model.display_name.casefold()]

    @property
    def page(self) -> int:
        return self.cursor // self.page_size if self.filtered else 0

    @property
    def page_count(self) -> int:
        return max(1, ceil(len(self.filtered) / self.page_size))

    @property
    def visible(self) -> list[ModelInfo]:
        start = self.page * self.page_size
        return self.filtered[start : start + self.page_size]

    def move(self, delta: int) -> None:
        if self.filtered:
            self.cursor = (self.cursor + delta) % len(self.filtered)
        self.number_buffer = ""

    def change_page(self, delta: int) -> None:
        if self.filtered:
            page = min(max(self.page + delta, 0), self.page_count - 1)
            self.cursor = min(page * self.page_size, len(self.filtered) - 1)
        self.number_buffer = ""

    def set_query(self, query: str) -> None:
        self.query = query.strip()
        self.cursor = 0
        self.number_buffer = ""

    def numbered_selection(self) -> ModelInfo | None:
        if not self.number_buffer:
            return None
        number = int(self.number_buffer)
        return self.filtered[number - 1] if 1 <= number <= len(self.filtered) else None


def _assignment_options(manager) -> list[MenuOption]:
    options = []
    for agent in AGENTS:
        provider, model = manager.assignment(agent)
        provider_name = "Offline" if provider == "offline" else PROVIDERS[provider].display_name
        options.append(MenuOption(agent, agent.title(), f"{provider_name}  -  {model}"))
    return options


def _provider_options(manager, agent: str) -> list[MenuOption]:
    assigned_provider, _ = manager.assignment(agent)
    options = [MenuOption("offline", "Offline", "Deterministic read-only demo mode", assigned_provider == "offline")]
    for provider in PROVIDERS.values():
        configured = "credential ready" if manager.credentials.get(provider.provider_id) else "API key required"
        options.append(MenuOption(provider.provider_id, provider.display_name, configured, assigned_provider == provider.provider_id))
    return options


def _catalog_panel(state: CatalogState, provider_name: str, agent: str, current_model: str, stale: bool) -> Panel:
    table = Table.grid(padding=(0, 1))
    table.add_column(width=2)
    table.add_column(width=5, justify="right")
    table.add_column(ratio=1)
    start = state.page * state.page_size
    for offset, model in enumerate(state.visible):
        absolute = start + offset
        selected = absolute == state.cursor
        pointer = ">" if selected else " "
        label = Text(model.model_id, style="bold cyan" if selected else "white")
        if model.model_id == current_model:
            label.append("  current", style="green")
        table.add_row(pointer, str(absolute + 1), label)
    if not state.visible:
        table.add_row("", "", Text("No models match this search.", style="yellow"))
    status = f"Agent: {agent.title()}  -  Provider: {provider_name}  -  {len(state.filtered)} models"
    if stale:
        status += "  -  STALE CACHE"
    if state.query:
        status += f"  -  Search: {state.query}"
    if state.number_buffer:
        status += f"  -  Select #: {state.number_buffer}"
    page = f"Page {state.page + 1}/{state.page_count}"
    help_line = "Up/Down move   Left/Right page   Enter select   type # + Enter   / search   C clear   R refresh   Esc back"
    return Panel(
        Group(Text(status, style="bright_black"), Text(page, style="bright_black"), Text(""), table, Text(""), Text(help_line, style="bright_black")),
        title="[bold]VIGIL MODEL CATALOG[/bold]", border_style="cyan", padding=(1, 2),
    )


def _fallback_catalog(models: list[ModelInfo], provider_name: str, current_model: str) -> ModelInfo | None:
    filtered = models
    page = 0
    page_size = 20
    while True:
        rows = filtered[page * page_size : (page + 1) * page_size]
        table = Table(title=f"{provider_name} models ({len(filtered)} total)")
        table.add_column("#", justify="right")
        table.add_column("Model ID")
        for index, model in enumerate(rows, page * page_size + 1):
            table.add_row(str(index), model.model_id + ("  [current]" if model.model_id == current_model else ""))
        console.print(table)
        try:
            answer = console.input("Number | N next | P previous | /text search | A all | R refresh | B back: ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if answer.lower() == "b": return None
        if answer.lower() == "r": raise LookupError("refresh")
        if answer.lower() == "n" and (page + 1) * page_size < len(filtered): page += 1; continue
        if answer.lower() == "p" and page > 0: page -= 1; continue
        if answer.lower() == "a": filtered = models; page = 0; continue
        if answer.startswith("/"): filtered = [m for m in models if answer[1:].casefold() in m.model_id.casefold()]; page = 0; continue
        if answer.isdigit() and 1 <= int(answer) <= len(filtered): return filtered[int(answer) - 1]


def browse_catalog(
    models: list[ModelInfo], provider_name: str, agent: str, current_model: str, stale: bool,
    *, key_reader: Callable[[], str] = read_key,
) -> ModelInfo | None:
    if not is_interactive(console):
        return _fallback_catalog(models, provider_name, current_model)
    state = CatalogState(models=models)
    with Live(_catalog_panel(state, provider_name, agent, current_model, stale), console=console, transient=True, refresh_per_second=20) as live:
        while True:
            key = key_reader()
            if key in {"up", "k"}: state.move(-1)
            elif key in {"down", "j"}: state.move(1)
            elif key in {"left", "p"}: state.change_page(-1)
            elif key in {"right", "n"}: state.change_page(1)
            elif key in {"escape", "q", "b"}: return None
            elif key.lower() == "c": state.set_query("")
            elif key.lower() == "r": raise LookupError("refresh")
            elif key == "/":
                live.stop()
                try: query = console.input("Search models: ")
                except (EOFError, KeyboardInterrupt): query = ""
                state.set_query(query)
                live.start(refresh=True)
            elif key == "backspace": state.number_buffer = state.number_buffer[:-1]
            elif len(key) == 1 and key.isdigit(): state.number_buffer += key
            elif key == "enter":
                numbered = state.numbered_selection()
                if numbered: return numbered
                if state.filtered: return state.filtered[state.cursor]
            live.update(_catalog_panel(state, provider_name, agent, current_model, stale))


def _obtain_key(manager, provider_id: str) -> bool:
    if manager.credentials.get(provider_id):
        return True
    provider = PROVIDERS[provider_id]
    console.print(f"\n[bold]{provider.display_name} credential[/bold]")
    console.print("Input is hidden. No stars are displayed on Windows.", style="bright_black")
    try:
        key = getpass("API key (blank cancels): ")
    except (EOFError, KeyboardInterrupt):
        return False
    if not key:
        return False
    persisted = manager.credentials.save(provider_id, key)
    if not persisted:
        console.print("[yellow]OS credential storage is unavailable. The key will be used for this process only.[/yellow]")
    return True


async def _configure_agent(manager, agent: str) -> bool:
    provider_id = choose_option(console, "VIGIL MODEL MANAGER", f"Configure cloud model for {agent.title()}", _provider_options(manager, agent))
    if not provider_id:
        return False
    if provider_id == "offline":
        manager.assign(agent, "offline", OFFLINE_MODEL)
        console.print(Panel(f"[green]Saved[/green]  {agent.title()} -> Offline / {OFFLINE_MODEL}", border_style="green"))
        return True
    if not _obtain_key(manager, provider_id):
        return False
    provider = PROVIDERS[provider_id]
    refresh = False
    while True:
        try:
            with console.status(f"Fetching the complete {provider.display_name} model catalog..."):
                models, stale = await manager.models(provider_id, refresh=refresh)
        except (RuntimeError, ModelCatalogError) as exc:
            console.print(Panel(str(exc), title="Model catalog unavailable", border_style="red"))
            return False
        _, current_model = manager.assignment(agent)
        try:
            selected = browse_catalog(models, provider.display_name, agent, current_model, stale)
        except LookupError:
            refresh = True
            continue
        if not selected:
            return False
        manager.assign(agent, provider_id, selected.model_id)
        capability = tool_capability(selected.model_id)
        try:
            consent = console.input("Run a small live tool-calling compatibility probe? [y/N]: ").strip().casefold()
        except (EOFError, KeyboardInterrupt):
            consent = ""
        if consent in {"y", "yes"}:
            try:
                capability = await manager.probe_tool_capability(agent)
            except Exception as exc:
                capability = f"probe failed ({exc})"
        console.print(Panel(
            f"[green]Saved[/green]  {agent.title()} -> {provider.display_name} / {selected.model_id}\n"
            f"Tool-calling capability: {capability}. Run [bold]vigil doctor[/bold] before a live investigation.",
            border_style="green", title="MODEL UPDATED",
        ))
        return True


async def run_model_wizard(manager, preselected_agent: str | None = None) -> None:
    """Codex-style model manager. A preselected agent returns to its chat shell."""
    while True:
        agent = preselected_agent or choose_option(
            console, "VIGIL MODEL MANAGER",
            "Each agent keeps an independent provider and model assignment.",
            _assignment_options(manager),
        )
        if not agent:
            return
        await _configure_agent(manager, agent)
        if preselected_agent or not is_interactive(console):
            return

