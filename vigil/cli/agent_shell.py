from __future__ import annotations

import asyncio
from dataclasses import dataclass

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vigil.core.models import AgentRequest, AlertEnvelope
from vigil.cli.model_menu import run_model_wizard
from vigil.cli.output import print_agent_result, print_case_history, print_json
from vigil.cli.terminal_menu import MenuOption, choose_option

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.completion import WordCompleter
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.styles import Style
except ImportError:  # pragma: no cover - source checkout before dependencies are installed
    PromptSession = None


@dataclass(frozen=True, slots=True)
class ShellCommand:
    name: str
    usage: str
    description: str

console = Console()


class AgentShell:
    commands = (
        ShellCommand("/help", "/help", "Show available commands"),
        ShellCommand("/status", "/status", "Show the active agent, model, and case"),
        ShellCommand("/agent", "/agent [name]", "Show or switch the active agent"),
        ShellCommand("/model", "/model", "Change the active agent's provider and model"),
        ShellCommand("/tools", "/tools", "Show tools and skills available to this agent"),
        ShellCommand("/case", "/case [case-id]", "Show or resume a persisted case"),
        ShellCommand("/history", "/history", "List recent investigations"),
        ShellCommand("/new", "/new", "Start a new case"),
        ShellCommand("/json", "/json [on|off]", "Toggle raw JSON results"),
        ShellCommand("/clear", "/clear", "Clear and redraw the screen"),
        ShellCommand("/exit", "/exit", "Close VIGIL"),
    )
    aliases = {"/q": "/exit", "/quit": "/exit", "/reset": "/new", "/?": "/help"}

    def __init__(self, agent_id: str, registry, *, json_output: bool = False) -> None:
        self.agent_id = agent_id
        self.registry = registry
        self.case_id: str | None = None
        self.json_output = json_output
        self._session = self._build_prompt_session()

    def _build_prompt_session(self):
        if PromptSession is None or not console.is_terminal:
            return None
        words = [command.name for command in self.commands] + list(self.aliases)
        history_path = self.registry.dependencies.settings.data_dir / "cli_history"
        style = Style.from_dict({"prompt": "bold ansicyan", "bottom-toolbar": "bg:#20252b #a9b1ba"})
        return PromptSession(
            completer=WordCompleter(words, ignore_case=True, sentence=True),
            complete_while_typing=True,
            history=FileHistory(str(history_path)),
            style=style,
        )

    def _assignment(self) -> tuple[str, str]:
        return self.registry.dependencies.model_manager.assignment(self.agent_id)

    def _toolbar(self) -> str:
        provider, model = self._assignment()
        case = self.case_id or "new case"
        return f" {self.agent_id}  |  {provider}/{model}  |  {case} "

    def _read_input(self) -> str:
        if self._session is None:
            return console.input("[bold cyan]You >[/bold cyan] ").strip()
        return self._session.prompt([("class:prompt", "You > ")], bottom_toolbar=self._toolbar).strip()

    def _banner(self) -> None:
        provider, model = self._assignment()
        title = Text("VIGIL", style="bold cyan")
        title.append("  Evidence-grounded SOC investigations", style="white")
        details = Table.grid(padding=(0, 2))
        details.add_column(style="bright_black")
        details.add_column()
        details.add_row("Agent", self.agent_id.title())
        details.add_row("Model", f"{provider} / {model}")
        details.add_row("Mode", f"{self.registry.dependencies.connector.mode} telemetry, read-only")
        console.print(Panel(Group(title, Text(""), details, Text(""), Text("Ask VIGIL to investigate an alert, or type /help.", style="bright_black")), border_style="cyan", padding=(1, 2)))

    def _help(self) -> None:
        table = Table(title="VIGIL commands", box=None, header_style="bold cyan")
        table.add_column("Command", style="cyan", no_wrap=True)
        table.add_column("Description")
        for command in self.commands:
            table.add_row(command.usage, command.description)
        console.print(table)
        console.print("[bright_black]Tip: type / and use Tab to complete commands. /quit and /q also exit.[/bright_black]")

    def _status(self) -> None:
        provider, model = self._assignment()
        table = Table.grid(padding=(0, 2))
        table.add_column(style="bright_black")
        table.add_column()
        table.add_row("Agent", self.agent_id.title())
        table.add_row("Provider", provider)
        table.add_row("Model", model)
        table.add_row("Case", self.case_id or "new case")
        table.add_row("Output", "JSON" if self.json_output else "human-readable")
        console.print(Panel(table, title="Session", border_style="cyan"))

    def _select_agent(self, requested: str | None) -> None:
        agents = self.registry.list()
        if requested:
            requested = requested.casefold()
            if requested not in agents:
                console.print(f"[red]Unknown agent:[/red] {requested}. Choose from {', '.join(agents)}.")
                return
            self.agent_id = requested
        else:
            selected = choose_option(
                console,
                "VIGIL AGENTS",
                "Choose the specialist used for the next message.",
                [MenuOption(agent, agent.title(), self.registry.create(agent).get_config().purpose, agent == self.agent_id) for agent in agents],
            )
            if selected:
                self.agent_id = selected
        provider, model = self._assignment()
        console.print(f"[green]Active agent:[/green] {self.agent_id.title()}  [bright_black]{provider} / {model}[/bright_black]")

    def _show_tools(self) -> None:
        agent = self.registry.create(self.agent_id)
        config = agent.get_config()
        table = Table(title=f"{self.agent_id.title()} capabilities", box=None, header_style="bold cyan")
        table.add_column("Type", style="bright_black")
        table.add_column("Name")
        for tool in sorted(config.allowed_tools):
            table.add_row("tool", tool)
        for skill in agent.get_skills():
            table.add_row("skill", skill.name)
        console.print(table)

    def _set_case(self, requested: str | None) -> None:
        if not requested:
            console.print(self.case_id or "No active case. Your next message will create one.")
            return
        case = self.registry.dependencies.store.get_case(requested)
        if not case:
            console.print(f"[red]Case not found:[/red] {requested}")
            return
        self.case_id = requested
        console.print(f"[green]Resumed case:[/green] {requested}")

    def _set_json(self, value: str | None) -> None:
        if value is None:
            self.json_output = not self.json_output
        elif value.casefold() in {"on", "true", "1"}:
            self.json_output = True
        elif value.casefold() in {"off", "false", "0"}:
            self.json_output = False
        else:
            console.print("Usage: /json [on|off]")
            return
        console.print(f"Raw JSON output is now {'on' if self.json_output else 'off'}.")

    def _handle_command(self, line: str) -> bool:
        parts = line.split(maxsplit=1)
        command = self.aliases.get(parts[0].casefold(), parts[0].casefold())
        argument = parts[1].strip() if len(parts) == 2 else None
        if command == "/exit":
            return False
        if command == "/help":
            self._help()
        elif command == "/status":
            self._status()
        elif command == "/agent":
            self._select_agent(argument)
        elif command == "/model":
            asyncio.run(run_model_wizard(self.registry.dependencies.model_manager, self.agent_id))
        elif command == "/tools":
            self._show_tools()
        elif command == "/case":
            self._set_case(argument)
        elif command == "/history":
            print_case_history(self.registry.dependencies.store.list_cases(), target=console)
        elif command == "/new":
            self.case_id = None
            console.print("[green]New case ready.[/green] Persisted history was not deleted.")
        elif command == "/json":
            self._set_json(argument)
        elif command == "/clear":
            console.clear()
            self._banner()
        else:
            console.print(f"[yellow]Unknown command:[/yellow] {parts[0]}  Type /help to see available commands.")
        return True

    def run(self) -> None:
        self._banner()
        while True:
            try:
                line = self._read_input()
            except (EOFError, KeyboardInterrupt):
                console.print("\nSession closed.")
                return
            if not line:
                continue
            if line.startswith("/"):
                if not self._handle_command(line):
                    console.print("Session closed.")
                    return
                continue
            alert = AlertEnvelope.from_payload({"alert": {"category": "interactive task", "description": line}}, source="cli-chat")
            with console.status(f"[cyan]{self.agent_id.title()} is investigating...[/cyan]", spinner="dots"):
                result = asyncio.run(self.registry.create(self.agent_id).chat(AgentRequest(alert=alert, case_id=self.case_id)))
            self.case_id = result.case_id
            if self.json_output:
                print_json(result)
            else:
                print_agent_result(result, target=console)

