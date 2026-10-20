from __future__ import annotations

import asyncio

from rich.console import Console

from vigil.core.models import AgentRequest, AlertEnvelope
from vigil.cli.model_menu import run_model_wizard
from vigil.cli.output import print_json

console = Console()


class AgentShell:
    commands = ("/help", "/model", "/case", "/history", "/clear", "/exit")

    def __init__(self, agent_id: str, registry) -> None:
        self.agent_id = agent_id
        self.registry = registry
        self.case_id: str | None = None

    def run(self) -> None:
        provider, model = self.registry.dependencies.model_manager.assignment(self.agent_id)
        console.print(f"Agent: {self.agent_id.title()} | Provider: {provider} | Model: {model} | Case: new")
        console.print("Type /help for commands. Alert text is treated as untrusted data.")
        while True:
            try:
                line = console.input(f"{self.agent_id}> ").strip()
            except (EOFError, KeyboardInterrupt):
                console.print("\nSession closed.")
                return
            if not line:
                continue
            if line == "/exit": return
            if line == "/help": console.print(" ".join(self.commands)); continue
            if line == "/clear": self.case_id = None; console.print("Session case cleared; persisted history remains."); continue
            if line == "/case": console.print(self.case_id or "No active case"); continue
            if line == "/history": print_json(self.registry.dependencies.store.list_cases()); continue
            if line == "/model": asyncio.run(run_model_wizard(self.registry.dependencies.model_manager, self.agent_id)); continue
            alert = AlertEnvelope.from_payload({"alert": {"category": "interactive task", "description": line}}, source="cli-chat")
            result = asyncio.run(self.registry.create(self.agent_id).chat(AgentRequest(alert=alert, case_id=self.case_id)))
            self.case_id = result.case_id
            print_json(result)

