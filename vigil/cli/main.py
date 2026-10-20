from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from vigil.agents.registry import build_registry
from vigil.cli.agent_shell import AgentShell
from vigil.cli.model_menu import run_model_wizard
from vigil.cli.output import print_agent_result, print_json
from vigil.cli.provider_menu import manage_credentials
from vigil.core.models import AgentRequest, AlertEnvelope
from vigil.integrations import SearchFilters

app = typer.Typer(help="VIGIL - evidence-grounded multi-agent SOC investigations", invoke_without_command=True)
model_app = typer.Typer(help="Discover and assign provider models", invoke_without_command=True)
cases_app = typer.Typer(help="Inspect persistent cases")
app.add_typer(model_app, name="model")
app.add_typer(cases_app, name="cases")
console = Console()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    agent: str = typer.Option("orchestrator", "--agent", "-a", help="Agent used by the interactive session"),
    query: str | None = typer.Option(None, "--query", "-q", help="Run one investigation request and exit"),
    json_output: bool = typer.Option(False, "--json", help="Print one-shot or chat results as JSON"),
) -> None:
    """Start an interactive VIGIL investigation session."""
    if ctx.invoked_subcommand is None:
        _validate_agent(agent)
        registry = _registry()
        if query:
            _run_query(agent, query, registry, json_output=json_output)
        else:
            shell = AgentShell(agent, registry)
            shell.json_output = json_output
            shell.run()


def _registry():
    return build_registry()


def _validate_agent(agent_id: str) -> None:
    if agent_id not in {"orchestrator", "triage", "malware", "hunter"}:
        raise typer.BadParameter("agent must be orchestrator, triage, malware, or hunter")


def _load_alert(path: Path) -> AlertEnvelope:
    if not path.is_file():
        raise typer.BadParameter(f"alert file not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return AlertEnvelope.from_payload(payload, source="cli")
    except (json.JSONDecodeError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc


def _run(agent_id: str, alert: Path) -> None:
    registry = _registry()
    result = asyncio.run(registry.create(agent_id).run(AgentRequest(alert=_load_alert(alert))))
    print_json(result)


def _run_query(agent_id: str, query: str, registry, *, json_output: bool = False) -> None:
    try:
        with console.status(f"[cyan]{agent_id.title()} is responding...[/cyan]", spinner="dots"):
            response = asyncio.run(registry.create(agent_id).chat_message(query, []))
    except RuntimeError as exc:
        console.print(f"[yellow]{exc}[/yellow]")
        return
    if json_output:
        print_json({"agent_id": agent_id, "mode": "chat", "response": response})
    else:
        console.print(response)


@app.command("chat")
def chat(
    agent: str = typer.Option("orchestrator", "--agent", "-a", help="Agent to use"),
    query: str | None = typer.Option(None, "--query", "-q", help="Run one request and exit"),
    json_output: bool = typer.Option(False, "--json", help="Print results as JSON"),
):
    """Start a Hermes-style interactive session, or run one query."""
    _validate_agent(agent)
    registry = _registry()
    if query:
        _run_query(agent, query, registry, json_output=json_output)
    else:
        shell = AgentShell(agent, registry)
        shell.json_output = json_output
        shell.run()


def _agent_group(agent_id: str, action: str):
    group = typer.Typer(help=f"Run {agent_id.title()} independently")

    @group.command("chat")
    def chat():
        AgentShell(agent_id, _registry()).run()

    @group.command(action)
    def investigate(alert: Path = typer.Option(..., "--alert", exists=True, readable=True)):
        _run(agent_id, alert)

    return group


app.add_typer(_agent_group("orchestrator", "investigate"), name="orchestrator")
app.add_typer(_agent_group("triage", "investigate"), name="triage")
app.add_typer(_agent_group("malware", "analyze"), name="malware")
app.add_typer(_agent_group("hunter", "hunt"), name="hunter")


@model_app.callback(invoke_without_command=True)
def model_callback(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        asyncio.run(run_model_wizard(_registry().dependencies.model_manager))


@model_app.command("show")
def model_show():
    registry = _registry()
    rows = registry.dependencies.store.all_assignments()
    table = Table("Agent", "Provider", "Model")
    for agent in registry.list():
        provider, model = rows.get(agent, ("offline", "deterministic-readonly-v1"))
        table.add_row(agent.title(), provider, model)
    console.print(table)


@model_app.command("list")
def model_list(provider: str = typer.Option(..., "--provider"), search: str = typer.Option("", "--search"), refresh: bool = False):
    manager = _registry().dependencies.model_manager
    try:
        models, stale = asyncio.run(manager.models(provider, refresh=refresh))
    except Exception as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)
    if search: models = manager.catalog.search(models, search)
    print_json({"provider": provider, "stale_cache": stale, "count": len(models), "models": [m.model_id for m in models]})


@model_app.command("select")
def model_select(agent: str = typer.Option(..., "--agent")):
    _validate_agent(agent)
    asyncio.run(run_model_wizard(_registry().dependencies.model_manager, agent))


@app.command("provider")
def provider():
    manage_credentials(_registry().dependencies.model_manager.credentials)


@app.command("doctor")
def doctor():
    registry = _registry()
    stages: dict[str, dict] = {}
    try:
        registry.dependencies.store.list_cases(limit=1)
        stages["local"] = {"status": "PASS", "database": str(registry.dependencies.store.path), "agents": registry.list()}
    except Exception as exc:
        stages["local"] = {"status": "FAIL", "remedy": f"Fix the writable VIGIL_DATA_DIR: {type(exc).__name__}"}
    if registry.dependencies.settings.api_token:
        stages["n8n"] = {"status": "PASS", "detail": "API bearer token is configured; Docker connectivity still requires a running server and firewall access.", "url": "http://host.docker.internal:8000/api/v1/investigations"}
    else:
        stages["n8n"] = {"status": "NOT CONFIGURED", "remedy": "Set VIGIL_API_TOKEN, then start 'vigil serve --host 0.0.0.0' only on a trusted/firewalled network."}
    if registry.dependencies.connector.mode == "mock":
        stages["wazuh"] = {"status": "NOT CONFIGURED", "detail": "Mock telemetry is active.", "remedy": "Set VIGIL_CONNECTOR_MODE=wazuh and the Indexer URL, read-only credentials, index pattern, and CA bundle."}
    else:
        now = datetime.now(timezone.utc)
        try:
            asyncio.run(registry.dependencies.connector.search_events("doctor", SearchFilters(start=now - timedelta(minutes=5), end=now, limit=1)))
            stages["wazuh"] = {"status": "PASS", "detail": "Authenticated read-only Indexer sample search succeeded.", "manager": "configured" if registry.dependencies.connector.manager else "not configured (optional)"}
        except Exception as exc:
            stages["wazuh"] = {"status": "FAIL", "remedy": str(exc)}
    models = {}
    for agent_id in registry.list():
        provider, model = registry.dependencies.model_manager.assignment(agent_id)
        models[agent_id] = {"provider": provider, "model_id": model, **registry.dependencies.model_manager.capability(agent_id)}
    print_json({"stages": stages, "models": models, "connector_mode": registry.dependencies.connector.mode})


@cases_app.command("list")
def cases_list():
    print_json(_registry().dependencies.store.list_cases())


@cases_app.command("show")
def cases_show(case_id: str):
    registry = _registry()
    case = registry.dependencies.store.get_case(case_id)
    if not case:
        raise typer.BadParameter("case not found")
    print_json({"case": case, "runs": [r.model_dump(mode="json") for r in registry.dependencies.store.results_for_case(case_id)], "report": registry.dependencies.store.get_report(case_id)})


@app.command("serve")
def serve(host: str = typer.Option("127.0.0.1"), port: int = typer.Option(8000)):
    if host not in {"127.0.0.1", "localhost"} and not _registry().dependencies.settings.api_token:
        console.print("[red]A VIGIL_API_TOKEN is required before binding beyond loopback.[/red]")
        raise typer.Exit(1)
    import uvicorn
    uvicorn.run("vigil.api.app:app", host=host, port=port, reload=False)


@app.command("worker")
def worker(once: bool = typer.Option(False, help="Process at most one job and exit")):
    from vigil.workers.investigation_worker import run_worker
    asyncio.run(run_worker(once=once))

