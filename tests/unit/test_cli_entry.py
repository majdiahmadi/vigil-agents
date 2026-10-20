from typer.testing import CliRunner

from vigil.cli.main import app


def test_bare_vigil_opens_orchestrator_chat(monkeypatch):
    calls: list[tuple[str, object]] = []
    fake_registry = object()

    class FakeShell:
        def __init__(self, agent_id, registry):
            calls.append((agent_id, registry))

        def run(self):
            calls.append(("run", fake_registry))

    monkeypatch.setattr("vigil.cli.main._registry", lambda: fake_registry)
    monkeypatch.setattr("vigil.cli.main.AgentShell", FakeShell)
    result = CliRunner().invoke(app, [])

    assert result.exit_code == 0
    assert calls == [("orchestrator", fake_registry), ("run", fake_registry)]


def test_chat_is_a_top_level_command():
    result = CliRunner().invoke(app, ["chat", "--help"])

    assert result.exit_code == 0
    assert "Hermes-style interactive session" in result.output
    assert "--agent" in result.output


def test_invalid_root_agent_is_explained():
    result = CliRunner().invoke(app, ["--agent", "unknown"])

    assert result.exit_code != 0
    assert "agent must be orchestrator, triage, malware, or hunter" in result.output
