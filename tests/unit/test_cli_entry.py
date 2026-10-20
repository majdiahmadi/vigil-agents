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
