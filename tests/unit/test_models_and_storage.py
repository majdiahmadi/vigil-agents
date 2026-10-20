from vigil.core.models import AlertEnvelope


def test_per_agent_assignments_persist_independently(registry):
    manager = registry.dependencies.model_manager
    manager.assign("triage", "openai", "gpt-test")
    manager.assign("malware", "deepseek", "deepseek-test")
    assert manager.assignment("triage") == ("openai", "gpt-test")
    assert manager.assignment("malware") == ("deepseek", "deepseek-test")
    assert manager.assignment("hunter") == ("offline", "deterministic-readonly-v1")


def test_alert_scope_does_not_mean_trust():
    alert = AlertEnvelope.from_payload({"alert": {"attack": "SSH", "ip": "192.0.2.10"}})
    assert alert.asset_scope.source_ips == ["192.0.2.10"]
    assert "trusted" not in alert.model_dump_json().lower()
    assert "authorized" not in alert.model_dump_json().lower()

