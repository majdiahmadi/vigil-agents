import keyring

from vigil.llm.credentials import CredentialStore


def test_key_survives_for_session_when_keyring_is_unavailable(monkeypatch):
    for name in ("VIGIL_OPENAI_API_KEY", "OPENAI_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(keyring, "set_password", lambda *args: (_ for _ in ()).throw(RuntimeError("unavailable")))
    monkeypatch.setattr(keyring, "get_password", lambda *args: None)
    credentials = CredentialStore()
    assert credentials.save("openai", "session-secret") is False
    assert credentials.get("openai") == "session-secret"

