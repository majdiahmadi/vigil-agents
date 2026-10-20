from __future__ import annotations

import os

from vigil.llm.provider_registry import get_provider


class CredentialStore:
    service_name = "VIGIL"

    def __init__(self) -> None:
        self._session: dict[str, str] = {}

    def get(self, provider_id: str) -> str | None:
        provider = get_provider(provider_id)
        for name in provider.env_names:
            if value := os.getenv(name):
                return value
        if value := self._session.get(provider.provider_id):
            return value
        try:
            import keyring
            return keyring.get_password(self.service_name, provider.provider_id)
        except Exception:
            return None

    def save(self, provider_id: str, secret: str) -> bool:
        if not secret.strip():
            raise ValueError("API key cannot be empty")
        provider = get_provider(provider_id)
        self._session[provider.provider_id] = secret
        try:
            import keyring
            keyring.set_password(self.service_name, provider.provider_id, secret)
            return True
        except Exception:
            return False

    def delete(self, provider_id: str) -> None:
        provider = get_provider(provider_id)
        self._session.pop(provider.provider_id, None)
        try:
            import keyring
            keyring.delete_password(self.service_name, provider.provider_id)
        except Exception:
            return

