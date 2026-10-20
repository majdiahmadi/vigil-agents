from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ProviderDefinition:
    provider_id: str
    display_name: str
    base_url: str
    env_names: tuple[str, ...]
    models_path: str = "/models"
    chat_path: str = "/chat/completions"


PROVIDERS: dict[str, ProviderDefinition] = {
    "nvidia": ProviderDefinition("nvidia", "NVIDIA NIM", "https://integrate.api.nvidia.com/v1", ("VIGIL_NVIDIA_API_KEY", "NVIDIA_API_KEY")),
    "deepseek": ProviderDefinition("deepseek", "DeepSeek", "https://api.deepseek.com", ("VIGIL_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY")),
    "openai": ProviderDefinition("openai", "OpenAI", "https://api.openai.com/v1", ("VIGIL_OPENAI_API_KEY", "OPENAI_API_KEY")),
    "openrouter": ProviderDefinition("openrouter", "OpenRouter", "https://openrouter.ai/api/v1", ("VIGIL_OPENROUTER_API_KEY", "OPENROUTER_API_KEY")),
}


def get_provider(provider_id: str) -> ProviderDefinition:
    try:
        return PROVIDERS[provider_id.lower()]
    except KeyError as exc:
        raise ValueError(f"unsupported provider: {provider_id}") from exc

