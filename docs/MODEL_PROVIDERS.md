# Model Providers

Supported provider registries are NVIDIA NIM, DeepSeek, OpenAI, and OpenRouter. VIGIL calls each provider's model catalog and does not use a hardcoded model dropdown. Catalog collection supports pagination, more than 30 results, search, refresh, short-lived caching, stale cache disclosure, and explicit empty/auth/rate-limit errors.

Credential precedence is environment variable first, then OS Credential Manager:

| Provider | Environment variables |
| --- | --- |
| NVIDIA NIM | `VIGIL_NVIDIA_API_KEY`, `NVIDIA_API_KEY` |
| DeepSeek | `VIGIL_DEEPSEEK_API_KEY`, `DEEPSEEK_API_KEY` |
| OpenAI | `VIGIL_OPENAI_API_KEY`, `OPENAI_API_KEY` |
| OpenRouter | `VIGIL_OPENROUTER_API_KEY`, `OPENROUTER_API_KEY` |

`vigil provider` securely prompts and stores a key through `keyring`. It never writes the key to SQLite. `vigil model` fetches the catalog and stores only `provider + exact model ID` per agent.

Catalog presence does not prove inference or tool-call compatibility. Unknown models should be tested before demonstrations. Provider failures never fall back to fabricated success. Offline mode is an explicit deterministic, read-only investigation mode and remains the default until a cloud model is assigned.

