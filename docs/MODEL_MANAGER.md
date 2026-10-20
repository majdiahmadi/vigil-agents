# Model manager

Run `vigil model` and select an agent, provider, then a numbered model from the provider's complete catalog. Search, paging, refresh, and stale-cache labels are supported. Model IDs are never typed manually in the interactive flow. Each of Orchestrator, Triage, Malware, and Hunter has an independent assignment.

Supported OpenAI-compatible providers are NVIDIA NIM, DeepSeek, OpenAI, and OpenRouter. Environment credentials take precedence over OS keyring values. Interactive keys use hidden input and are retained only for the process if the OS keyring fails. Credentials are never stored in SQLite.

Catalog pagination is bounded and exact-origin HTTPS only. Redirects and cross-origin `next` URLs are refused before another authorized request is sent.

A model name is not treated as proof of function calling. After selection, the wizard offers a small live compatibility probe. Its `supported`, `unsupported`, or `unverified` state and check time are shown by `vigil doctor`. Missing cloud credentials fail visibly and never silently fall back to offline mode.

Offline uses `deterministic-readonly-v1`. It is a deterministic fixture workflow, not cloud AI. Conversational chat requires an explicitly configured cloud model; structured investigations work in offline mode.
