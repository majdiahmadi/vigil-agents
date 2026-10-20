# Test Results

Verified locally on October 20, 2026 using Windows and CPython 3.14.7.

```text
python -m pytest -q
..............................                                           [100%]
30 passed, 1 warning in 5.41s
```

The warning is an upstream Starlette `TestClient` deprecation notice about its current `httpx` compatibility path. It does not indicate a VIGIL test failure.

Additional successful checks:

- Editable installation from `pyproject.toml` into `.venv` with all development dependencies.
- `python -m compileall -q vigil`.
- Installed `vigil --help`, `vigil doctor`, and `vigil model show` entry points.
- Bare `vigil` dispatch to the Orchestrator chat.
- Built-in plugin discovery, dependency validation, and duplicate-agent rejection.
- Codex-style model dashboard and catalog browser with real PTY keyboard navigation, multi-digit number selection, search state, paging, and redirected PowerShell fallback.
- Standalone offline commands for Orchestrator, Triage, Malware, and Hunter.
- Authenticated API submission, idempotent duplicate, durable worker processing, status polling, and final report retrieval.
- Mocked two-page 50-model provider catalog and mocked Wazuh Indexer HTTP contract.

Not claimed: live NVIDIA/DeepSeek/OpenAI/OpenRouter inference and live Wazuh connectivity. Those require the user's credentials and Izzat's future Wazuh deployment. No n8n workflow or Wazuh configuration was modified.

