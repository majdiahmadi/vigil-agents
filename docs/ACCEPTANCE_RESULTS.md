# Acceptance results

Verified on 20 October 2026 in Windows PowerShell with Python 3.14.7. These results describe this checkout, not unavailable external services.

## Commands and results

```powershell
.\.venv\Scripts\python.exe -m ensurepip --upgrade
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider --basetemp=.pytest-tmp
```

- Editable install: PASS. The existing environment initially lacked pip; `ensurepip` installed it, then the declared editable development install succeeded.
- Tests: 52 passed, 0 failed, 0 skipped in 9.21 seconds.
- Warning: one third-party Starlette deprecation warning states that its compatibility `TestClient` currently imports `httpx` rather than the future `httpx2` package.
- `python -m compileall -q vigil tests`: PASS.
- Importable n8n workflow JSON parse: PASS.
- `scripts/smoke_test.ps1`: PASS when invoked with `-ExecutionPolicy Bypass` because this Windows host blocks direct `.ps1` execution by policy.
- CLI smoke: `vigil --help`, `model show`, `doctor`, all four agent help commands, `serve --help`, `worker --help`, all four offline structured investigations, and `worker --once`: PASS.

## Regression coverage

- Multi-round fake LLM chooses the session tool only after receiving authentication evidence with its matching tool-call ID.
- Actual alert description, timestamp, purpose, trusted scope, and verified case evidence are included in bounded model context.
- Unknown tools, malformed arguments, repeated queries, scope escape, and tool budgets produce safe result messages.
- Cross-origin provider pagination is refused before an authenticated request can reach the hostile origin.
- Mock events and realistic sanitized Wazuh hits normalize to equivalent SSH semantics.
- Wazuh query types differ and 401, 403, 5xx, timeout/transport, and malformed data have typed failure paths.
- Structured evidence claims reject a fabricated aggregate count.
- Stable evidence IDs deduplicate repeated searches.
- Active worker leases cannot be reclaimed; expired leases can; idempotency keys are payload-bound.
- Failed `AgentResult` status propagates to job and case rather than becoming completed.
- API submission/poll/report, authentication, early-report 409, payload limit, idempotency collision, and final report flow are covered.
- Conversational chat uses actual user history, creates no synthetic alert/case, and is explicitly unavailable in Offline mode.

## Readiness matrix

| Capability | Implemented | Mock/fixture verified | Live verified | Blocked by external environment |
| --- | --- | --- | --- | --- |
| Shared four-agent lifecycle | Yes | Yes | N/A | No |
| Iterative cloud LLM/tool loop | Yes | Yes, fake provider | No | Provider key/network/model access |
| Dynamic per-agent model selection | Yes | Yes, fake catalogs | No | Provider key/network |
| Tool-capability probe | Yes | Yes, fake adapter path | No | Provider key/network/cost consent |
| Offline Orchestrator/Triage/Malware/Hunter | Yes | Yes | N/A | No |
| Safe local file analysis | Yes | Yes | Local only | No |
| Optional VirusTotal hash lookup | Yes | HTTP path implemented | No | VirusTotal key/network |
| Wazuh Indexer connector | Yes | Yes, realistic fake HTTP | No | Izzat's URL, indices, credentials, CA, sample |
| Optional Wazuh Manager | Yes | Constructor/client covered indirectly | No | Manager URL/token |
| Authenticated FastAPI + durable worker | Yes | Yes, end to end | Local test client only | Running service/network |
| n8n workflow and contract | Yes | JSON/API contract verified | No | Running n8n Docker/firewall/token |
| Automatic response/remediation | Intentionally absent | N/A | N/A | Product safety boundary |

## External validation still not run

NVIDIA NIM, DeepSeek, OpenAI, OpenRouter, Windows Credential Manager persistence, VirusTotal, a real Wazuh Indexer/Manager, and the running n8n Docker workflow were not contacted. Their state is `NOT TESTED`, not pass or fail.
