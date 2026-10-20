# VIGIL Agents

VIGIL is a defensive, read-only, multi-agent SOC investigation framework for the FYP. It implements four independently runnable agents, one shared bounded tool-feedback runtime, SQLite case/job persistence, mock telemetry for immediate demos, live provider model discovery, a Wazuh connector, and an authenticated FastAPI interface for n8n.

VIGIL does not execute remediation, malware, arbitrary code, shell commands, Wazuh Active Response, or unrestricted queries. Every report requires analyst review.

## Windows setup

From PowerShell:

```powershell
Set-Location '<fresh-clone>\vigil-agents'
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
vigil --help
```

If Python 3.14 dependency wheels are unavailable on another machine, use Python 3.12 or 3.13. `python -m vigil` is the fallback when the console script is not on `PATH`.

After installation and activation, the shortest start command is simply:

```powershell
vigil
```

The bare command opens a Hermes-style Orchestrator chat. Conversational chat requires a selected cloud model and never turns ordinary questions into synthetic investigations. `vigil chat`, `vigil chat --agent triage`, and `vigil orchestrator chat` are equivalent entry points. With Offline selected, use the structured investigation commands below.

## Immediate offline demo

No key or Wazuh system is needed. Mock records are explicitly marked `simulated: true`.

```powershell
vigil doctor
vigil triage investigate --alert .\fixtures\alerts\ssh_bruteforce.json
vigil malware analyze --alert .\fixtures\alerts\suspicious_file.json
vigil hunter hunt --alert .\fixtures\alerts\hunt_scenario.json
vigil orchestrator investigate --alert .\fixtures\alerts\ssh_bruteforce.json
vigil cases list
```

Interactive shells use `/help`, `/status`, `/agent`, `/model`, `/tools`, `/case`, `/history`, `/new`, `/json`, `/clear`, and `/exit`. `/new` clears bounded conversation state without deleting persisted investigations.

```powershell
vigil orchestrator chat
vigil triage chat
vigil malware chat
vigil hunter chat
```

## Provider models

Configure credentials through `vigil provider` or environment variables. Hidden Windows input intentionally shows no characters.

```powershell
$env:NVIDIA_API_KEY = 'your-key'
$env:DEEPSEEK_API_KEY = 'your-key'
# Alternatives: OPENAI_API_KEY, OPENROUTER_API_KEY
vigil model
vigil model list --provider nvidia
vigil model select --agent triage
vigil model show
```

The selected provider catalog is fetched from its live `/models` API and displayed as a complete numbered, searchable, paginated list. Assignments are independent per agent. Credentials are never stored in SQLite or project files. Exact-origin HTTPS pagination prevents credentials from following a hostile `next` link. The optional live compatibility probe verifies tool calling; a model name alone is reported as unverified.

The interactive manager uses a Codex-style terminal flow. Use the arrow keys and Enter, or press a displayed number. In the model catalog, type a multi-digit model number and press Enter, use `/` to search, `C` to clear the search, left/right to change pages, `R` to refresh the provider catalog, and Escape to go back. Select `Offline` at any time to restore deterministic demo mode for only that agent.

## API and worker

```powershell
$env:VIGIL_API_TOKEN = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
vigil serve --host 127.0.0.1 --port 8000
# In a second activated PowerShell:
vigil worker
```

The ingestion endpoint is `POST http://127.0.0.1:8000/api/v1/investigations`. Docker n8n uses `http://host.docker.internal:8000` after starting with `vigil serve --host 0.0.0.0`, token authentication, and appropriate Windows Firewall restrictions. Import the template at `examples/n8n/vigil_investigation_workflow.json` or follow [N8N integration](docs/N8N_INTEGRATION.md).

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Agent developer guide](docs/AGENT_DEVELOPER_GUIDE.md)
- [CLI guide](docs/CLI_GUIDE.md)
- [Model providers](docs/MODEL_PROVIDERS.md)
- [Model manager](docs/MODEL_MANAGER.md)
- [Plugin system](docs/PLUGINS.md)
- [API reference](docs/API_REFERENCE.md)
- [Wazuh integration](docs/WAZUH_INTEGRATION.md)
- [Security](docs/SECURITY.md)
- [Acceptance results](docs/ACCEPTANCE_RESULTS.md)

Operational limitations: this is an FYP prototype, not a production-certified SOC platform. External model use may transmit minimized alert scope to that provider. Retain only required case data, secure the user data directory, rotate API credentials, and have a human validate all findings and proposed actions.

