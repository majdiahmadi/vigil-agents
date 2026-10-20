# CLI Guide

Use `vigil --help` or `python -m vigil --help`.

```powershell
vigil
vigil chat
vigil chat --agent triage
vigil -q "Investigate repeated SSH failures from 203.0.113.42"
vigil chat -a hunter -q "Look for related activity"
vigil model
vigil model list --provider nvidia --search llama
vigil model show
vigil model select --agent triage
vigil provider
vigil doctor
vigil orchestrator chat
vigil triage chat
vigil malware chat
vigil hunter chat
vigil triage investigate --alert .\fixtures\alerts\ssh_bruteforce.json
vigil malware analyze --alert .\fixtures\alerts\suspicious_file.json
vigil hunter hunt --alert .\fixtures\alerts\hunt_scenario.json
vigil orchestrator investigate --alert .\fixtures\alerts\ssh_bruteforce.json
vigil cases list
vigil cases show CASE_ID
vigil serve
vigil worker
```

Running `vigil` with no arguments opens the Orchestrator chat. `vigil chat` is the equivalent explicit command, following the same primary workflow as Hermes. Use `--agent`/`-a` to start with a specialist and `--query`/`-q` for a single human-readable result. Add `--json` when a script needs the complete result object.

The chat shell shows the active agent, provider/model, telemetry mode, and case. Type `/` and press Tab to complete a command. It supports `/help`, `/status`, `/agent`, `/model`, `/tools`, `/case`, `/history`, `/new`, `/json`, `/clear`, and `/exit`. `/q` and `/quit` are exit aliases; `/reset` is an alias for `/new`. `Ctrl+C` and EOF close the shell cleanly.

`/new` starts a new case without deleting persisted history. `/case CASE_ID` resumes a prior case. `/clear` only redraws the terminal. Interactive results are summarized for analysts by default instead of being dumped as JSON; `/json on` restores raw output for inspection.

## Codex-style model manager

Running `vigil model` opens a keyboard-driven dashboard showing the current provider and model for all four agents. The flow is:

```text
Agent dashboard -> provider -> fetched model catalog -> saved assignment
```

Controls: arrow keys or `J`/`K` move, Enter selects, number keys provide quick selection, `/` searches models, `C` clears search, left/right changes pages, `R` refreshes, and Escape returns. A model assignment changes only the selected agent. `/model` inside any agent chat opens the same interface preselected for that agent and returns to the chat afterward.

