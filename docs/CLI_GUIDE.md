# CLI Guide

Use `vigil --help` or `python -m vigil --help`.

```powershell
vigil
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

Running `vigil` with no arguments opens the Orchestrator chat. This is the normal entry point for a beginner. The other commands are explicit shortcuts for model setup, specialist chat, one-shot investigations, the API, and the worker.

Every chat shell supports `/help`, `/model`, `/case`, `/history`, `/clear`, and `/exit`. `Ctrl+C` and EOF close a shell without a normal-cancellation traceback. `/clear` resets only the interactive session pointer and never deletes persisted cases.

## Codex-style model manager

Running `vigil model` opens a keyboard-driven dashboard showing the current provider and model for all four agents. The flow is:

```text
Agent dashboard -> provider -> fetched model catalog -> saved assignment
```

Controls: arrow keys or `J`/`K` move, Enter selects, number keys provide quick selection, `/` searches models, `C` clears search, left/right changes pages, `R` refreshes, and Escape returns. A model assignment changes only the selected agent. `/model` inside any agent chat opens the same interface preselected for that agent and returns to the chat afterward.

