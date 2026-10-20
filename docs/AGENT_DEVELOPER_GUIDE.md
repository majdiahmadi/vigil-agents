# Agent Developer Guide

## One blueprint

`OrchestratorAgent`, `TriageAgent`, `MalwareAgent`, and `HunterAgent` all subclass `vigil.agents.base.BaseAgent`. The public methods and lifecycle are identical. `BaseAgent.run(AgentRequest) -> AgentResult` is the Template Method and is not reimplemented by a specialist.

Each standard agent package has meaningful matching files:

| File | Responsibility |
| --- | --- |
| `__init__.py` | Exposes the concrete class. |
| `agent.py` | Implements the six domain hooks and typed interpretation. |
| `config.py` | Identity, purpose, tool allowlist, and budgets. Never a model ID or secret. |
| `prompts.py` | Composes domain instructions while treating evidence text as untrusted. |
| `skills.py` | Returns inspectable procedures. Skills guide reasoning; they are not executable tools. |
| `tools.py` | Defines Pydantic arguments, default bounded arguments, and thin read-only handlers. |
| `schemas.py` | Defines domain-specific structured summaries. |

Shared code owns provider HTTP, the tool loop, persistence, scope validation, error semantics, and the CLI shell.

## Exact lifecycle

1. `BaseAgent.run` validates the agent configuration and creates or resumes a case.
2. It snapshots that agent's current provider and model into `CaseContext`.
3. It loads memory for the exact `case_id` and `agent_id` namespace.
4. It loads agent skills, builds instructions, and registers only allowed tools.
5. `AgentRuntime.execute` obtains bounded tool choices from the selected model adapter or the deterministic offline planner.
6. `ToolRegistry.execute` validates arguments and enforces permission and call budgets before calling a handler.
7. The concrete `interpret_result` converts returned evidence to typed facts, hypotheses, gaps, and recommendations.
8. The evidence validator checks machine-verifiable references and prohibited claims.
9. `BaseAgent` persists evidence, tool calls, the run, status, and a non-evidentiary memory summary.
10. The Orchestrator's common final hook stores `CaseReport`; other agents use the no-op base hook.

## Triage call walkthrough

`vigil triage investigate --alert fixtures/alerts/ssh_bruteforce.json` calls the shared CLI loader, creates `TriageAgent` through `AgentRegistry`, and invokes `BaseAgent.run`. Triage supplies `CONFIG`, two skills, its evidence-safety prompt, and three query tools. The shared runtime selects authentication, session, and surrounding-event searches. The mock connector returns provenance-preserving records. `TriageAgent.interpret_result` records exact observations while explicitly leaving authorization and brute-force causation unknown. The base validator and store finish the run and the CLI serializes the same `AgentResult` used by the API.

## Module mapping

| Hook | Orchestrator | Triage | Malware | Hunter |
| --- | --- | --- | --- | --- |
| Config purpose | Routing/reporting | Alert/session triage | Static file/IOC | Hypothesis hunt |
| Skills | Selective routing, synthesis | SSH sequence, gaps | Safe static, reputation | Hypothesis, alternatives |
| Tools | Typed delegation | Auth/session/events | Static/IOC/events | Events/indicator |
| Interpretation | Combines specialist contracts | Separates auth facts | Avoids family verdicts | Correlation remains bounded |

All use the same `run`, `chat`, statuses, model resolution, memory, runtime, and storage.

## Add a fifth agent

1. Create `vigil/agents/<slug>/` with all seven standard files above.
2. Subclass `BaseAgent` and implement the same six hooks.
3. Define at least two real skills and only read-only, typed, bounded tools.
4. Create an `AgentPlugin` manifest that maps the slug to the class.
5. For an external package, publish that manifest through the `vigil.agent_plugins` Python entry-point group. For a new built-in agent, add the manifest to `builtin_plugins()`.
6. Add its UI name where the model selector enumerates agents.
7. Add conformance, permission, specialist, reasoning, plugin, and CLI tests.
8. Update docs. No change to `AgentRuntime` or `AgentShell` should be necessary.

See `docs/PLUGINS.md` for the complete extension contract and its differences from DeepSeek Harness.

