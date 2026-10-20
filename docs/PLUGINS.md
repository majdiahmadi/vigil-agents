# Plugin System

VIGIL now applies the main plugin idea used by DeepSeek Harness: capabilities are registered through small manifests instead of being permanently hardcoded into the central registry. The implementation is intentionally smaller because VIGIL is an FYP security tool, not a general-purpose application host.

## What is implemented

- Every built-in agent is represented by an `AgentPlugin` manifest.
- A plugin declares its unique plugin ID, agent classes, required shared services, and description.
- `PluginManager` validates required services and `BaseAgent` inheritance before registration.
- Duplicate plugin IDs and duplicate agent IDs fail immediately.
- Installed Python packages can publish extensions through the `vigil.agent_plugins` entry-point group.
- `vigil doctor` and `GET /api/v1/agents` show loaded plugins without exposing secrets.

## What is deliberately not copied

DeepSeek Harness uses Cordis fibers, automatic resource disposal, nested contexts, configuration hot replacement, and hot module reload. VIGIL does not currently need those application-host features. It loads trusted installed Python plugins once when a process starts. It does not download code, watch files, hot-reload plugins, or permit a model to install extensions.

An installed plugin executes Python code with the same operating-system permissions as VIGIL. Only install plugins whose source and publisher you trust.

## External plugin shape

An extension package exposes a zero-argument factory or an `AgentPlugin` value:

```python
from vigil.plugins import AgentPlugin
from example_agent.agent import ExampleAgent


def plugin() -> AgentPlugin:
    return AgentPlugin(
        plugin_id="example.agent",
        agents={"example": ExampleAgent},
        description="Example read-only specialist",
    )
```

Its `pyproject.toml` publishes the factory:

```toml
[project.entry-points."vigil.agent_plugins"]
example = "example_agent.plugin:plugin"
```

After that package is installed into the same Python environment, a new VIGIL process discovers it automatically. The agent class must subclass `BaseAgent` and must obey the same typed, read-only lifecycle as the four built-in agents.
