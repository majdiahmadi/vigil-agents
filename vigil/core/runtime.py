from __future__ import annotations

from typing import Any

from vigil.core.models import AgentResult, CaseContext, EvidenceRecord, RuntimeResult
from vigil.core.tool_registry import ToolRegistry


class AgentRuntime:
    """One bounded execution loop shared by all four agents."""

    async def execute(
        self,
        *,
        context: CaseContext,
        instructions: str,
        skills: list[Any],
        registry: ToolRegistry,
        model_adapter: Any = None,
    ) -> RuntimeResult:
        result = RuntimeResult()
        if model_adapter is not None:
            planned = await model_adapter.plan_tool_calls(context, instructions, skills, registry.tools)
        else:
            planned = self._offline_plan(context, registry)

        for name, arguments in planned[: registry.max_calls]:
            call, value = await registry.execute(name, arguments, context)
            result.tool_calls.append(call)
            if call.status != "completed":
                result.errors.append(f"{name}: {call.error}")
                continue
            if isinstance(value, list) and all(isinstance(x, EvidenceRecord) for x in value):
                result.evidence.extend(value)
            elif isinstance(value, AgentResult):
                result.specialist_results.append(value)
            elif isinstance(value, dict) and isinstance(value.get("result"), AgentResult):
                result.specialist_results.append(value["result"])
        result.narrative = "Bounded read-only investigation completed." if not result.errors else "Investigation completed with tool gaps."
        return result

    def _offline_plan(self, context: CaseContext, registry: ToolRegistry) -> list[tuple[str, dict[str, Any]]]:
        available = {t.name: t for t in registry.tools}
        category = str(context.alert.normalized_fields.get("category", "")).lower()
        raw_text = str(context.alert.original_alert).lower()
        text = f"{category} {raw_text}"
        names: list[str] = []
        if context.agent_id == "orchestrator":
            if any(x in text for x in ("file", "malware", "hash", "sha256", "ransom")):
                names.append("delegate_malware")
            if any(x in text for x in ("campaign", "hunt", "multi-host", "lateral", "correlation")):
                names.append("delegate_hunter")
            if any(x in text for x in ("ssh", "auth", "login", "brute", "unknown")) or not names:
                names.append("delegate_triage")
        elif context.agent_id == "triage":
            names = [n for n in ("search_authentication_events", "search_session_events", "search_events") if n in available]
        elif context.agent_id == "malware":
            if context.alert.normalized_fields.get("file_path") and "analyze_static_file" in available:
                names.append("analyze_static_file")
            if context.scope.indicators and "search_by_indicator" in available:
                names.append("search_by_indicator")
            if "search_events" in available:
                names.append("search_events")
        elif context.agent_id == "hunter":
            names = [n for n in ("search_events", "search_by_indicator") if n in available and (n != "search_by_indicator" or context.scope.indicators)]
        return [(name, available[name].default_arguments(context)) for name in names if name in available]

