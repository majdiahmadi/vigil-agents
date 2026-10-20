from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from uuid import uuid4

from pydantic import BaseModel, ValidationError

from vigil.core.models import CaseContext, EvidenceRecord, ToolCallRecord


class EmptyArgs(BaseModel):
    pass


Handler = Callable[[BaseModel, CaseContext], Awaitable[Any]]
ArgumentBuilder = Callable[[CaseContext], dict[str, Any]]


@dataclass(slots=True)
class ToolDefinition:
    name: str
    description: str
    args_model: type[BaseModel]
    handler: Handler
    default_arguments: ArgumentBuilder

    def schema(self) -> dict[str, Any]:
        return {"type": "function", "function": {"name": self.name, "description": self.description, "parameters": self.args_model.model_json_schema()}}


class ToolRegistry:
    def __init__(self, allowed_names: set[str], max_calls: int = 6) -> None:
        self.allowed_names = allowed_names
        self.max_calls = max_calls
        self._tools: dict[str, ToolDefinition] = {}
        self.call_count = 0

    def register(self, tool: ToolDefinition) -> None:
        if tool.name not in self.allowed_names:
            raise PermissionError(f"tool {tool.name!r} is not allowed for this agent")
        self._tools[tool.name] = tool

    @property
    def tools(self) -> list[ToolDefinition]:
        return list(self._tools.values())

    async def execute(self, name: str, arguments: dict[str, Any], context: CaseContext, *, call_id: str | None = None) -> tuple[ToolCallRecord, Any]:
        call_id = call_id or f"call-{uuid4().hex[:12]}"
        if name not in self.allowed_names or name not in self._tools:
            return ToolCallRecord(call_id=call_id, tool_name=name, arguments={}, status="denied", error="tool not allowed"), None
        if self.call_count >= self.max_calls:
            return ToolCallRecord(call_id=call_id, tool_name=name, arguments={}, status="budget_exceeded", error="tool call budget exhausted"), None
        tool = self._tools[name]
        try:
            parsed = tool.args_model.model_validate(arguments)
            self.call_count += 1
            value = await tool.handler(parsed, context)
            evidence = value if isinstance(value, list) and all(isinstance(x, EvidenceRecord) for x in value) else []
            record = ToolCallRecord(call_id=call_id, tool_name=name, arguments=parsed.model_dump(mode="json"), status="completed", evidence_ids=[x.evidence_id for x in evidence])
            return record, value
        except ValidationError as exc:
            return ToolCallRecord(call_id=call_id, tool_name=name, arguments={}, status="invalid_arguments", error=str(exc).splitlines()[0]), None
        except PermissionError as exc:
            return ToolCallRecord(call_id=call_id, tool_name=name, arguments={}, status="denied", error=str(exc)), None
        except Exception as exc:
            return ToolCallRecord(call_id=call_id, tool_name=name, arguments={}, status="failed", error=f"{type(exc).__name__}: {exc}"), None

