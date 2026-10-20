from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from vigil.core.models import AgentDependencies, AgentRequest, AgentResult, AgentStatus, CaseContext, RuntimeResult
from vigil.core.skills import Skill
from vigil.core.tool_registry import ToolDefinition, ToolRegistry


@dataclass(frozen=True, slots=True)
class AgentConfig:
    agent_id: str
    display_name: str
    purpose: str
    allowed_tools: frozenset[str]
    max_tool_calls: int = 6


class BaseAgent(ABC):
    """Template Method: all agents use this exact public lifecycle."""

    def __init__(self, dependencies: AgentDependencies) -> None:
        self.dependencies = dependencies

    @property
    @abstractmethod
    def agent_id(self) -> str: ...

    @abstractmethod
    def get_config(self) -> AgentConfig: ...

    @abstractmethod
    def get_skills(self) -> list[Skill]: ...

    @abstractmethod
    def build_instructions(self, context: CaseContext) -> str: ...

    @abstractmethod
    def get_tool_specs(self) -> list[ToolDefinition]: ...

    @abstractmethod
    def interpret_result(self, context: CaseContext, runtime_result: RuntimeResult, started_at: datetime) -> AgentResult: ...

    def after_persist(self, result: AgentResult, context: CaseContext) -> None:
        """Optional final lifecycle hook. The Orchestrator persists a CaseReport here."""

    async def run(self, request: AgentRequest) -> AgentResult:
        config = self.get_config()
        if config.agent_id != self.agent_id:
            raise ValueError("agent config identity mismatch")
        started = self.dependencies.clock()
        case_id = request.case_id or self.dependencies.store.create_case(request.alert, reuse_alert=not request.force_new_run)
        self.dependencies.store.ensure_case(case_id, request.alert)
        self.dependencies.store.set_case_status(case_id, AgentStatus.RUNNING.value)
        provider, model_id = self.dependencies.model_manager.assignment(self.agent_id)
        run_id = f"run-{uuid4().hex[:12]}"
        scope = request.scope or request.alert.asset_scope
        context = CaseContext(
            case_id=case_id, alert=request.alert, agent_id=self.agent_id, run_id=run_id,
            scope=scope, model_provider=provider, model_id=model_id,
            memory=self.dependencies.store.load_memory(case_id, self.agent_id),
        )
        tool_registry = ToolRegistry(set(config.allowed_tools), min(config.max_tool_calls, self.dependencies.settings.max_tool_calls))
        for tool in self.get_tool_specs():
            tool_registry.register(tool)
        try:
            adapter = self.dependencies.model_manager.adapter_for(self.agent_id)
            runtime_result = await self.dependencies.runtime.execute(
                context=context,
                instructions=self.build_instructions(context),
                skills=self.get_skills(),
                registry=tool_registry,
                model_adapter=adapter,
            )
            self.dependencies.store.save_evidence(runtime_result.evidence)
            result = self.interpret_result(context, runtime_result, started)
            validation_errors = self.dependencies.validator.validate(result, self.dependencies.store.evidence_for_case(case_id))
            if validation_errors:
                result.limitations.extend(validation_errors)
                result.run_status = AgentStatus.PARTIAL
        except Exception as exc:
            result = AgentResult(
                case_id=case_id, agent_id=self.agent_id, run_id=run_id,
                run_status=AgentStatus.FAILED, model_provider=provider, model_id=model_id,
                evidence_gaps=[f"Agent execution failed: {type(exc).__name__}: {exc}"],
                limitations=["No missing evidence should be interpreted as negative evidence."],
                started_at=started, completed_at=self.dependencies.clock(),
                skills_used=[skill.name for skill in self.get_skills()],
            )
        self.dependencies.store.save_result(result)
        self.dependencies.store.append_memory(case_id, self.agent_id, "run_summary", {
            "run_id": result.run_id, "status": result.run_status.value,
            "evidence_ids": [ref.evidence_id for ref in result.evidence_refs],
            "note": "AI interpretations are not reusable as verified evidence.",
        })
        self.after_persist(result, context)
        return result

    async def chat(self, request: AgentRequest) -> AgentResult:
        return await self.run(request)

