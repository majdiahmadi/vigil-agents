from __future__ import annotations

from datetime import datetime

from vigil.agents.base import BaseAgent
from vigil.agents.hunter.config import CONFIG
from vigil.agents.hunter.prompts import build_prompt
from vigil.agents.hunter.schemas import HuntSummary
from vigil.agents.hunter.skills import load_skills
from vigil.agents.hunter.tools import build_tools
from vigil.core.evidence import references
from vigil.core.models import AgentResult, AgentStatus, CaseContext, Hypothesis, ObservedFact, RuntimeResult, SecurityAssessment


class HunterAgent(BaseAgent):
    agent_id = "hunter"
    def get_config(self): return CONFIG
    def get_skills(self): return load_skills()
    def build_instructions(self, context): return build_prompt(context, self.get_skills())
    def get_tool_specs(self): return build_tools(self.dependencies)

    def interpret_result(self, context: CaseContext, runtime_result: RuntimeResult, started_at: datetime) -> AgentResult:
        by_destination: dict[str, list] = {}
        for event in runtime_result.evidence:
            if event.destination_ip:
                by_destination.setdefault(event.destination_ip, []).append(event)
        facts: list[ObservedFact] = []
        hypotheses: list[Hypothesis] = []
        for destination, events in by_destination.items():
            hosts = sorted({e.host for e in events if e.host})
            if len(hosts) >= 2:
                ids = [e.evidence_id for e in events]
                facts.append(ObservedFact(statement=f"Telemetry shows {len(hosts)} hosts communicating with destination {destination} in the searched window.", evidence_ids=ids))
                hypotheses.append(Hypothesis(statement="The shared destination may represent coordinated activity or a shared legitimate service; compromise and lateral movement are not established.", status="inconclusive", supporting_evidence_ids=ids))
        if not hypotheses:
            hypotheses.append(Hypothesis(statement="The hunt hypothesis remains inconclusive because no multi-host correlation was established in the returned evidence.", status="inconclusive"))
        gaps = ["Asset ownership and expected service behavior were not available."]
        if not runtime_result.evidence:
            gaps.append("No events were returned; telemetry coverage may be incomplete.")
        return AgentResult(
            case_id=context.case_id, agent_id=self.agent_id, run_id=context.run_id,
            run_status=AgentStatus.PARTIAL if runtime_result.errors else AgentStatus.COMPLETED,
            security_assessment=SecurityAssessment.INCONCLUSIVE,
            model_provider=context.model_provider, model_id=context.model_id,
            observed_facts=facts, hypotheses=hypotheses, evidence_refs=references(runtime_result.evidence),
            evidence_gaps=gaps, tool_calls=runtime_result.tool_calls,
            recommendations=["Validate whether the shared destination is an approved service.", "Extend the bounded hunt with DNS and process telemetry after analyst approval."],
            limitations=["Correlation does not establish causation, compromise, attribution, or lateral movement."],
            skills_used=[s.name for s in self.get_skills()], started_at=started_at, completed_at=self.dependencies.clock(),
        )

