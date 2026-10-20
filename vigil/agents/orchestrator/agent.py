from __future__ import annotations

from datetime import datetime

from vigil.agents.base import BaseAgent
from vigil.agents.orchestrator.config import CONFIG
from vigil.agents.orchestrator.prompts import build_prompt
from vigil.agents.orchestrator.skills import load_skills
from vigil.agents.orchestrator.tools import build_tools
from vigil.core.models import AgentResult, AgentStatus, CaseContext, CaseReport, RuntimeResult, SecurityAssessment


class OrchestratorAgent(BaseAgent):
    agent_id = "orchestrator"
    def get_config(self): return CONFIG
    def get_skills(self): return load_skills()
    def build_instructions(self, context): return build_prompt(context, self.get_skills())
    def get_tool_specs(self): return build_tools(self.dependencies)

    def interpret_result(self, context: CaseContext, runtime_result: RuntimeResult, started_at: datetime) -> AgentResult:
        specialists = runtime_result.specialist_results
        facts = [fact for result in specialists for fact in result.observed_facts]
        hypotheses = [item for result in specialists for item in result.hypotheses]
        refs = []
        seen: set[tuple[str, str]] = set()
        for result in specialists:
            for ref in result.evidence_refs:
                key = (ref.source_type, ref.native_event_id)
                if key not in seen:
                    refs.append(ref)
                    seen.add(key)
        gaps = [gap for result in specialists for gap in result.evidence_gaps]
        if not specialists:
            gaps.append("No specialist completed; the alert category may be unsupported or delegation failed.")
        failed = any(result.run_status in {AgentStatus.FAILED, AgentStatus.PARTIAL} for result in specialists)
        assessment = SecurityAssessment.SUSPICIOUS if any(r.security_assessment == SecurityAssessment.SUSPICIOUS for r in specialists) else SecurityAssessment.INCONCLUSIVE
        return AgentResult(
            case_id=context.case_id, agent_id=self.agent_id, run_id=context.run_id,
            run_status=AgentStatus.PARTIAL if failed or runtime_result.errors else AgentStatus.COMPLETED,
            security_assessment=assessment, model_provider=context.model_provider, model_id=context.model_id,
            observed_facts=facts, hypotheses=hypotheses, evidence_refs=refs, evidence_gaps=gaps,
            tool_calls=runtime_result.tool_calls,
            recommendations=[item for r in specialists for item in r.recommendations] or ["Have an analyst review the submitted alert and available data sources."],
            limitations=["Specialist outputs are interpretations over bounded evidence and require analyst review.", "VIGIL executed no remediation."],
            skills_used=[s.name for s in self.get_skills()], specialist_results=specialists,
            started_at=started_at, completed_at=self.dependencies.clock(),
        )

    def after_persist(self, result: AgentResult, context: CaseContext) -> None:
        evidence = {e.evidence_id: e for e in self.dependencies.store.evidence_for_case(result.case_id)}
        timeline = [
            {"observed_at": evidence[ref.evidence_id].observed_at.isoformat() if evidence.get(ref.evidence_id) and evidence[ref.evidence_id].observed_at else None,
             "native_event_id": ref.native_event_id, "source_type": ref.source_type}
            for ref in result.evidence_refs
        ]
        names = ", ".join(r.agent_id.title() for r in result.specialist_results) or "no specialist"
        report = CaseReport(
            case_id=result.case_id, status=result.run_status,
            security_assessment=result.security_assessment,
            executive_summary=f"VIGIL completed a bounded read-only investigation using {names}. The assessment is {result.security_assessment.value}; this is not proof of compromise and requires analyst review.",
            timeline=timeline, specialist_results=result.specialist_results,
            supported_findings=result.observed_facts,
            unresolved_questions=result.evidence_gaps,
            next_steps=result.recommendations,
        )
        self.dependencies.store.save_report(report)

