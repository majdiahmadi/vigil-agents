from __future__ import annotations

from datetime import datetime

from vigil.agents.base import BaseAgent
from vigil.agents.triage.config import CONFIG
from vigil.agents.triage.prompts import build_prompt
from vigil.agents.triage.schemas import TriageSummary
from vigil.agents.triage.skills import load_skills
from vigil.agents.triage.tools import build_tools
from vigil.core.evidence import references
from vigil.core.models import AgentResult, AgentStatus, CaseContext, EvidenceClaim, Hypothesis, NormalizedEventKind, ObservedFact, RuntimeResult, SecurityAssessment


class TriageAgent(BaseAgent):
    agent_id = "triage"

    def get_config(self): return CONFIG
    def get_skills(self): return load_skills()
    def build_instructions(self, context): return build_prompt(context, self.get_skills())
    def get_tool_specs(self): return build_tools(self.dependencies)

    def interpret_result(self, context: CaseContext, runtime_result: RuntimeResult, started_at: datetime) -> AgentResult:
        facts: list[ObservedFact] = []
        summary = TriageSummary(searched_event_ids=[e.native_event_id for e in runtime_result.evidence])
        seen_native: set[tuple[str, str]] = set()
        for event in runtime_result.evidence:
            key = (event.source_type, event.native_event_id)
            if key in seen_native:
                continue
            seen_native.add(key)
            if event.normalized_event_kind == NormalizedEventKind.AUTH_FAILED:
                attempts = event.event_count or 1
                summary.failed_auth_events += attempts
                facts.append(ObservedFact(
                    statement=f"{attempts} failed SSH authentication attempts were recorded for {event.user or 'an unknown user'} from {event.source_ip or 'an unknown source'}.",
                    evidence_ids=[event.evidence_id],
                    claims=[EvidenceClaim(evidence_id=event.evidence_id, field_path="normalized_event_kind", expected_value="auth_failed"), EvidenceClaim(evidence_id=event.evidence_id, field_path="event_count", expected_value=attempts)],
                ))
            elif event.normalized_event_kind == NormalizedEventKind.AUTH_SUCCESS:
                summary.successful_auth_events += event.event_count or 1
                facts.append(ObservedFact(
                    statement=f"A successful SSH authentication event was recorded for {event.user or 'an unknown user'}; whether it was authorized is unknown.", evidence_ids=[event.evidence_id],
                    claims=[EvidenceClaim(evidence_id=event.evidence_id, field_path="normalized_event_kind", expected_value="auth_success")],
                ))
            elif event.normalized_event_kind == NormalizedEventKind.SESSION_START:
                summary.session_events += event.event_count or 1
                facts.append(ObservedFact(statement="A session-start event was observed after authentication.", evidence_ids=[event.evidence_id], claims=[EvidenceClaim(evidence_id=event.evidence_id, field_path="normalized_event_kind", expected_value="session_start")]))
            elif event.normalized_event_kind == NormalizedEventKind.COMMAND:
                summary.session_events += event.event_count or 1
                facts.append(ObservedFact(statement=f"The command {event.command or '[unknown]'!r} was observed; its intent is unknown.", evidence_ids=[event.evidence_id], claims=[EvidenceClaim(evidence_id=event.evidence_id, field_path="command", expected_value=event.command)]))
            elif event.normalized_event_kind == NormalizedEventKind.UNKNOWN:
                facts.append(ObservedFact(statement="An event with an unrecognized Wazuh layout was preserved for analyst review.", evidence_ids=[event.evidence_id], claims=[EvidenceClaim(evidence_id=event.evidence_id, field_path="normalized_event_kind", expected_value="unknown")]))
        suspicious = bool(summary.failed_auth_events and summary.successful_auth_events)
        gaps = [] if runtime_result.evidence else ["No matching events were returned; this is an evidence gap, not an all-clear result."]
        gaps.append("Authorization of the successful login was not established by the available telemetry.")
        return AgentResult(
            case_id=context.case_id, agent_id=self.agent_id, run_id=context.run_id,
            run_status=AgentStatus.PARTIAL if runtime_result.errors else AgentStatus.COMPLETED,
            security_assessment=SecurityAssessment.SUSPICIOUS if suspicious else SecurityAssessment.UNKNOWN,
            model_provider=context.model_provider, model_id=context.model_id,
            observed_facts=facts,
            hypotheses=[Hypothesis(statement="The sequence may warrant investigation, but successful password guessing and unauthorized access are not proven.", status="inconclusive", supporting_evidence_ids=[e.evidence_id for e in runtime_result.evidence])],
            evidence_refs=references(runtime_result.evidence), evidence_gaps=gaps,
            tool_calls=runtime_result.tool_calls,
            recommendations=["Have an analyst verify whether the source and admin login were authorized.", "Review additional host and identity telemetry around the session."],
            limitations=["Mock results are simulated." if any(e.simulated for e in runtime_result.evidence) else "Telemetry coverage depends on Wazuh indexing."],
            skills_used=[s.name for s in self.get_skills()], started_at=started_at,
            completed_at=self.dependencies.clock(),
        )

