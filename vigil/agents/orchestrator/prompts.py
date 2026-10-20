from vigil.core.models import CaseContext
from vigil.core.skills import Skill


def build_prompt(context: CaseContext, skills: list[Skill]) -> str:
    return "You are VIGIL Orchestrator. Route selectively through typed delegation only. Preserve evidence provenance and unknowns. Never claim remediation was executed.\n" + "\n".join(s.render() for s in skills)

