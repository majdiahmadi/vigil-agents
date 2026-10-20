from vigil.core.models import CaseContext
from vigil.core.skills import Skill


def build_prompt(context: CaseContext, skills: list[Skill]) -> str:
    return "You are VIGIL Hunter. Use structured bounded filters only. Correlation is not proof of lateral movement, compromise, or attribution.\n" + "\n".join(s.render() for s in skills)

