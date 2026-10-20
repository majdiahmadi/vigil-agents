from vigil.core.models import AgentResult, EvidenceRecord


class EvidenceValidator:
    forbidden_claims = (
        "confirmed brute force succeeded",
        "proven unauthorized access",
        "whoami proves reconnaissance",
        "response was executed",
    )

    def validate(self, result: AgentResult, evidence: list[EvidenceRecord]) -> list[str]:
        known = {item.evidence_id for item in evidence}
        errors: list[str] = []
        for fact in result.observed_facts:
            missing = set(fact.evidence_ids) - known
            if missing:
                errors.append(f"fact references unknown evidence: {sorted(missing)}")
        text = " ".join(f.statement.lower() for f in result.observed_facts)
        for phrase in self.forbidden_claims:
            if phrase in text:
                errors.append(f"unsupported prohibited claim: {phrase}")
        if result.response_executed:
            errors.append("VIGIL cannot execute remediation")
        return errors

