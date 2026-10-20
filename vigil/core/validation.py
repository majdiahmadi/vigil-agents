from typing import Any

from vigil.core.models import AgentResult, EvidenceClaim, EvidenceRecord


class EvidenceValidator:
    forbidden_claims = (
        "confirmed brute force succeeded",
        "proven unauthorized access",
        "whoami proves reconnaissance",
        "response was executed",
    )

    def validate(self, result: AgentResult, evidence: list[EvidenceRecord]) -> list[str]:
        known = {item.evidence_id: item for item in evidence}
        errors: list[str] = []
        for fact in result.observed_facts:
            missing = set(fact.evidence_ids) - set(known)
            if missing:
                errors.append(f"fact references unknown evidence: {sorted(missing)}")
            for claim in fact.claims:
                if claim.evidence_id not in fact.evidence_ids:
                    errors.append(f"claim evidence {claim.evidence_id} is not cited by its fact")
                    continue
                record = known.get(claim.evidence_id)
                if record is None:
                    continue
                actual = self._field(record, claim.field_path)
                if not self._matches(actual, claim):
                    errors.append(
                        f"unsupported claim for {claim.evidence_id}: {claim.field_path} "
                        f"{claim.operator} {claim.expected_value!r} (actual {actual!r})"
                    )
        text = " ".join(f.statement.lower() for f in result.observed_facts)
        for phrase in self.forbidden_claims:
            if phrase in text:
                errors.append(f"unsupported prohibited claim: {phrase}")
        if result.response_executed:
            errors.append("VIGIL cannot execute remediation")
        return errors

    @staticmethod
    def _field(record: EvidenceRecord, path: str) -> Any:
        value: Any = record.model_dump(mode="python")
        for part in path.split("."):
            if not isinstance(value, dict) or part not in value:
                return None
            value = value[part]
        return value

    @staticmethod
    def _matches(actual: Any, claim: EvidenceClaim) -> bool:
        try:
            if claim.operator == "eq":
                return actual == claim.expected_value
            if claim.operator == "contains":
                return claim.expected_value in actual
            if claim.operator == "gte":
                return actual >= claim.expected_value
            if claim.operator == "lte":
                return actual <= claim.expected_value
        except (TypeError, ValueError):
            return False
        return False

