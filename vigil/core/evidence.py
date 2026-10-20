from vigil.core.models import EvidenceRecord, EvidenceReference


def references(records: list[EvidenceRecord]) -> list[EvidenceReference]:
    seen: set[tuple[str, str]] = set()
    output: list[EvidenceReference] = []
    for record in records:
        key = (record.source_type, record.native_event_id)
        if key not in seen:
            output.append(EvidenceReference(evidence_id=record.evidence_id, native_event_id=record.native_event_id, source_type=record.source_type))
            seen.add(key)
    return output

