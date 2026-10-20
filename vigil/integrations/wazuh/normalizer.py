from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from vigil.core.models import EvidenceRecord, NormalizedEventKind


def _stable_id(case_id: str, source_type: str, native_id: str, index_name: str | None = None) -> str:
    value = f"{case_id}|{source_type}|{index_name or ''}|{native_id}".encode("utf-8")
    return f"ev-{hashlib.sha256(value).hexdigest()[:20]}"


def _timestamp(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _classify(*, action: str, kind: str, decoder: str, description: str, command: str | None, file_hash: str | None) -> NormalizedEventKind:
    text = " ".join((action, kind, decoder, description)).casefold()
    if action == "ssh_failed" or ("ssh" in text and any(term in text for term in ("failed", "failure", "invalid user"))):
        return NormalizedEventKind.AUTH_FAILED
    if action == "ssh_success" or ("ssh" in text and any(term in text for term in ("accepted", "success"))):
        return NormalizedEventKind.AUTH_SUCCESS
    if action == "session_started" or ("session" in text and any(term in text for term in ("start", "opened"))):
        return NormalizedEventKind.SESSION_START
    if action == "command_observed" or command:
        return NormalizedEventKind.COMMAND
    if kind in {"file", "fim"} or file_hash:
        return NormalizedEventKind.FILE_EVENT
    if kind == "process":
        return NormalizedEventKind.PROCESS_EVENT
    if kind in {"network", "dns"}:
        return NormalizedEventKind.NETWORK_EVENT
    if any(term in text for term in ("malware", "trojan", "ransomware")):
        return NormalizedEventKind.MALWARE_ALERT
    return NormalizedEventKind.UNKNOWN


def normalize_hit(case_id: str, hit: dict[str, Any], query_scope: dict[str, Any]) -> EvidenceRecord:
    source = hit.get("_source", {}) if isinstance(hit.get("_source", {}), dict) else {}
    data = source.get("data", {}) if isinstance(source.get("data"), dict) else {}
    agent = source.get("agent", {}) if isinstance(source.get("agent"), dict) else {}
    rule = source.get("rule", {}) if isinstance(source.get("rule"), dict) else {}
    decoder_value = source.get("decoder", {})
    decoder = str(decoder_value.get("name", "")) if isinstance(decoder_value, dict) else str(decoder_value or "")
    command = data.get("command") or data.get("audit", {}).get("command") if isinstance(data.get("audit"), dict) else data.get("command")
    file_hash = data.get("sha256") or data.get("hash", {}).get("sha256") if isinstance(data.get("hash"), dict) else data.get("sha256")
    event_count_raw = rule.get("firedtimes") or source.get("event_count") or data.get("count")
    try:
        event_count = max(1, int(event_count_raw)) if event_count_raw is not None else 1
    except (TypeError, ValueError):
        event_count = None
    native_id = str(hit.get("_id") or source.get("id") or "missing-native-id")
    index_name = str(hit.get("_index")) if hit.get("_index") is not None else None
    kind = _classify(
        action=str(data.get("action") or source.get("action") or ""),
        kind=str(source.get("kind") or ""), decoder=decoder,
        description=str(rule.get("description") or source.get("full_log") or ""),
        command=str(command) if command else None, file_hash=str(file_hash) if file_hash else None,
    )
    return EvidenceRecord(
        evidence_id=_stable_id(case_id, "wazuh_indexer", native_id, index_name),
        case_id=case_id, native_event_id=native_id, source_type="wazuh_indexer", connector_mode="wazuh",
        observed_at=_timestamp(source.get("timestamp") or source.get("@timestamp")), index_name=index_name,
        host=agent.get("name") or (source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else None),
        agent_id=str(agent.get("id")) if agent.get("id") is not None else None,
        user=data.get("srcuser") or data.get("dstuser") or (source.get("user", {}).get("name") if isinstance(source.get("user"), dict) else source.get("user")),
        source_ip=data.get("srcip") or (source.get("source", {}).get("ip") if isinstance(source.get("source"), dict) else None),
        destination_ip=data.get("dstip") or (source.get("destination", {}).get("ip") if isinstance(source.get("destination"), dict) else None),
        rule_id=str(rule.get("id")) if rule.get("id") is not None else None,
        normalized_event_kind=kind, event_count=event_count,
        command=str(command) if command else None, file_hash=str(file_hash) if file_hash else None,
        raw_fields={"_index": index_name, "_source": source}, query_scope=query_scope,
        telemetry_coverage={"status": "covered", "returned": 1, "source": "wazuh_indexer"},
        provenance={"native_event_id": native_id, "index_name": index_name}, simulated=False,
    )


def normalize_mock_event(case_id: str, event: dict[str, Any], query_scope: dict[str, Any]) -> EvidenceRecord:
    native_id = str(event.get("event_id") or "missing-native-id")
    command = str(event.get("command")) if event.get("command") else None
    file_hash = str(event.get("sha256")) if event.get("sha256") else None
    kind = _classify(
        action=str(event.get("action") or ""), kind=str(event.get("kind") or ""), decoder="mock",
        description=str(event.get("description") or ""), command=command, file_hash=file_hash,
    )
    try:
        event_count = max(1, int(event.get("attempts") or event.get("event_count") or 1))
    except (TypeError, ValueError):
        event_count = None
    return EvidenceRecord(
        evidence_id=_stable_id(case_id, "mock_wazuh_event", native_id),
        case_id=case_id, native_event_id=native_id, source_type="mock_wazuh_event", connector_mode="mock",
        observed_at=_timestamp(event.get("timestamp")), host=event.get("host"),
        agent_id=str(event.get("agent_id")) if event.get("agent_id") is not None else None,
        user=event.get("user"), source_ip=event.get("source_ip"), destination_ip=event.get("destination_ip"),
        rule_id=str(event.get("rule_id")) if event.get("rule_id") is not None else None,
        normalized_event_kind=kind, event_count=event_count, command=command, file_hash=file_hash,
        raw_fields=dict(event), query_scope=query_scope,
        telemetry_coverage={"status": "covered", "returned": 1, "source": "mock_fixture"},
        provenance={"native_event_id": native_id, "fixture": True}, simulated=True,
    )
