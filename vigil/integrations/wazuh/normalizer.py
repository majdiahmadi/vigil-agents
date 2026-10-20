from __future__ import annotations

from datetime import datetime
from typing import Any

from vigil.core.models import EvidenceRecord


def normalize_hit(case_id: str, hit: dict[str, Any], query_scope: dict[str, Any]) -> EvidenceRecord:
    source = hit.get("_source", {})
    data = source.get("data", {}) if isinstance(source.get("data"), dict) else {}
    agent = source.get("agent", {}) if isinstance(source.get("agent"), dict) else {}
    rule = source.get("rule", {}) if isinstance(source.get("rule"), dict) else {}
    ts = source.get("timestamp") or source.get("@timestamp")
    observed = datetime.fromisoformat(str(ts).replace("Z", "+00:00")) if ts else None
    return EvidenceRecord(
        case_id=case_id,
        native_event_id=str(hit.get("_id") or source.get("id") or "missing-native-id"),
        source_type="wazuh_indexer",
        connector_mode="wazuh",
        observed_at=observed,
        host=agent.get("name") or source.get("host", {}).get("name") if isinstance(source.get("host"), dict) else agent.get("name"),
        user=data.get("srcuser") or data.get("dstuser") or source.get("user"),
        source_ip=data.get("srcip") or source.get("source", {}).get("ip") if isinstance(source.get("source"), dict) else data.get("srcip"),
        destination_ip=data.get("dstip") or source.get("destination", {}).get("ip") if isinstance(source.get("destination"), dict) else data.get("dstip"),
        rule_id=str(rule.get("id")) if rule.get("id") is not None else None,
        raw_fields={"_index": hit.get("_index"), "_source": source},
        query_scope=query_scope,
        simulated=False,
    )

