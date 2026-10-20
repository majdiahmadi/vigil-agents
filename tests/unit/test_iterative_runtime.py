import json
from datetime import datetime, timezone

import pytest
from pydantic import BaseModel

from vigil.core.models import AlertEnvelope, CaseContext, EvidenceRecord
from vigil.core.runtime import AgentRuntime
from vigil.core.tool_registry import ToolDefinition, ToolRegistry


class SearchArgs(BaseModel):
    source_ip: str


class EvidenceAwareFakeModel:
    def __init__(self):
        self.calls = 0

    async def complete(self, *, messages, tools):
        self.calls += 1
        if self.calls == 1:
            context = json.loads(messages[-1]["content"])
            assert context["description"] == "Investigate the submitted SSH sequence"
            assert context["observed_at"] == "2026-10-19T10:00:00+00:00"
            assert context["verified_case_memory"][0]["native_event_id"] == "prior-1"
            return {"content": None, "tool_calls": [{"id": "auth-1", "type": "function", "function": {"name": "auth", "arguments": '{"source_ip":"192.0.2.10"}'}}]}
        if self.calls == 2:
            tool_messages = [message for message in messages if message["role"] == "tool"]
            assert tool_messages[-1]["tool_call_id"] == "auth-1"
            assert '"event_count": 15' in tool_messages[-1]["content"]
            return {"content": None, "tool_calls": [{"id": "session-1", "type": "function", "function": {"name": "sessions", "arguments": '{"source_ip":"192.0.2.10"}'}}]}
        assert any(message.get("tool_call_id") == "session-1" for message in messages)
        return {"content": '{"assessment":"inconclusive","evidence_ids":["ev-auth","ev-session"]}', "tool_calls": []}


@pytest.mark.asyncio
async def test_model_receives_tool_evidence_before_choosing_follow_up():
    alert = AlertEnvelope.from_payload({"alert": {"alert_id": "a-1", "attack": "SSH", "description": "Investigate the submitted SSH sequence", "ip": "192.0.2.10", "observed_at": "2026-10-19T10:00:00Z"}})
    context = CaseContext(case_id="case-1", alert=alert, agent_id="triage", run_id="run-1", scope=alert.asset_scope, model_provider="test", model_id="test", purpose="correlate authentication and session activity", memory=[{"native_event_id": "prior-1", "verified": True}])
    registry = ToolRegistry({"auth", "sessions"}, max_calls=4)

    async def auth(args, context):
        return [EvidenceRecord(evidence_id="ev-auth", case_id=context.case_id, native_event_id="auth-native", source_type="test", connector_mode="test", observed_at=datetime.now(timezone.utc), source_ip=args.source_ip, normalized_event_kind="auth_failed", event_count=15)]

    async def sessions(args, context):
        return [EvidenceRecord(evidence_id="ev-session", case_id=context.case_id, native_event_id="session-native", source_type="test", connector_mode="test", observed_at=datetime.now(timezone.utc), source_ip=args.source_ip, normalized_event_kind="session_start", event_count=1)]

    registry.register(ToolDefinition("auth", "auth", SearchArgs, auth, lambda c: {"source_ip": "192.0.2.10"}))
    registry.register(ToolDefinition("sessions", "sessions", SearchArgs, sessions, lambda c: {"source_ip": "192.0.2.10"}))
    fake = EvidenceAwareFakeModel()
    result = await AgentRuntime(max_rounds=4).execute(context=context, instructions="test", skills=[], registry=registry, model_adapter=fake)

    assert fake.calls == 3
    assert [call.call_id for call in result.tool_calls] == ["auth-1", "session-1"]
    assert {item.evidence_id for item in result.evidence} == {"ev-auth", "ev-session"}
    assert result.rounds == 3


@pytest.mark.asyncio
async def test_every_invalid_model_call_gets_one_tool_response():
    class InvalidFake:
        calls = 0
        async def complete(self, *, messages, tools):
            self.calls += 1
            if self.calls == 1:
                return {"tool_calls": [
                    {"id": "bad-json", "function": {"name": "safe", "arguments": "{"}},
                    {"id": "unknown", "function": {"name": "shell", "arguments": "{}"}},
                ]}
            replies = [message["tool_call_id"] for message in messages if message["role"] == "tool"]
            assert replies == ["bad-json", "unknown"]
            return {"content": "done", "tool_calls": []}

    alert = AlertEnvelope.from_payload({"alert": {"attack": "SSH", "ip": "192.0.2.10"}})
    context = CaseContext(case_id="case-x", alert=alert, agent_id="triage", run_id="run-x", scope=alert.asset_scope, model_provider="test", model_id="test")
    registry = ToolRegistry({"safe"})
    registry.register(ToolDefinition("safe", "safe", SearchArgs, lambda a, c: None, lambda c: {"source_ip": "192.0.2.10"}))
    result = await AgentRuntime().execute(context=context, instructions="test", skills=[], registry=registry, model_adapter=InvalidFake())
    assert [call.status for call in result.tool_calls] == ["invalid_arguments", "denied"]
