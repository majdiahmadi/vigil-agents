from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field, field_validator

from vigil.core.models import CaseContext
from vigil.core.tool_registry import ToolDefinition
from vigil.integrations import SearchFilters


class EventSearchArgs(BaseModel):
    source_ip: str | None = None
    host: str | None = None
    user: str | None = None
    start: datetime
    end: datetime
    limit: int = Field(default=100, ge=1, le=100)

    @field_validator("source_ip")
    @classmethod
    def ip(cls, value):
        if value:
            from ipaddress import ip_address
            ip_address(value)
        return value


def _defaults(context: CaseContext) -> dict:
    window = context.scope.time_window
    observed = context.alert.normalized_fields.get("observed_at")
    anchor = datetime.fromisoformat(str(observed).replace("Z", "+00:00")) if observed else datetime.now(timezone.utc)
    return {
        "source_ip": context.scope.source_ips[0] if context.scope.source_ips else None,
        "host": context.scope.hosts[0] if context.scope.hosts else None,
        "user": context.scope.users[0] if context.scope.users else None,
        "start": window.start if window else anchor - timedelta(days=1),
        "end": window.end if window else anchor + timedelta(days=1),
        "limit": 100,
    }


def build_tools(dependencies) -> list[ToolDefinition]:
    def enforce(args: EventSearchArgs, context: CaseContext) -> None:
        if not any((args.source_ip, args.host, args.user)):
            raise PermissionError("triage search requires a scoped IP, host, or user")
        checks = ((args.source_ip, context.scope.source_ips, "source IP"), (args.host, context.scope.hosts, "host"), (args.user, context.scope.users, "user"))
        for value, allowed, label in checks:
            if allowed and value not in allowed:
                raise PermissionError(f"{label} is outside the authorized case scope")

    async def auth(args: EventSearchArgs, context: CaseContext):
        enforce(args, context)
        return await dependencies.connector.search_authentication_events(context.case_id, SearchFilters(**args.model_dump()))

    async def sessions(args: EventSearchArgs, context: CaseContext):
        enforce(args, context)
        return await dependencies.connector.search_session_events(context.case_id, SearchFilters(**args.model_dump()))

    async def events(args: EventSearchArgs, context: CaseContext):
        enforce(args, context)
        return await dependencies.connector.search_events(context.case_id, SearchFilters(**args.model_dump()))

    return [
        ToolDefinition("search_authentication_events", "Read bounded authentication events", EventSearchArgs, auth, _defaults),
        ToolDefinition("search_session_events", "Read bounded session and command events", EventSearchArgs, sessions, _defaults),
        ToolDefinition("search_events", "Read bounded surrounding security events", EventSearchArgs, events, _defaults),
    ]

