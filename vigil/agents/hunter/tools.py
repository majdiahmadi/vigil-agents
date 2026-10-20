from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field

from vigil.core.models import CaseContext
from vigil.core.tool_registry import ToolDefinition
from vigil.integrations import SearchFilters


class HuntArgs(BaseModel):
    indicator: str | None = Field(default=None, max_length=256)
    host: str | None = Field(default=None, max_length=200)
    source_ip: str | None = None
    start: datetime
    end: datetime
    limit: int = Field(default=100, ge=1, le=100)


def _default(context: CaseContext) -> dict:
    window = context.scope.time_window
    observed = context.alert.normalized_fields.get("observed_at")
    anchor = datetime.fromisoformat(str(observed).replace("Z", "+00:00")) if observed else datetime.now(timezone.utc)
    return {
        "indicator": context.scope.indicators[0] if context.scope.indicators else None,
        "host": None,
        "source_ip": context.scope.source_ips[0] if context.scope.source_ips and not context.scope.indicators else None,
        "start": window.start if window else anchor - timedelta(days=1),
        "end": window.end if window else anchor + timedelta(days=1),
        "limit": 100,
    }


def build_tools(dependencies) -> list[ToolDefinition]:
    def enforce(args: HuntArgs, context: CaseContext) -> None:
        values = ((args.indicator, context.scope.indicators, "indicator"), (args.host, context.scope.hosts, "host"), (args.source_ip, context.scope.source_ips, "source IP"))
        if not any(value for value, _, _ in values):
            raise PermissionError("hunt requires a scoped indicator, host, or source IP")
        for value, allowed, label in values:
            if value and (not allowed or value not in allowed):
                raise PermissionError(f"{label} is outside the authorized hunt scope")
        if context.scope.time_window and (args.start < context.scope.time_window.start or args.end > context.scope.time_window.end):
            raise PermissionError("requested time window is outside the authorized hunt scope")

    def filters(args: HuntArgs) -> SearchFilters:
        return SearchFilters(indicator=args.indicator, host=args.host, source_ip=args.source_ip, start=args.start, end=args.end, limit=args.limit)

    async def auth_trends(args: HuntArgs, context: CaseContext):
        enforce(args, context)
        return await dependencies.connector.search_authentication_events(context.case_id, filters(args))

    async def cross_host(args: HuntArgs, context: CaseContext):
        enforce(args, context)
        return await dependencies.connector.search_by_indicator(context.case_id, filters(args))

    async def timeline(args: HuntArgs, context: CaseContext):
        enforce(args, context)
        return await dependencies.connector.search_events(context.case_id, filters(args))

    return [
        ToolDefinition("hunt_authentication_trends", "Test a bounded distributed-authentication hypothesis", HuntArgs, auth_trends, _default),
        ToolDefinition("hunt_cross_host_indicator", "Correlate one approved indicator across scoped hosts", HuntArgs, cross_host, _default),
        ToolDefinition("get_event_timeline", "Retrieve a bounded event timeline for the hunt hypothesis", HuntArgs, timeline, _default),
    ]
