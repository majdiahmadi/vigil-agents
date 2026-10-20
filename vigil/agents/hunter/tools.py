from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, Field

from vigil.core.models import CaseContext
from vigil.core.tool_registry import ToolDefinition
from vigil.integrations import SearchFilters


class HuntArgs(BaseModel):
    indicator: str | None = Field(default=None, max_length=256)
    host: str | None = Field(default=None, max_length=200)
    start: datetime
    end: datetime
    limit: int = Field(default=100, ge=1, le=100)


def _default(context: CaseContext) -> dict:
    window = context.scope.time_window
    observed = context.alert.normalized_fields.get("observed_at")
    anchor = datetime.fromisoformat(str(observed).replace("Z", "+00:00")) if observed else datetime.now(timezone.utc)
    return {"indicator": context.scope.indicators[0] if context.scope.indicators else None, "host": None, "start": window.start if window else anchor - timedelta(days=1), "end": window.end if window else anchor + timedelta(days=1), "limit": 100}


def build_tools(dependencies) -> list[ToolDefinition]:
    def enforce(args: HuntArgs, context: CaseContext) -> None:
        if args.indicator and context.scope.indicators and args.indicator not in context.scope.indicators:
            raise PermissionError("indicator is outside the authorized hunt scope")
        if args.host and context.scope.hosts and args.host not in context.scope.hosts:
            raise PermissionError("host is outside the authorized hunt scope")
        if not args.indicator and not args.host:
            raise PermissionError("hunt requires a scoped indicator or host")

    async def events(args: HuntArgs, context: CaseContext):
        enforce(args, context)
        return await dependencies.connector.search_events(context.case_id, SearchFilters(indicator=args.indicator, host=args.host, start=args.start, end=args.end, limit=args.limit))

    async def indicator(args: HuntArgs, context: CaseContext):
        enforce(args, context)
        return await dependencies.connector.search_by_indicator(context.case_id, SearchFilters(indicator=args.indicator, host=args.host, start=args.start, end=args.end, limit=args.limit))

    return [
        ToolDefinition("search_events", "Search bounded telemetry using structured hunt filters", HuntArgs, events, _default),
        ToolDefinition("search_by_indicator", "Pivot on one bounded indicator", HuntArgs, indicator, _default),
    ]

