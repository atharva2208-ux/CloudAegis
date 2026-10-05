"""Time helpers. Providers emit ISO-8601 strings; rules compare ages."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def parse_ts(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def age_days(value: Any, now: datetime | None = None) -> int | None:
    ts = parse_ts(value)
    if ts is None:
        return None
    now = now or datetime.now(timezone.utc)
    return max(0, (now - ts).days)
