"""JSON and CSV report writers."""

from __future__ import annotations

import csv
import io
import json
from typing import Any

CSV_COLUMNS = ("id", "severity", "status", "rule_id", "title", "service", "region", "account", "account_id",
               "resource_name", "resource", "first_detected", "last_detected", "compliance", "remediation")

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: Any) -> str:
    """Neutralise spreadsheet formula injection (CWE-1236)."""
    text = "; ".join(value) if isinstance(value, list) else ("" if value is None else str(value))
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def to_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, indent=2, default=str).encode()


def to_csv(data: dict[str, Any]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)
    for row in data["findings"]:
        writer.writerow([_csv_safe(row.get(col)) for col in CSV_COLUMNS])
    return buffer.getvalue().encode("utf-8-sig")
