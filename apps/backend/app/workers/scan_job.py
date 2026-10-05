"""Entry point executed by scan workers (thread pool or RQ)."""

from __future__ import annotations

from app.core.logging import request_id_ctx
from app.services.scans import execute_scan


def run_scan(scan_id: int) -> None:
    token = request_id_ctx.set(f"scan-{scan_id}")
    try:
        execute_scan(scan_id)
    finally:
        request_id_ctx.reset(token)
