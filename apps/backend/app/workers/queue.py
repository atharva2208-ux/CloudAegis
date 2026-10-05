"""Scan job dispatch.

Two interchangeable executors keep the API responsive while scans run:

* ``inprocess`` — a bounded thread pool inside the API process (single-node
  deployments and local development);
* ``rq`` — jobs are pushed to Redis and executed by one or more separate
  ``rq worker`` processes (the docker-compose default), which scales
  horizontally and isolates scanning from request handling.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from app.core.config import get_settings

log = logging.getLogger("cloudaegis.queue")

QUEUE_NAME = "cloudaegis-scans"


class ScanQueue(Protocol):
    def enqueue(self, scan_id: int) -> None: ...


class InProcessQueue:
    def __init__(self, workers: int) -> None:
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan")

    def enqueue(self, scan_id: int) -> None:
        from app.workers.scan_job import run_scan

        future = self._pool.submit(run_scan, scan_id)
        future.add_done_callback(lambda f: f.exception() and log.error("scan_thread_error", exc_info=f.exception()))


class RedisQueue:
    def __init__(self, redis_url: str, timeout: int) -> None:
        from redis import Redis
        from rq import Queue

        self._queue = Queue(QUEUE_NAME, connection=Redis.from_url(redis_url), default_timeout=timeout)

    def enqueue(self, scan_id: int) -> None:
        self._queue.enqueue("app.workers.scan_job.run_scan", scan_id, job_id=f"scan-{scan_id}",
                            failure_ttl=86400, result_ttl=3600)


_queue: ScanQueue | None = None


def get_queue() -> ScanQueue:
    global _queue
    if _queue is None:
        settings = get_settings()
        if settings.scan_executor == "rq" and settings.redis_url:
            _queue = RedisQueue(settings.redis_url, settings.scan_timeout_seconds)
        else:
            _queue = InProcessQueue(settings.scan_workers)
        log.info("scan_queue_ready", extra={"executor": type(_queue).__name__})
    return _queue


def set_queue(queue: ScanQueue) -> None:
    """Override the queue (tests)."""
    global _queue
    _queue = queue
