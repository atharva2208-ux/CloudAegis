"""Standalone RQ worker: ``python -m app.workers.worker``."""

from __future__ import annotations

from redis import Redis
from rq import Queue, Worker

from app.core.config import get_settings
from app.core.logging import configure_logging
from app.workers.queue import QUEUE_NAME


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    if not settings.redis_url:
        raise SystemExit("REDIS_URL is required for the RQ worker")
    connection = Redis.from_url(settings.redis_url)
    Worker([Queue(QUEUE_NAME, connection=connection)], connection=connection).work(with_scheduler=False)


if __name__ == "__main__":
    main()
