"""Fixtures for API-level tests (integration and security).

* ``database``  – rebuilds the schema with Alembic migrations (so migrations
  are verified on every run), seeds roles, permissions, rules and users.
* ``demo_account`` – connects the simulated environment and runs two real
  scans through the scan pipeline at different maturity levels.
* ``api(role)`` – a TestClient signed in as ADMIN, SECURITY_ANALYST or VIEWER
  with the CSRF header wired up, exactly like the browser client.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "apps" / "backend"
PASSWORD = "CloudAegis!Demo2026"
USERS = {
    "ADMIN": "admin@cloudaegis.local",
    "SECURITY_ANALYST": "analyst@cloudaegis.local",
    "VIEWER": "viewer@cloudaegis.local",
}
# Small simulated estate keeps API tests fast while exercising every service.
SCAN_OVERRIDES = {"scale": 0.12, "pace_seconds": 0}


class SyncQueue:
    """Runs scans inline so tests can assert on results deterministically."""

    def __init__(self) -> None:
        self.overrides: dict = dict(SCAN_OVERRIDES)
        self.enqueued: list[int] = []

    def enqueue(self, scan_id: int) -> None:
        from app.services.scans import execute_scan

        self.enqueued.append(scan_id)
        execute_scan(scan_id, provider_overrides=self.overrides)


def _reset_schema() -> None:
    from sqlalchemy import text

    from app.core.database import engine

    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))


def _migrate() -> None:
    from alembic import command
    from alembic.config import Config

    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session")
def database():
    from sqlalchemy import text

    from app.core.database import SessionLocal, engine

    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"PostgreSQL not reachable for API tests ({type(exc).__name__}); set TEST_DATABASE_URL")
    _reset_schema()
    _migrate()

    from app.services.demo import ensure_admin, ensure_demo_users
    from app.services.catalog import sync_catalog
    from app.workers.queue import set_queue

    with SessionLocal() as db:
        sync_catalog(db)
        ensure_admin(db)
        ensure_demo_users(db)
    queue = SyncQueue()
    set_queue(queue)
    yield queue


@pytest.fixture(scope="session")
def app(database):
    from app.main import app as fastapi_app

    return fastapi_app


@pytest.fixture(autouse=True)
def _fresh_rate_limits():
    from app.core.rate_limit import get_rate_limiter

    get_rate_limiter().reset()
    yield


@pytest.fixture(scope="session")
def demo_account(database):
    """The simulated account with two completed scans (maturity 0.3 → 0.6)."""
    from app.services import accounts
    from app.schemas.account import DemoAccountCreate
    from app.services.context import SYSTEM
    from app.services.scans import create_scan, execute_scan
    from app.core.database import SessionLocal

    with SessionLocal() as db:
        account = accounts.create_demo_account(db, DemoAccountCreate(name="Demo Cloud Environment", start_scan=False), SYSTEM)
        scan_ids = []
        for maturity in (0.3, 0.6):
            scan = create_scan(db, account.id, SYSTEM, trigger="seed")
            scan_ids.append(scan.id)
            execute_scan(scan.id, provider_overrides={**SCAN_OVERRIDES, "maturity": maturity})
        return {"id": account.id, "scans": scan_ids}


def _client(app, role: str | None):
    from fastapi.testclient import TestClient

    client = TestClient(app, raise_server_exceptions=False)
    if role:
        response = client.post("/api/v1/auth/login", json={"email": USERS[role], "password": PASSWORD})
        assert response.status_code == 200, response.text
        client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
    return client


@pytest.fixture
def api(app) -> Callable[[str | None], object]:
    """Factory: ``api("VIEWER")`` → signed-in client; ``api(None)`` → anonymous."""
    clients = []

    def make(role: str | None = "ADMIN"):
        client = _client(app, role)
        clients.append(client)
        return client

    yield make
    for c in clients:
        c.close()


@pytest.fixture
def admin(api):
    return api("ADMIN")
