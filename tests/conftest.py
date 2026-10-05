"""Shared test configuration.

Environment variables are set *before* the application is imported so the
SQLAlchemy engine, rate limiter and scan queue bind to test resources.

Database: integration and security tests need PostgreSQL (the production
database). ``TEST_DATABASE_URL`` selects it; the default points at a local
``cloudaegis_test`` database. The schema is rebuilt with Alembic for each run.
If PostgreSQL is unreachable those tests are skipped; unit tests need nothing.
No test needs a real AWS account: AWS calls are served by moto and scans use
the simulated provider.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "apps" / "backend"
ENGINE = ROOT / "packages" / "security-engine"
for path in (BACKEND, ENGINE, ROOT / "tests"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

_tmp = Path(tempfile.mkdtemp(prefix="cloudaegis-test-"))
os.environ.update(
    {
        "ENVIRONMENT": "test",
        "DATABASE_URL": os.environ.get(
            "TEST_DATABASE_URL", "postgresql+psycopg2://cloudaegis:cloudaegis@localhost:5432/cloudaegis_test"
        ),
        "REDIS_URL": "",
        "SCAN_EXECUTOR": "inprocess",
        "DEMO_MODE": "true",
        "COOKIE_SECURE": "false",
        "LOG_JSON": "false",
        "LOG_LEVEL": "WARNING",
        "SECRET_KEY": "test-secret-key-0123456789abcdef0123456789abcdef",
        "CREDENTIAL_ENCRYPTION_KEY": "",
        "LOGIN_RATE_LIMIT_PER_MINUTE": "1000",
        "API_RATE_LIMIT_PER_MINUTE": "100000",
        # moto / boto3 must never pick up real credentials from the host.
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_CONFIG_FILE": os.devnull,
        "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
    }
)

# API fixtures import the application lazily, so unit tests never touch a database.
pytest_plugins = ["fixtures.app_fixtures"]
