"""Schema integrity: migrations match the models, required tables, keys and indexes exist."""

from __future__ import annotations

import pytest
from sqlalchemy import inspect

pytestmark = pytest.mark.integration

REQUIRED_TABLES = {
    "users", "roles", "permissions", "cloud_accounts", "cloud_regions", "assets", "asset_relationships",
    "security_rules", "findings", "finding_events", "scans", "scan_results", "compliance_frameworks",
    "compliance_controls", "compliance_mappings", "reports", "audit_logs", "notifications",
}


def test_migrations_match_models(database):
    """Alembic autogenerate finds nothing to change after `upgrade head`."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    from app.core.database import engine
    from app.models import Base

    with engine.connect() as conn:
        diff = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}), Base.metadata)
    assert diff == [], f"models and migrations differ: {diff}"


def test_required_tables_exist(database):
    from app.core.database import engine

    tables = set(inspect(engine).get_table_names())
    assert REQUIRED_TABLES <= tables, REQUIRED_TABLES - tables


@pytest.mark.parametrize(
    "table,column,target",
    [
        ("findings", "asset_id", "assets"),
        ("findings", "cloud_account_id", "cloud_accounts"),
        ("findings", "security_rule_id", "security_rules"),
        ("finding_events", "finding_id", "findings"),
        ("assets", "cloud_account_id", "cloud_accounts"),
        ("scans", "cloud_account_id", "cloud_accounts"),
        ("scan_results", "scan_id", "scans"),
        ("compliance_mappings", "security_rule_id", "security_rules"),
        ("users", "role_id", "roles"),
    ],
)
def test_foreign_keys(database, table, column, target):
    from app.core.database import engine

    fks = inspect(engine).get_foreign_keys(table)
    assert any(column in fk["constrained_columns"] and fk["referred_table"] == target for fk in fks)


@pytest.mark.parametrize("table,column", [("findings", "status"), ("findings", "severity"), ("assets", "resource_uid"),
                                          ("audit_logs", "timestamp"), ("users", "email")])
def test_query_paths_are_indexed(database, table, column):
    from app.core.database import engine

    insp = inspect(engine)
    indexed = {c for ix in insp.get_indexes(table) for c in ix["column_names"]}
    unique = {c for uq in insp.get_unique_constraints(table) for c in uq["column_names"]}
    assert column in indexed | unique, f"{table}.{column} is not indexed"


def test_catalog_is_synchronised(database):
    from sqlalchemy import func, select

    from app.core.database import SessionLocal
    from app.models import SecurityRule
    from cloudaegis_engine.rules import default_registry

    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(SecurityRule)) == len(default_registry())
