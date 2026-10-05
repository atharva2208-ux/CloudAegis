"""Operational commands.

    python -m app.cli bootstrap        # sync catalogs, create admin, seed demo (if DEMO_MODE)
    python -m app.cli create-user EMAIL "Full Name" ROLE
"""

from __future__ import annotations

import argparse
import getpass
import sys

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.logging import configure_logging
from app.core.permissions import Role


def main(argv: list[str] | None = None) -> int:
    settings = get_settings()
    configure_logging(settings.log_level, settings.log_json)
    parser = argparse.ArgumentParser(prog="cloudaegis")
    sub = parser.add_subparsers(dest="command", required=True)
    boot = sub.add_parser("bootstrap", help="Initialise catalogs, admin user and demo data")
    boot.add_argument("--no-demo", action="store_true")
    cu = sub.add_parser("create-user", help="Create a user (password read from stdin/tty)")
    cu.add_argument("email")
    cu.add_argument("full_name")
    cu.add_argument("role", choices=[r.value for r in Role])
    args = parser.parse_args(argv)

    with SessionLocal() as db:
        if args.command == "bootstrap":
            from app.services.demo import bootstrap

            result = bootstrap(db, with_demo=False if args.no_demo else None)
            print(f"Admin account: {result['admin']}")
            if result["generated_password"]:
                print(f"Generated admin password (shown once): {result['generated_password']}")
            print("Demo environment seeded" if result["demo_seeded"] else "Demo environment unchanged")
        elif args.command == "create-user":
            from app.schemas.auth import UserCreate
            from app.services.context import SYSTEM
            from app.services.users import create_user

            password = getpass.getpass("Password: ") if sys.stdin.isatty() else sys.stdin.readline().strip()
            user = create_user(db, UserCreate(email=args.email, full_name=args.full_name, role=Role(args.role),
                                              password=password), SYSTEM)
            print(f"Created {user.email} ({user.role_name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
