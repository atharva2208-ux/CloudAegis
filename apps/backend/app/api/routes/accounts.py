from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, require
from app.core.database import get_db
from app.core.permissions import Perm
from app.schemas.account import (
    AccountCreate,
    AccountOut,
    AccountUpdate,
    ConnectionTestRequest,
    ConnectionTestResult,
    DemoAccountCreate,
    OnboardingGuide,
)
from app.schemas.common import Message
from app.services import accounts as account_service, scans as scan_service
from app.services.context import Actor
from app.workers.queue import get_queue

router = APIRouter(prefix="/accounts", tags=["cloud accounts"])


def _maybe_scan(db: Session, account_id: int, start: bool, actor: Actor) -> None:
    if start:
        scan = scan_service.create_scan(db, account_id, actor, trigger="onboarding")
        get_queue().enqueue(scan.id)


@router.get("", response_model=list[AccountOut])
def list_accounts(_: AuthContext = Depends(require(Perm.ACCOUNTS_READ)), db: Session = Depends(get_db)) -> list[dict]:
    return account_service.list_accounts(db)


@router.get("/onboarding-guide", response_model=OnboardingGuide,
            summary="IAM trust policy, least-privilege policy and CloudFormation template for the audit role")
def onboarding_guide(_: AuthContext = Depends(require(Perm.ACCOUNTS_MANAGE))) -> dict:
    return account_service.onboarding_guide()


@router.post("/test-connection", response_model=ConnectionTestResult)
def test_connection(data: ConnectionTestRequest, ctx: AuthContext = Depends(require(Perm.ACCOUNTS_MANAGE))) -> dict:
    result = account_service.test_connection(data.credentials, data.default_region)
    return result.__dict__


@router.post("", response_model=AccountOut, status_code=201)
def create_account(data: AccountCreate, ctx: AuthContext = Depends(require(Perm.ACCOUNTS_MANAGE)),
                   db: Session = Depends(get_db)) -> dict:
    account = account_service.create_aws_account(db, data, ctx.actor)
    _maybe_scan(db, account.id, data.start_scan, ctx.actor)
    return account_service.account_out(account)


@router.post("/demo", response_model=AccountOut, status_code=201, summary="Connect the simulated demo environment")
def create_demo(data: DemoAccountCreate, ctx: AuthContext = Depends(require(Perm.ACCOUNTS_MANAGE)),
                db: Session = Depends(get_db)) -> dict:
    account = account_service.create_demo_account(db, data, ctx.actor)
    _maybe_scan(db, account.id, data.start_scan, ctx.actor)
    return account_service.account_out(account)


@router.get("/{account_id}", response_model=AccountOut)
def get_account(account_id: int, _: AuthContext = Depends(require(Perm.ACCOUNTS_READ)),
                db: Session = Depends(get_db)) -> dict:
    account_service.get_account(db, account_id)
    return next(a for a in account_service.list_accounts(db) if a["id"] == account_id)


@router.patch("/{account_id}", response_model=AccountOut)
def update_account(account_id: int, data: AccountUpdate, ctx: AuthContext = Depends(require(Perm.ACCOUNTS_MANAGE)),
                   db: Session = Depends(get_db)) -> dict:
    account_service.update_account(db, account_id, data, ctx.actor)
    return next(a for a in account_service.list_accounts(db) if a["id"] == account_id)


@router.post("/{account_id}/validate", response_model=ConnectionTestResult)
def validate(account_id: int, ctx: AuthContext = Depends(require(Perm.ACCOUNTS_MANAGE)),
             db: Session = Depends(get_db)) -> dict:
    return account_service.revalidate(db, account_id, ctx.actor).__dict__


@router.delete("/{account_id}", response_model=Message)
def delete_account(account_id: int, ctx: AuthContext = Depends(require(Perm.ACCOUNTS_MANAGE)),
                   db: Session = Depends(get_db)) -> dict:
    account_service.delete_account(db, account_id, ctx.actor)
    return {"message": "Account removed"}
