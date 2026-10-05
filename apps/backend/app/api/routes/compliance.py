from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, require
from app.core.database import get_db
from app.core.permissions import Perm
from app.services import compliance as compliance_service

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/frameworks")
def frameworks(account_id: int | None = None, _: AuthContext = Depends(require(Perm.COMPLIANCE_READ)),
               db: Session = Depends(get_db)) -> dict:
    return compliance_service.overview(db, account_id)


@router.get("/frameworks/{key}")
def framework(key: str, account_id: int | None = None, _: AuthContext = Depends(require(Perm.COMPLIANCE_READ)),
              db: Session = Depends(get_db)) -> dict:
    return compliance_service.framework_detail(db, key, account_id)


@router.get("/frameworks/{key}/controls/{control_id}/findings")
def control_findings(key: str, control_id: str, account_id: int | None = None,
                     _: AuthContext = Depends(require(Perm.COMPLIANCE_READ, Perm.FINDINGS_READ)),
                     db: Session = Depends(get_db)) -> list[dict]:
    return compliance_service.control_findings(db, key, control_id, account_id)


@router.get("/controls")
def controls(account_id: int | None = None, framework: str | None = Query(None, max_length=32),
             status: Literal["PASS", "FAIL", "NOT_APPLICABLE"] | None = None, q: str | None = Query(None, max_length=100),
             _: AuthContext = Depends(require(Perm.COMPLIANCE_READ)), db: Session = Depends(get_db)) -> list[dict]:
    return compliance_service.all_controls(db, account_id, framework, status, q)
