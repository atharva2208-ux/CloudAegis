from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import AuthContext, require
from app.core.database import get_db
from app.core.permissions import Perm
from app.models import RoleModel
from app.schemas.auth import RoleOut, UserCreate, UserOut, UserUpdate
from app.services import users as user_service

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
def list_users(_: AuthContext = Depends(require(Perm.USERS_MANAGE)), db: Session = Depends(get_db)) -> list[dict]:
    return [user_service.to_out(u) for u in user_service.list_users(db)]


@router.post("", response_model=UserOut, status_code=201)
def create_user(data: UserCreate, ctx: AuthContext = Depends(require(Perm.USERS_MANAGE)),
                db: Session = Depends(get_db)) -> dict:
    return user_service.to_out(user_service.create_user(db, data, ctx.actor))


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: int, data: UserUpdate, ctx: AuthContext = Depends(require(Perm.USERS_MANAGE)),
                db: Session = Depends(get_db)) -> dict:
    return user_service.to_out(user_service.update_user(db, user_id, data, ctx.actor))


@router.post("/{user_id}/unlock", response_model=UserOut)
def unlock_user(user_id: int, ctx: AuthContext = Depends(require(Perm.USERS_MANAGE)),
                db: Session = Depends(get_db)) -> dict:
    return user_service.to_out(user_service.unlock_user(db, user_id, ctx.actor))


@router.get("/roles", response_model=list[RoleOut])
def roles(_: AuthContext = Depends(require(Perm.USERS_MANAGE)), db: Session = Depends(get_db)) -> list[dict]:
    return [{"name": r.name, "description": r.description, "permissions": sorted(r.permission_codes)}
            for r in db.scalars(select(RoleModel).order_by(RoleModel.id)).all()]
