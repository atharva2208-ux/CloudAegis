from fastapi import APIRouter

from app.api.routes import accounts, assets, auth, compliance, findings, platform, reports, scans, users

api_router = APIRouter(prefix="/api/v1")
for module in (auth, users, accounts, assets, findings, scans, compliance, reports, platform):
    api_router.include_router(module.router)
