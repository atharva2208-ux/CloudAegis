"""Users, settings, rule catalogue, audit trail and notifications."""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration
STRONG = "Correct-Horse-Battery-9"


def _new_user(admin, role="VIEWER"):
    email = f"user-{uuid.uuid4().hex[:8]}@example.com"
    r = admin.post("/api/v1/users", json={"email": email, "full_name": "Test User", "role": role, "password": STRONG})
    assert r.status_code == 201, r.text
    return r.json()


def _login(api, email, password=STRONG):
    from fastapi.testclient import TestClient

    client = api(None)
    return client, client.post("/api/v1/auth/login", json={"email": email, "password": password})


def test_create_user_and_sign_in(admin, api):
    user = _new_user(admin, "SECURITY_ANALYST")
    assert user["role"] == "SECURITY_ANALYST"
    assert "password" not in str(user).lower() or "password_hash" not in user
    _, r = _login(api, user["email"])
    assert r.status_code == 200
    assert "findings:update" in r.json()["user"]["permissions"]
    assert "users:manage" not in r.json()["user"]["permissions"]


def test_weak_and_duplicate_users_rejected(admin):
    weak = admin.post("/api/v1/users", json={"email": "weak@example.com", "full_name": "W", "role": "VIEWER", "password": "password"})
    assert weak.status_code == 422
    user = _new_user(admin)
    dup = admin.post("/api/v1/users", json={"email": user["email"].upper(), "full_name": "Dupe User", "role": "VIEWER", "password": STRONG})
    assert dup.status_code == 409


def test_role_change_is_audited(admin):
    user = _new_user(admin)
    r = admin.patch(f"/api/v1/users/{user['id']}", json={"role": "SECURITY_ANALYST"})
    assert r.json()["role"] == "SECURITY_ANALYST"
    events = admin.get("/api/v1/audit", params={"action": "user.role_changed"}).json()["items"]
    assert any(e["resource_id"] == str(user["id"]) and e["details"]["role"]["to"] == "SECURITY_ANALYST" for e in events)


def test_deactivation_revokes_sessions(admin, api):
    user = _new_user(admin)
    client, login = _login(api, user["email"])
    client.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    assert client.get("/api/v1/auth/me").status_code == 200
    admin.patch(f"/api/v1/users/{user['id']}", json={"is_active": False})
    assert client.get("/api/v1/auth/me").status_code == 401
    _, again = _login(api, user["email"])
    assert again.status_code == 401


def test_admin_cannot_demote_or_disable_self(admin):
    me = admin.get("/api/v1/auth/me").json()["user"]
    assert admin.patch(f"/api/v1/users/{me['id']}", json={"role": "VIEWER"}).status_code in (400, 403, 409)
    assert admin.patch(f"/api/v1/users/{me['id']}", json={"is_active": False}).status_code in (400, 403, 409)


def test_change_password_signs_out_other_sessions(admin, api):
    user = _new_user(admin)
    first, login1 = _login(api, user["email"])
    first.headers["X-CSRF-Token"] = login1.json()["csrf_token"]
    second, login2 = _login(api, user["email"])
    second.headers["X-CSRF-Token"] = login2.json()["csrf_token"]
    wrong = first.post("/api/v1/auth/change-password", json={"current_password": "nope-nope-nope", "new_password": "Another-Strong-Pass-1"})
    assert wrong.status_code in (400, 401, 422)
    ok = first.post("/api/v1/auth/change-password", json={"current_password": STRONG, "new_password": "Another-Strong-Pass-1"})
    assert ok.status_code == 200
    assert second.get("/api/v1/auth/me").status_code == 401
    assert first.get("/api/v1/auth/me").status_code == 200
    _, relogin = _login(api, user["email"], "Another-Strong-Pass-1")
    assert relogin.status_code == 200


def test_settings_validation_and_audit(admin):
    current = admin.get("/api/v1/settings").json()
    bad = admin.patch("/api/v1/settings", json={"thresholds": {"stale_credential_days": 5}})
    assert bad.status_code == 422
    unknown = admin.patch("/api/v1/settings", json={"thresholds": {"made_up": 30}})
    assert unknown.status_code == 422
    ok = admin.patch("/api/v1/settings", json={"thresholds": {"stale_credential_days": 120}, "notify_on_critical": False})
    assert ok.status_code == 200
    assert ok.json()["thresholds"]["stale_credential_days"] == 120
    admin.patch("/api/v1/settings", json={"thresholds": current["thresholds"], "notify_on_critical": current["notify_on_critical"]})
    assert admin.get("/api/v1/audit", params={"action": "settings.modified"}).json()["total"] >= 2


def test_disabled_rule_is_skipped_by_next_scan(admin, demo_account, database):
    assert admin.patch("/api/v1/rules/S3-005", json={"enabled": False}).json()["enabled"] is False
    try:
        database.overrides["maturity"] = 0.6
        scan = admin.post("/api/v1/scans", json={"account_id": demo_account["id"], "services": ["S3"]}).json()
        database.overrides.pop("maturity")
        from sqlalchemy import select

        from app.core.database import SessionLocal
        from app.models import ScanResult

        with SessionLocal() as db:
            evaluated = set(db.scalars(select(ScanResult.rule_id).where(ScanResult.scan_id == scan["id"])).all())
        assert "S3-005" not in evaluated and "S3-004" in evaluated
    finally:
        admin.patch("/api/v1/rules/S3-005", json={"enabled": True})


def test_audit_log_filters(admin):
    logins = admin.get("/api/v1/audit", params={"action": "auth.login", "result": "success", "page_size": 5}).json()
    assert logins["items"] and all(e["action"] == "auth.login" and e["result"] == "success" for e in logins["items"])
    entry = logins["items"][0]
    assert entry["timestamp"] and entry["user_email"] and entry["ip_address"]
    by_user = admin.get("/api/v1/audit", params={"user": "admin@cloudaegis.local", "page_size": 5}).json()
    assert all(e["user_email"] == "admin@cloudaegis.local" for e in by_user["items"])
    facets = admin.get("/api/v1/audit/facets").json()
    assert "auth.login" in facets["actions"]


def test_notifications_can_be_marked_read(admin, demo_account):
    data = admin.get("/api/v1/notifications").json()
    assert "items" in data and "unread" in data
    assert admin.post("/api/v1/notifications/read", json={"ids": None}).status_code == 200
    assert admin.get("/api/v1/notifications").json()["unread"] == 0
