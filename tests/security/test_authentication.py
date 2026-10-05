"""Authentication: password storage, generic errors, lockout, cookies, session revocation and expiry."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.security
STRONG = "Correct-Horse-Battery-9"


@pytest.fixture
def user(admin):
    email = f"sec-{uuid.uuid4().hex[:8]}@example.com"
    r = admin.post("/api/v1/users", json={"email": email, "full_name": "Security Test", "role": "VIEWER", "password": STRONG})
    assert r.status_code == 201
    return r.json()


def _login(client, email, password):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def test_passwords_are_hashed_with_argon2(user):
    from sqlalchemy import select

    from app.core.database import SessionLocal
    from app.models import User

    with SessionLocal() as db:
        stored = db.scalar(select(User.password_hash).where(User.id == user["id"]))
    assert stored.startswith("$argon2id$")
    assert STRONG not in stored


def test_unknown_user_and_wrong_password_are_indistinguishable(api, user):
    client = api(None)
    unknown = _login(client, "nobody@example.com", STRONG)
    wrong = _login(client, user["email"], "Wrong-Password-123")
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json()["error"]["message"] == wrong.json()["error"]["message"]


def test_lockout_after_repeated_failures(api, admin, user):
    from app.core.config import get_settings

    client = api(None)
    for _ in range(get_settings().lockout_threshold):
        assert _login(client, user["email"], "Wrong-Password-123").status_code == 401
    locked = _login(client, user["email"], STRONG)
    assert locked.status_code in (401, 423)
    assert "locked" in locked.json()["error"]["message"].lower()
    listed = next(u for u in admin.get("/api/v1/users").json() if u["id"] == user["id"])
    assert listed["locked"] is True
    assert admin.post(f"/api/v1/users/{user['id']}/unlock").status_code == 200
    assert _login(client, user["email"], STRONG).status_code == 200
    denied = admin.get("/api/v1/audit", params={"user": user["email"], "result": "denied"}).json()["items"]
    assert any(e["details"].get("reason") == "account_locked" for e in denied)


def test_session_cookie_flags(api, user):
    client = api(None)
    r = _login(client, user["email"], STRONG)
    cookies = r.headers.get_list("set-cookie")
    session = next(c for c in cookies if c.startswith("ca_session="))
    csrf = next(c for c in cookies if c.startswith("ca_csrf="))
    assert "HttpOnly" in session and "SameSite=strict" in session.replace("Strict", "strict")
    assert "HttpOnly" not in csrf, "the CSRF cookie must be readable by the SPA"
    assert "Path=/" in session
    assert r.json()["csrf_token"]
    assert "token" not in {k.lower() for k in r.json()["user"]}


def test_logout_revokes_the_token(api, user):
    client = api(None)
    r = _login(client, user["email"], STRONG)
    token = client.cookies.get("ca_session")
    client.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    assert client.post("/api/v1/auth/logout").status_code == 200
    replay = api(None)
    replay.cookies.set("ca_session", token)
    assert replay.get("/api/v1/auth/me").status_code == 401


@pytest.mark.parametrize("token", ["", "garbage", "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.", "a.b.c"])
def test_malformed_or_unsigned_tokens_are_rejected(api, token):
    client = api(None)
    client.cookies.set("ca_session", token)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_token_signed_with_other_key_is_rejected(api, user):
    import jwt

    forged = jwt.encode({"sub": str(user["id"]), "jti": "x" * 32, "role": "ADMIN",
                         "exp": datetime.now(timezone.utc) + timedelta(hours=1)}, "attacker-key-" + "0" * 32, algorithm="HS256")
    client = api(None)
    client.cookies.set("ca_session", forged)
    assert client.get("/api/v1/auth/me").status_code == 401


def test_idle_sessions_expire(api, user):
    from sqlalchemy import update

    from app.core.config import get_settings
    from app.core.database import SessionLocal
    from app.models import UserSession

    client = api(None)
    _login(client, user["email"], STRONG)
    assert client.get("/api/v1/auth/me").status_code == 200
    stale = datetime.now(timezone.utc) - timedelta(minutes=get_settings().session_idle_minutes + 1)
    with SessionLocal() as db:
        db.execute(update(UserSession).where(UserSession.user_id == user["id"]).values(last_seen_at=stale))
        db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_absolute_expiry_is_enforced(api, user):
    from sqlalchemy import update

    from app.core.database import SessionLocal
    from app.models import UserSession

    client = api(None)
    _login(client, user["email"], STRONG)
    with SessionLocal() as db:
        db.execute(update(UserSession).where(UserSession.user_id == user["id"])
                   .values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
        db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_role_change_forces_reauthentication(api, admin, user):
    client = api(None)
    _login(client, user["email"], STRONG)
    admin.patch(f"/api/v1/users/{user['id']}", json={"role": "SECURITY_ANALYST"})
    assert client.get("/api/v1/auth/me").status_code == 401


def test_login_is_audited_with_ip(admin, api, user):
    _login(api(None), user["email"], STRONG)
    events = admin.get("/api/v1/audit", params={"user": user["email"], "action": "auth.login"}).json()["items"]
    assert events and events[0]["ip_address"] and events[0]["result"] == "success"
