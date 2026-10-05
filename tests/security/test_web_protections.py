"""CSRF, secure headers, CORS, error handling without leaks, and rate limiting."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


def test_state_changing_requests_require_csrf_token(api, demo_account):
    client = api("ADMIN")
    token = client.headers.pop("X-CSRF-Token")
    finding = client.get("/api/v1/findings", params={"page_size": 1}).json()["items"][0]["id"]
    missing = client.post(f"/api/v1/findings/{finding}/comments", json={"note": "csrf"})
    assert missing.status_code == 403 and missing.json()["error"]["code"] == "csrf_failed"
    wrong = client.post(f"/api/v1/findings/{finding}/comments", json={"note": "csrf"}, headers={"X-CSRF-Token": "forged"})
    assert wrong.status_code == 403
    ok = client.post(f"/api/v1/findings/{finding}/comments", json={"note": "csrf"}, headers={"X-CSRF-Token": token})
    assert ok.status_code == 200


def test_csrf_token_is_bound_to_the_session(api):
    a, b = api("ADMIN"), api("SECURITY_ANALYST")
    stolen = a.headers["X-CSRF-Token"]
    r = b.post("/api/v1/notifications/read", json={"ids": None}, headers={"X-CSRF-Token": stolen})
    assert r.status_code == 403


def test_security_headers(api):
    r = api("VIEWER").get("/api/v1/auth/me")
    h = r.headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["cache-control"] == "no-store"
    assert r.headers["content-type"].startswith("application/json")


def test_cors_only_allows_configured_origins(api):
    client = api(None)
    allowed = client.options("/api/v1/auth/login", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert allowed.headers.get("access-control-allow-origin") == "http://localhost:5173"
    evil = client.options("/api/v1/auth/login", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert evil.headers.get("access-control-allow-origin") is None


def test_unhandled_errors_do_not_leak_internals(admin, monkeypatch):
    from app.services import dashboard

    def boom(*args, **kwargs):
        raise RuntimeError("psycopg2 connection string postgresql://cloudaegis:secret@db/x")

    monkeypatch.setattr(dashboard, "summary", boom)
    r = admin.get("/api/v1/dashboard/summary")
    assert r.status_code == 500
    body = r.text
    assert "secret" not in body and "Traceback" not in body and "RuntimeError" not in body
    error = r.json()["error"]
    assert error["code"] == "internal_error" and error["request_id"] == r.headers["x-request-id"]


def test_login_rate_limit(api, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setattr(get_settings(), "login_rate_limit_per_minute", 3)
    client = api(None)
    codes = [client.post("/api/v1/auth/login", json={"email": "brute@example.com", "password": "x"}).status_code
             for _ in range(5)]
    assert codes[:3] == [401, 401, 401]
    assert codes[3] == 429
    blocked = client.post("/api/v1/auth/login", json={"email": "brute@example.com", "password": "x"})
    assert int(blocked.headers["retry-after"]) > 0
    assert blocked.json()["error"]["code"] == "rate_limited"


def test_api_rate_limit(api, monkeypatch):
    from app.core.config import get_settings

    client = api("VIEWER")
    monkeypatch.setattr(get_settings(), "api_rate_limit_per_minute", 5)
    from app.core.rate_limit import get_rate_limiter

    get_rate_limiter().reset()
    codes = [client.get("/api/v1/auth/me").status_code for _ in range(7)]
    assert 429 in codes and codes[0] == 200
