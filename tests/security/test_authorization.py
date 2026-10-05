"""Authorization: every API route requires a session, and RBAC is enforced server-side per role."""

from __future__ import annotations

import re

import pytest

pytestmark = pytest.mark.security

PUBLIC = {("POST", "/api/v1/auth/login"), ("GET", "/api/v1/auth/demo-info")}


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "1", path)


def test_every_api_route_requires_authentication(api):
    client = api(None)
    checked = 0
    for path, operations in client.get("/api/openapi.json").json()["paths"].items():
        if not path.startswith("/api/v1/"):
            continue
        for method in (m.upper() for m in operations):
            if (method, path) in PUBLIC:
                continue
            response = client.request(method, _concrete(path), json={})
            assert response.status_code == 401, f"{method} {path} -> {response.status_code}"
            checked += 1
    assert checked > 40


# (method, path, body) and the roles allowed to perform it.
ACTIONS = [
    ("POST", "/api/v1/scans", {"account_id": "{account}"}, {"ADMIN", "SECURITY_ANALYST"}),
    ("PATCH", "/api/v1/findings/{finding}/status", {"status": "ACKNOWLEDGED"}, {"ADMIN", "SECURITY_ANALYST"}),
    ("POST", "/api/v1/findings/{finding}/comments", {"note": "rbac check"}, {"ADMIN", "SECURITY_ANALYST"}),
    ("POST", "/api/v1/reports", {"title": "RBAC report", "format": "json"}, {"ADMIN", "SECURITY_ANALYST"}),
    ("POST", "/api/v1/accounts/demo", {"name": "Second demo"}, {"ADMIN"}),
    ("PATCH", "/api/v1/accounts/{account}", {"name": "Renamed demo"}, {"ADMIN"}),
    ("GET", "/api/v1/accounts/onboarding-guide", None, {"ADMIN"}),
    ("POST", "/api/v1/users", {"email": "x@example.com", "full_name": "X Y", "role": "VIEWER", "password": "Correct-Horse-9-a"}, {"ADMIN"}),
    ("GET", "/api/v1/users", None, {"ADMIN"}),
    ("PATCH", "/api/v1/settings", {"notify_on_critical": True}, {"ADMIN"}),
    ("PATCH", "/api/v1/rules/S3-001", {"enabled": True}, {"ADMIN"}),
    ("GET", "/api/v1/audit", None, {"ADMIN"}),
    ("GET", "/api/v1/findings", None, {"ADMIN", "SECURITY_ANALYST", "VIEWER"}),
    ("GET", "/api/v1/reports", None, {"ADMIN", "SECURITY_ANALYST", "VIEWER"}),
    ("GET", "/api/v1/compliance/frameworks", None, {"ADMIN", "SECURITY_ANALYST", "VIEWER"}),
]


@pytest.mark.parametrize("role", ["ADMIN", "SECURITY_ANALYST", "VIEWER"])
@pytest.mark.parametrize("method,path,body,allowed", ACTIONS, ids=[f"{m} {p}" for m, p, _, _ in ACTIONS])
def test_rbac_matrix(api, demo_account, role, method, path, body, allowed, database):
    client = api(role)
    finding = client.get("/api/v1/findings", params={"page_size": 1}).json()["items"][0]["id"]
    fill = {"account": demo_account["id"], "finding": finding}
    path = path.format(**fill)
    if body:
        body = {k: (fill["account"] if v == "{account}" else v) for k, v in body.items()}
    response = client.request(method, path, json=body)
    if role in allowed:
        assert response.status_code != 403, f"{role} should be allowed: {response.text}"
    else:
        assert response.status_code == 403, f"{role} must be denied {method} {path}: {response.status_code}"
        assert response.json()["error"]["code"] == "forbidden"


def test_denied_access_is_audited(api, admin):
    api("VIEWER").get("/api/v1/users")
    denied = admin.get("/api/v1/audit", params={"action": "access.denied", "user": "viewer@cloudaegis.local"}).json()
    assert denied["total"] >= 1
    assert denied["items"][0]["result"] == "denied"


def test_viewer_permissions_are_read_only(api):
    perms = set(api("VIEWER").get("/api/v1/auth/me").json()["user"]["permissions"])
    assert perms and all(p.endswith(":read") for p in perms)
