"""Input validation, injection resistance and safe output handling."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.security

SQLI = ["' OR '1'='1", "1; DROP TABLE findings; --", "\" OR 1=1 --", "%' UNION SELECT password_hash FROM users --"]


@pytest.mark.parametrize("payload", SQLI)
def test_search_parameters_are_not_injectable(admin, demo_account, payload):
    total = admin.get("/api/v1/findings", params={"page_size": 1}).json()["total"]
    for path in ("/api/v1/findings", "/api/v1/assets", "/api/v1/audit"):
        r = admin.get(path, params={"q": payload})
        assert r.status_code == 200
        assert r.json()["total"] < max(total, 1) or r.json()["total"] == 0
    assert admin.get("/api/v1/search", params={"q": payload}).status_code == 200
    assert "argon2" not in admin.get("/api/v1/search", params={"q": payload}).text
    assert admin.get("/api/v1/findings", params={"page_size": 1}).json()["total"] == total


@pytest.mark.parametrize("sort", ["severity; DROP TABLE x", "id desc", "password_hash"])
def test_sort_fields_are_allow_listed(admin, sort):
    assert admin.get("/api/v1/findings", params={"sort": sort}).status_code == 422
    assert admin.get("/api/v1/assets", params={"sort": sort}).status_code == 422


def test_stored_xss_is_returned_as_inert_json(admin, demo_account):
    payload = '<img src=x onerror="alert(document.cookie)"><script>alert(1)</script>'
    fid = admin.get("/api/v1/findings", params={"page_size": 1}).json()["items"][0]["id"]
    admin.post(f"/api/v1/findings/{fid}/comments", json={"note": payload})
    r = admin.get(f"/api/v1/findings/{fid}")
    assert r.headers["content-type"].startswith("application/json")
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert any(e["note"] == payload for e in r.json()["events"]), "content is stored verbatim and rendered as text by the UI"


@pytest.mark.parametrize(
    "path,body",
    [
        ("/api/v1/auth/login", {"email": "not-an-email", "password": "x"}),
        ("/api/v1/auth/login", {"email": "a@b.co", "password": "x" * 500}),
        ("/api/v1/accounts", {"name": "<script>", "credentials": {"method": "assume_role", "role_arn": "arn:aws:iam::123456789012:role/x"}}),
        ("/api/v1/accounts", {"name": "ok name", "credentials": {"method": "access_keys"}}),
        ("/api/v1/scans", {"account_id": "1; drop"}),
        ("/api/v1/reports", {"title": "x" * 500, "format": "pdf"}),
        ("/api/v1/findings/bulk-status", {"finding_ids": [], "status": "RESOLVED"}),
    ],
)
def test_invalid_payloads_are_rejected(api, path, body):
    client = api("ADMIN") if path != "/api/v1/auth/login" else api(None)
    r = client.post(path, json=body)
    assert r.status_code == 422, r.text
    assert r.json()["error"]["code"] == "validation_error"


def test_oversized_comment_rejected(admin, demo_account):
    fid = admin.get("/api/v1/findings", params={"page_size": 1}).json()["items"][0]["id"]
    assert admin.post(f"/api/v1/findings/{fid}/comments", json={"note": "x" * 10_001}).status_code == 422


def test_non_numeric_ids_rejected(admin):
    assert admin.get("/api/v1/findings/abc").status_code == 422
    assert admin.get("/api/v1/assets/1%20OR%201=1").status_code == 422


def test_csv_cell_sanitiser():
    from app.services.reports.exporters import _csv_safe

    for dangerous in ("=HYPERLINK(\"http://evil\")", "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\t=1"):
        assert _csv_safe(dangerous).startswith("'"), dangerous
    assert _csv_safe("prod-bucket") == "prod-bucket"
    assert _csv_safe(None) == ""
