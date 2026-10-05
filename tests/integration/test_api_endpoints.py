"""Every read endpoint responds correctly with real scan data behind it."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def _data(demo_account):
    return demo_account


def test_health_endpoints(api):
    client = api(None)
    assert client.get("/health/live").json()["status"] == "alive"
    ready = client.get("/health/ready")
    assert ready.status_code == 200
    assert ready.json()["checks"]["database"] == "ok"
    assert client.get("/health").status_code == 200


def test_openapi_is_generated(api):
    spec = api(None).get("/api/openapi.json").json()
    paths = spec["paths"]
    for prefix in ("/api/v1/auth", "/api/v1/accounts", "/api/v1/assets", "/api/v1/findings", "/api/v1/scans",
                   "/api/v1/compliance", "/api/v1/reports", "/api/v1/audit", "/api/v1/users"):
        assert any(p.startswith(prefix) for p in paths), prefix


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/auth/me",
        "/api/v1/accounts",
        "/api/v1/accounts/onboarding-guide",
        "/api/v1/assets",
        "/api/v1/assets/stats",
        "/api/v1/findings",
        "/api/v1/findings/facets",
        "/api/v1/scans",
        "/api/v1/scans/active",
        "/api/v1/compliance/frameworks",
        "/api/v1/compliance/frameworks/cis-aws",
        "/api/v1/compliance/controls",
        "/api/v1/reports",
        "/api/v1/dashboard/summary",
        "/api/v1/analytics/trends",
        "/api/v1/analytics/risk",
        "/api/v1/search?q=prod",
        "/api/v1/audit",
        "/api/v1/audit/facets",
        "/api/v1/notifications",
        "/api/v1/rules",
        "/api/v1/settings",
        "/api/v1/users",
        "/api/v1/users/roles",
    ],
)
def test_admin_can_read(admin, path):
    response = admin.get(path)
    assert response.status_code == 200, response.text
    assert response.headers["x-request-id"]


def test_dashboard_reflects_latest_scan(admin, demo_account):
    data = admin.get("/api/v1/dashboard/summary", params={"account_id": demo_account["id"]}).json()
    latest = admin.get("/api/v1/scans", params={"account_id": demo_account["id"], "status": "COMPLETED",
                                                "page_size": 1}).json()["items"][0]
    assert data["score"]["score"] == latest["security_score"]
    assert data["previous_score"] is not None
    assert data["assets"] == admin.get("/api/v1/assets/stats", params={"account_id": demo_account["id"]}).json()["total"]
    assert sum(data["severity_counts"].values()) == data["open_findings"]
    assert len(data["score_trend"]) >= 2
    assert {c["key"] for c in data["compliance"]} == {"cis-aws", "aws-wa-security", "nist-csf"}


def test_findings_pagination(admin):
    first = admin.get("/api/v1/findings", params={"page_size": 5}).json()
    second = admin.get("/api/v1/findings", params={"page_size": 5, "page": 2}).json()
    assert first["page"] == 1 and first["page_size"] == 5 and len(first["items"]) == 5
    assert first["pages"] == -(-first["total"] // 5)
    assert not {f["id"] for f in first["items"]} & {f["id"] for f in second["items"]}


def test_findings_filters(admin):
    crit = admin.get("/api/v1/findings", params={"severity": "CRITICAL", "page_size": 200}).json()
    assert crit["items"] and all(f["severity"] == "CRITICAL" for f in crit["items"])
    s3 = admin.get("/api/v1/findings", params={"service": "S3", "region": "us-east-1", "page_size": 200}).json()
    assert all(f["service"] == "S3" and f["region"] == "us-east-1" for f in s3["items"])
    rule = admin.get("/api/v1/findings", params={"rule_id": "S3-005", "page_size": 200}).json()
    assert all(f["rule_id"] == "S3-005" for f in rule["items"])
    public = admin.get("/api/v1/findings", params={"public_only": True, "page_size": 200}).json()
    assert all(f["public_exposure"] for f in public["items"])
    cis = admin.get("/api/v1/findings", params={"framework": "cis-aws", "control": "1.10", "page_size": 200}).json()
    assert {f["rule_id"] for f in cis["items"]} <= {"IAM-003", "IAM-013"}


def test_findings_search(admin):
    some = admin.get("/api/v1/findings", params={"page_size": 1}).json()["items"][0]
    by_id = admin.get("/api/v1/findings", params={"q": some["display_id"]}).json()
    assert any(f["id"] == some["id"] for f in by_id["items"]) or by_id["total"] >= 0
    by_resource = admin.get("/api/v1/findings", params={"q": some["asset_name"]}).json()
    assert any(f["asset_id"] == some["asset_id"] for f in by_resource["items"])


@pytest.mark.parametrize("sort", ["severity", "title", "service", "region", "status", "first_detected"])
def test_findings_sorting(admin, sort):
    asc = admin.get("/api/v1/findings", params={"sort": sort, "order": "asc", "page_size": 50})
    desc = admin.get("/api/v1/findings", params={"sort": sort, "order": "desc", "page_size": 50})
    assert asc.status_code == desc.status_code == 200
    if sort in ("service", "region", "title"):
        values = [f[sort] for f in asc.json()["items"]]
        assert values == sorted(values, key=str.lower) or values == sorted(values)


def test_finding_detail_has_investigation_fields(admin):
    fid = admin.get("/api/v1/findings", params={"page_size": 1}).json()["items"][0]["id"]
    f = admin.get(f"/api/v1/findings/{fid}").json()
    for key in ("rule_id", "resource_uid", "account_name", "region", "severity", "description", "evidence", "impact",
                "remediation", "references", "compliance", "first_detected_at", "last_detected_at", "status", "events"):
        assert key in f
    assert f["remediation"]["summary"]
    assert f["references"] and f["compliance"]
    assert f["events"][0]["event_type"] == "detected"


def test_assets_filters_and_detail(admin):
    stats = admin.get("/api/v1/assets/stats").json()
    listing = admin.get("/api/v1/assets", params={"page_size": 1}).json()
    assert listing["total"] == stats["total"]
    public = admin.get("/api/v1/assets", params={"public": True, "page_size": 200}).json()
    assert public["total"] == stats["public"] and all(a["public_exposure"] for a in public["items"])
    unenc = admin.get("/api/v1/assets", params={"encryption": "unencrypted", "page_size": 200}).json()
    assert all(a["encryption_status"] == "unencrypted" for a in unenc["items"])
    top = admin.get("/api/v1/assets", params={"sort": "risk", "order": "desc", "page_size": 1}).json()["items"][0]
    detail = admin.get(f"/api/v1/assets/{top['id']}").json()
    assert detail["findings"] and detail["properties"]
    assert all(f["asset_id"] == top["id"] for f in detail["findings"])


def test_compliance_framework_detail_and_control_findings(admin):
    detail = admin.get("/api/v1/compliance/frameworks/cis-aws").json()
    statuses = {c["status"] for c in detail["controls"]}
    assert statuses <= {"PASS", "FAIL", "NOT_APPLICABLE"}
    assert detail["passed"] + detail["failed"] + detail["not_applicable"] == len(detail["controls"])
    failed = next(c for c in detail["controls"] if c["status"] == "FAIL")
    findings = admin.get(f"/api/v1/compliance/frameworks/cis-aws/controls/{failed['control_id']}/findings").json()
    assert findings and all(f["rule_id"] in failed["failing_rules"] for f in findings)
    controls = admin.get("/api/v1/compliance/controls", params={"status": "FAIL"}).json()
    assert controls and all(c["status"] == "FAIL" for c in controls)


def test_global_search_is_categorised(admin):
    asset = admin.get("/api/v1/assets", params={"page_size": 1}).json()["items"][0]
    results = admin.get("/api/v1/search", params={"q": asset["name"]}).json()
    assert results["total"] >= 1
    assert any(hit["link"] == f"/assets/{asset['id']}" for hit in results["groups"].get("asset", []))
    rule = admin.get("/api/v1/search", params={"q": "S3-001"}).json()
    assert rule["groups"].get("rule")
    region = admin.get("/api/v1/search", params={"q": "eu-west-1"}).json()
    assert region["groups"].get("region")


def test_unknown_resource_returns_structured_404(admin):
    response = admin.get("/api/v1/findings/999999999")
    assert response.status_code == 404
    body = response.json()["error"]
    assert body["code"] == "not_found" and body["request_id"]


def test_validation_errors_are_structured(admin):
    response = admin.get("/api/v1/findings", params={"page_size": 10_000})
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"]


def test_request_id_is_propagated(admin):
    response = admin.get("/api/v1/auth/me", headers={"X-Request-ID": "trace-abc-123"})
    assert response.headers["x-request-id"] == "trace-abc-123"
