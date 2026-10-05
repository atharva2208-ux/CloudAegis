"""Finding lifecycle: triage transitions, suppression, tickets, and scan-driven reopen/resolve."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def _open_finding(client, **params):
    params = {"status": "OPEN", "page_size": 1, **params}
    items = client.get("/api/v1/findings", params=params).json()["items"]
    assert items, f"no open finding for {params}"
    return items[0]


def _events(client, fid):
    return client.get(f"/api/v1/findings/{fid}").json()["events"]


def test_triage_transitions_are_recorded(admin, demo_account):
    f = _open_finding(admin, service="S3")
    for status in ("ACKNOWLEDGED", "IN_PROGRESS"):
        r = admin.patch(f"/api/v1/findings/{f['id']}/status", json={"status": status, "note": f"moving to {status}"})
        assert r.status_code == 200 and r.json()["status"] == status
    detail = admin.get(f"/api/v1/findings/{f['id']}").json()
    changes = [e for e in detail["events"] if e["event_type"] == "status_changed"]
    assert [(e["from_status"], e["to_status"]) for e in reversed(changes)][-2:] == [
        ("OPEN", "ACKNOWLEDGED"), ("ACKNOWLEDGED", "IN_PROGRESS")]
    assert changes[0]["user"] == "admin@cloudaegis.local"
    audit = admin.get("/api/v1/audit", params={"q": f["display_id"]}).json()["items"]
    assert {"finding.acknowledged", "finding.in_progress"} <= {a["action"] for a in audit}


def test_suppression_requires_justification_and_leaves_score(admin, demo_account):
    f = _open_finding(admin, service="Lambda")
    missing = admin.patch(f"/api/v1/findings/{f['id']}/status", json={"status": "SUPPRESSED"})
    assert missing.status_code == 422
    assert missing.json()["error"]["details"][0]["field"] == "note"
    ok = admin.patch(f"/api/v1/findings/{f['id']}/status",
                     json={"status": "SUPPRESSED", "note": "Accepted risk per review SR-12"})
    assert ok.status_code == 200
    body = ok.json()
    assert body["status"] == "SUPPRESSED"
    assert body["suppression_reason"] == "Accepted risk per review SR-12"
    default_list = admin.get("/api/v1/findings", params={"q": f["display_id"]}).json()["items"]
    assert all(x["id"] != f["id"] for x in default_list if x["status"] in ("OPEN",))
    reopened = admin.patch(f"/api/v1/findings/{f['id']}/status", json={"status": "OPEN", "note": "re-review"})
    assert reopened.json()["status"] == "OPEN" and reopened.json()["suppression_reason"] is None


def test_invalid_status_is_rejected(admin, demo_account):
    f = _open_finding(admin)
    r = admin.patch(f"/api/v1/findings/{f['id']}/status", json={"status": "DELETED"})
    assert r.status_code == 422


def test_bulk_status_update(admin, demo_account):
    items = admin.get("/api/v1/findings", params={"status": "OPEN", "service": "EC2", "page_size": 3}).json()["items"]
    ids = [f["id"] for f in items]
    r = admin.post("/api/v1/findings/bulk-status", json={"finding_ids": ids, "status": "ACKNOWLEDGED", "note": "batch"})
    assert r.status_code == 200
    for fid in ids:
        assert admin.get(f"/api/v1/findings/{fid}").json()["status"] == "ACKNOWLEDGED"
    missing = admin.post("/api/v1/findings/bulk-status", json={"finding_ids": [ids[0], 99999999], "status": "OPEN"})
    assert missing.status_code == 404
    assert admin.get(f"/api/v1/findings/{ids[0]}").json()["status"] == "ACKNOWLEDGED", "bulk update must be atomic"


def test_comments_and_ticket_linking(admin, demo_account):
    f = _open_finding(admin, service="RDS")
    c = admin.post(f"/api/v1/findings/{f['id']}/comments", json={"note": "Owner is the payments team"})
    assert c.status_code == 200
    draft = admin.get(f"/api/v1/findings/{f['id']}/ticket-draft").json()
    assert f["title"] in draft["title"] and f["asset_name"] in draft["title"]
    assert f["rule_id"] in draft["body"] and f["resource_uid"] in draft["body"]
    linked = admin.post(f"/api/v1/findings/{f['id']}/ticket", json={"ticket_ref": "SEC-4242"}).json()
    assert linked["ticket_ref"] == "SEC-4242"
    assert linked["status"] == "IN_PROGRESS", "linking a ticket moves open work to in progress"
    kinds = [e["event_type"] for e in linked["events"]]
    assert "comment" in kinds and "ticket_linked" in kinds


def test_resolved_finding_reopens_when_detected_again(admin, demo_account, database):
    f = _open_finding(admin, service="S3")
    admin.patch(f"/api/v1/findings/{f['id']}/status", json={"status": "RESOLVED", "note": "fixed, trust me"})
    database.overrides["maturity"] = 0.6  # same estate: the issue is still there
    scan = admin.post("/api/v1/scans", json={"account_id": demo_account["id"], "services": ["S3"]}).json()
    database.overrides.pop("maturity")
    detail = admin.get(f"/api/v1/findings/{f['id']}").json()
    assert detail["status"] == "OPEN"
    reopened = [e for e in detail["events"] if e["event_type"] == "reopened"]
    assert reopened and reopened[0]["scan_id"] == scan["id"]


def test_fixed_issue_is_auto_resolved_with_previous_status(admin, demo_account, database):
    candidates = admin.get("/api/v1/findings", params={"status": "OPEN", "service": "EC2", "page_size": 50}).json()["items"]
    ids = [f["id"] for f in candidates]
    admin.post("/api/v1/findings/bulk-status", json={"finding_ids": ids, "status": "ACKNOWLEDGED"})
    database.overrides["maturity"] = 1.0  # the estate is now largely remediated
    admin.post("/api/v1/scans", json={"account_id": demo_account["id"], "services": ["EC2"]})
    database.overrides.pop("maturity")
    details = [admin.get(f"/api/v1/findings/{i}").json() for i in ids]
    resolved = [d for d in details if d["status"] == "RESOLVED"]
    assert resolved, "a remediated estate should resolve some findings"
    for d in resolved:
        auto = next(e for e in d["events"] if e["event_type"] == "auto_resolved")
        assert auto["from_status"] == "ACKNOWLEDGED"
        assert auto["note"] == "Check passed in latest scan"
        assert d["resolved_at"]


def test_out_of_scope_findings_are_not_auto_resolved(admin, demo_account, database):
    """A scan of one service must not close findings that depend on resources from other services."""
    ct = admin.get("/api/v1/findings", params={"service": "CloudTrail", "status": "OPEN", "page_size": 100}).json()
    lam = admin.get("/api/v1/findings", params={"service": "Lambda", "status": "OPEN", "page_size": 1}).json()["total"]
    database.overrides["maturity"] = 1.0
    admin.post("/api/v1/scans", json={"account_id": demo_account["id"], "services": ["S3"]})
    database.overrides.pop("maturity")
    assert admin.get("/api/v1/findings", params={"service": "Lambda", "status": "OPEN", "page_size": 1}).json()["total"] == lam
    for f in ct["items"]:
        assert admin.get(f"/api/v1/findings/{f['id']}").json()["status"] == "OPEN"
