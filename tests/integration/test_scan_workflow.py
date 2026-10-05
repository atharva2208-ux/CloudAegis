"""Scan lifecycle through the API: queue → discover → evaluate → score → persist → compare."""

from __future__ import annotations

import threading
import time

import pytest

pytestmark = pytest.mark.integration


def test_seeded_scans_completed(admin, demo_account):
    for scan_id in demo_account["scans"]:
        scan = admin.get(f"/api/v1/scans/{scan_id}").json()
        assert scan["status"] == "COMPLETED"
        assert scan["assets_discovered"] > 0
        assert scan["checks_evaluated"] >= scan["findings_total"] > 0
        assert 0 <= scan["security_score"] <= 100
        assert scan["score_breakdown"]["score"] == scan["security_score"]
        assert {s["status"] for s in scan["progress"]["services"]} == {"completed"}
        assert scan["progress"]["assets_analyzed"] == scan["assets_discovered"]
        assert len(scan["compliance_summary"]) == 3
        assert scan["duration_seconds"] is not None


def test_more_mature_scan_scores_better(admin, demo_account):
    first, second = (admin.get(f"/api/v1/scans/{i}").json() for i in demo_account["scans"])
    assert second["security_score"] > first["security_score"]
    assert second["findings_total"] < first["findings_total"]
    assert second["findings_resolved"] > 0


def test_compare_scans(admin, demo_account):
    base, target = demo_account["scans"]
    data = admin.get("/api/v1/scans/compare", params={"base": base, "target": target}).json()
    assert data["score_delta"] == data["target"]["security_score"] - data["base"]["security_score"]
    for sev, delta in data["severity_delta"].items():
        assert delta == data["target"]["severity_counts"][sev] - data["base"]["severity_counts"][sev]
    assert data["resolved_findings"], "remediation between scans should resolve findings"
    assert {c["key"] for c in data["compliance_delta"]} == {"cis-aws", "aws-wa-security", "nist-csf"}


def test_compare_rejects_unknown_scan(admin, demo_account):
    response = admin.get("/api/v1/scans/compare", params={"base": demo_account["scans"][0], "target": 987654})
    assert response.status_code == 404


def test_start_scan_via_api(admin, demo_account, database):
    before = admin.get("/api/v1/findings", params={"page_size": 1, "account_id": demo_account["id"]}).json()["total"]
    database.overrides["maturity"] = 0.6  # same posture as the last scan
    response = admin.post("/api/v1/scans", json={"account_id": demo_account["id"], "regions": ["us-east-1"],
                                                 "services": ["S3", "IAM"]})
    assert response.status_code == 202
    scan = admin.get(f"/api/v1/scans/{response.json()['id']}").json()
    assert scan["status"] == "COMPLETED"
    assert scan["regions"] == ["us-east-1"]
    assert set(scan["services"]) == {"S3", "IAM"}
    assert {s["service"] for s in scan["progress"]["services"]} == {"S3", "IAM"}
    # A partial-scope scan must not auto-resolve findings for services or regions it did not look at.
    after = admin.get("/api/v1/findings", params={"page_size": 1, "account_id": demo_account["id"]}).json()["total"]
    assert after >= before - scan["findings_resolved"]
    ec2_open = admin.get("/api/v1/findings", params={"service": "EC2", "page_size": 1}).json()["total"]
    assert ec2_open > 0
    database.overrides.pop("maturity", None)


def test_scan_validation(admin, demo_account):
    bad_region = admin.post("/api/v1/scans", json={"account_id": demo_account["id"], "regions": ["mars-north-1"]})
    assert bad_region.status_code in (400, 422)
    bad_service = admin.post("/api/v1/scans", json={"account_id": demo_account["id"], "services": ["NotAService"]})
    assert bad_service.status_code in (400, 422)
    missing = admin.post("/api/v1/scans", json={"account_id": 424242})
    assert missing.status_code == 404


def test_concurrent_scan_for_same_account_is_rejected(admin, demo_account, database):
    from app.core.database import SessionLocal
    from app.models import Scan
    from app.services.context import SYSTEM
    from app.services.scans import create_scan

    with SessionLocal() as db:
        queued = create_scan(db, demo_account["id"], SYSTEM)  # sits in QUEUED (never enqueued)
    try:
        response = admin.post("/api/v1/scans", json={"account_id": demo_account["id"]})
        assert response.status_code == 409
        active = admin.get("/api/v1/scans/active").json()
        assert any(s["id"] == queued.id for s in active)
        cancelled = admin.post(f"/api/v1/scans/{queued.id}/cancel")
        assert cancelled.status_code == 200
        assert cancelled.json()["status"] == "CANCELLED"
    finally:
        with SessionLocal() as db:
            scan = db.get(Scan, queued.id)
            if scan.status in ("QUEUED", "RUNNING"):
                scan.status = "CANCELLED"
                db.commit()


def test_inprocess_queue_runs_scans_off_the_request_thread(demo_account):
    """The in-process executor must not block the caller (the web server stays responsive)."""
    from app.core.database import SessionLocal
    from app.models import Scan
    from app.services.context import SYSTEM
    from app.services.scans import create_scan
    from app.workers.queue import InProcessQueue
    from app.workers import scan_job

    started = threading.Event()
    release = threading.Event()
    original = scan_job.run_scan

    def slow_run(scan_id: int) -> None:
        started.set()
        release.wait(5)
        with SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            scan.status = "CANCELLED"
            db.commit()

    with SessionLocal() as db:
        scan = create_scan(db, demo_account["id"], SYSTEM)
    scan_job.run_scan = slow_run
    try:
        queue = InProcessQueue(workers=1)
        t0 = time.monotonic()
        queue.enqueue(scan.id)
        assert time.monotonic() - t0 < 0.5, "enqueue must return immediately"
        assert started.wait(5), "scan should start on a worker thread"
    finally:
        release.set()
        scan_job.run_scan = original
    for _ in range(50):
        with SessionLocal() as db:
            if db.get(Scan, scan.id).status == "CANCELLED":
                break
        time.sleep(0.1)


def test_scan_history_filters(admin, demo_account):
    listing = admin.get("/api/v1/scans", params={"account_id": demo_account["id"], "status": "COMPLETED"}).json()
    assert listing["total"] >= 2
    assert all(s["status"] == "COMPLETED" for s in listing["items"])
    dates = [s["queued_at"] for s in listing["items"]]
    assert dates == sorted(dates, reverse=True)


def test_assets_are_upserted_not_duplicated(admin, demo_account):
    from sqlalchemy import func, select

    from app.core.database import SessionLocal
    from app.models import Asset

    with SessionLocal() as db:
        dupes = db.execute(select(Asset.resource_uid).where(Asset.cloud_account_id == demo_account["id"])
                           .group_by(Asset.resource_uid).having(func.count() > 1)).all()
    assert dupes == []
