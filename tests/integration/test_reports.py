"""Report generation and export (PDF, JSON, CSV)."""

from __future__ import annotations

import csv
import hashlib
import io
import json

import pytest

pytestmark = pytest.mark.integration


def _generate(client, fmt, report_type="executive", **extra):
    r = client.post("/api/v1/reports", json={"title": f"Test {fmt} report", "format": fmt, "report_type": report_type, **extra})
    assert r.status_code in (200, 201), r.text
    report = r.json()
    download = client.get(f"/api/v1/reports/{report['id']}/download")
    assert download.status_code == 200
    return report, download


def test_pdf_report(admin, demo_account):
    report, download = _generate(admin, "pdf", "technical")
    assert download.content.startswith(b"%PDF")
    assert download.headers["content-type"] == "application/pdf"
    assert "attachment" in download.headers["content-disposition"]
    assert report["sha256"] == hashlib.sha256(download.content).hexdigest()
    assert report["size_bytes"] == len(download.content)


def test_json_report_contents(admin, demo_account):
    _, download = _generate(admin, "json", "technical", account_id=demo_account["id"])
    data = json.loads(download.content)
    text = json.dumps(data).lower()
    for section in ("executive", "score", "findings", "compliance", "assets", "recommend", "scan"):
        assert section in text, section
    assert data["simulated"] is True
    assert data["findings_included"] == len(data["findings"]) <= data["findings_total_open"]
    assert all({"evidence", "remediation", "compliance", "resource"} <= set(f) for f in data["findings"])


def test_csv_report_is_one_row_per_finding(admin, demo_account):
    _, download = _generate(admin, "csv", "technical", account_id=demo_account["id"])
    rows = list(csv.DictReader(io.StringIO(download.content.decode("utf-8-sig"))))
    assert rows
    header = {h.lower() for h in rows[0]}
    assert {"severity", "rule_id"} <= {h.replace(" ", "_") for h in header}
    open_total = admin.get("/api/v1/findings", params={
        "account_id": demo_account["id"], "page_size": 1, "status": ["OPEN", "ACKNOWLEDGED", "IN_PROGRESS"]}).json()["total"]
    assert len(rows) == open_total


def test_csv_neutralises_formula_injection(admin, demo_account):
    """Cells that a spreadsheet would execute (=, +, -, @) must be escaped."""
    _, download = _generate(admin, "csv", "technical")
    for row in csv.reader(io.StringIO(download.content.decode("utf-8-sig"))):
        for cell in row:
            assert not cell.startswith(("=", "+", "@")) or cell.startswith("'"), cell


def test_reports_are_listed_and_deletable(admin, demo_account):
    report, _ = _generate(admin, "json")
    assert any(r["id"] == report["id"] for r in admin.get("/api/v1/reports").json())
    assert admin.delete(f"/api/v1/reports/{report['id']}").status_code == 200
    assert admin.get(f"/api/v1/reports/{report['id']}/download").status_code == 404
    actions = {a["action"] for a in admin.get("/api/v1/audit", params={"action": "report.generated"}).json()["items"]}
    assert actions == {"report.generated"}


def test_report_validation(admin):
    assert admin.post("/api/v1/reports", json={"title": "x", "format": "pdf"}).status_code == 422
    assert admin.post("/api/v1/reports", json={"title": "Valid title", "format": "docx"}).status_code == 422
