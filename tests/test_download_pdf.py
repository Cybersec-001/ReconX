"""download_pdf: login gate, report ownership, incomplete data and the PDF response."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")

import pytest

import app as rx

OWNER = "pdf_test_owner"
OTHER = "pdf_test_other"

FULL_REPORT = dict(
    whois_data={"registrar": "Example Registrar"},
    email_validation={"valid_format": True},
    website_title="Example Domain",
    ip_geolocation={"country": "Nowhere"},
    shodan_scan={"ports": [80, 443]},
    subdomains=["www.example.com"],
    wayback_urls=["http://example.com/old"],
)


@pytest.fixture()
def users(monkeypatch):
    monkeypatch.setattr(rx, "scan_reports", {})
    rx.limiter.reset()
    with rx.app.app_context():
        for name in (OWNER, OTHER):
            existing = rx.User.query.filter_by(username=name).first()
            if existing:
                rx.db.session.delete(existing)
        rx.db.session.commit()
        owner, other = rx.User(username=OWNER), rx.User(username=OTHER)
        for user in (owner, other):
            user.set_password("pass1234")
        rx.db.session.add_all([owner, other])
        rx.db.session.commit()
        yield {"owner": owner.id, "other": other.id}
        for name in (OWNER, OTHER):
            leftover = rx.User.query.filter_by(username=name).first()
            if leftover:
                rx.db.session.delete(leftover)
        rx.db.session.commit()


def client_as(user_id, report_id=None):
    rx.app.config["TESTING"] = True
    client = rx.app.test_client()
    with client.session_transaction() as sess:
        if user_id is not None:
            sess["_user_id"] = str(user_id)
        if report_id is not None:
            sess["report_id"] = report_id
    return client


def test_anonymous_visitors_are_sent_to_login(users):
    resp = client_as(None).get("/download_pdf")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_no_report_in_session_redirects_to_workspace(users):
    resp = client_as(users["owner"]).get("/download_pdf")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/workspace")


def test_another_users_report_is_not_downloadable(users):
    rx.scan_reports["r1"] = (users["other"], dict(FULL_REPORT))
    resp = client_as(users["owner"], "r1").get("/download_pdf")
    assert resp.status_code == 302
    assert resp.headers["Content-Type"] != "application/pdf"


def test_incomplete_report_redirects_instead_of_building_a_pdf(users):
    partial = dict(FULL_REPORT, shodan_scan=None)
    rx.scan_reports["r2"] = (users["owner"], partial)
    resp = client_as(users["owner"], "r2").get("/download_pdf")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/workspace")


def test_complete_report_downloads_as_a_pdf_attachment(users):
    rx.scan_reports["r3"] = (users["owner"], dict(FULL_REPORT))
    resp = client_as(users["owner"], "r3").get("/download_pdf")
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert "recon_x_report.pdf" in resp.headers["Content-Disposition"]
    assert resp.data.startswith(b"%PDF")
