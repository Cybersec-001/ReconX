"""workspace POST: field validation and the scan-success path."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")

import pytest

import app as rx

USERNAME = "workspace_test_user"

VALID_FORM = dict(domain="example.com", email="a@example.com",
                  url="https://example.com", ip="93.184.216.34")


@pytest.fixture()
def user(monkeypatch):
    monkeypatch.setattr(rx, "scan_reports", {})
    rx.limiter.reset()
    with rx.app.app_context():
        existing = rx.User.query.filter_by(username=USERNAME).first()
        if existing:
            rx.db.session.delete(existing)
            rx.db.session.commit()
        account = rx.User(username=USERNAME)
        account.set_password("pass1234")
        rx.db.session.add(account)
        rx.db.session.commit()
        yield account.id
        leftover = rx.User.query.filter_by(username=USERNAME).first()
        if leftover:
            rx.db.session.delete(leftover)
            rx.db.session.commit()


def client_for(user_id):
    rx.app.config["TESTING"] = True
    client = rx.app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_csrf"] = "ws-csrf"
    return client


def post_workspace(user_id, **overrides):
    form = dict(VALID_FORM)
    form.update(overrides)
    form["csrf_token"] = "ws-csrf"
    return client_for(user_id).post("/workspace", data=form)


def test_missing_fields_are_rejected(user):
    form = dict(VALID_FORM)
    del form["ip"]
    form["csrf_token"] = "ws-csrf"
    resp = client_for(user).post("/workspace", data=form)
    assert resp.status_code == 200
    assert b"All fields are required" in resp.data


def test_invalid_domain_is_rejected(user):
    resp = post_workspace(user, domain="https://example.com/path")
    assert resp.status_code == 400
    assert b"Enter a domain name only" in resp.data


def test_private_ip_is_rejected(user):
    resp = post_workspace(user, ip="10.0.0.8")
    assert resp.status_code == 400
    assert b"Enter a public IP address" in resp.data


def test_overlong_input_is_rejected(user):
    resp = post_workspace(user, email="a" * 250 + "@x.com")
    assert resp.status_code == 400
    assert b"Input is too long" in resp.data


def test_successful_scan_renders_results_and_stores_report(user, monkeypatch):
    monkeypatch.setattr(rx, "get_whois_data", lambda domain: {"registrar": "Test Registrar"})
    monkeypatch.setattr(rx, "validate_email", lambda email: {"valid_format": True})
    monkeypatch.setattr(rx, "get_website_title", lambda url: "Example Title")
    monkeypatch.setattr(rx, "get_ip_geolocation", lambda ip: {"country": "Testland"})
    monkeypatch.setattr(rx, "get_shodan_scan", lambda ip: {"ports": [80]})
    monkeypatch.setattr(rx, "get_crt_subdomains", lambda domain: ["www.example.com"])
    monkeypatch.setattr(rx, "get_wayback_urls", lambda domain: ["http://example.com/old"])

    client = client_for(user)
    resp = client.post("/workspace", data={**VALID_FORM, "csrf_token": "ws-csrf"})
    assert resp.status_code == 200
    assert b"Example Title" in resp.data

    with client.session_transaction() as sess:
        report_id = sess.get("report_id")
    assert report_id in rx.scan_reports
    owner_id, report = rx.scan_reports[report_id]
    assert report["website_title"] == "Example Title"


def test_scan_failure_reraises_as_error_page(user, monkeypatch):
    def boom(domain):
        raise RuntimeError("whois backend down")

    monkeypatch.setattr(rx, "get_whois_data", boom)
    monkeypatch.setattr(rx, "validate_email", lambda email: {"valid_format": True})
    monkeypatch.setattr(rx, "get_website_title", lambda url: "t")
    monkeypatch.setattr(rx, "get_ip_geolocation", lambda ip: {})
    monkeypatch.setattr(rx, "get_shodan_scan", lambda ip: {})
    monkeypatch.setattr(rx, "get_crt_subdomains", lambda domain: [])
    monkeypatch.setattr(rx, "get_wayback_urls", lambda domain: [])

    resp = post_workspace(user)
    assert resp.status_code == 200
    assert b"whois backend down" in resp.data
