"""First-run admin bootstrap and the PDF generation failure path."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")

import sqlite3
import subprocess
import sys

import pytest

import app as rx

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OWNER = "bootstrap_pdf_owner"

FULL_REPORT = dict(
    whois_data={"registrar": "Example Registrar"},
    email_validation={"valid_format": True},
    website_title="Example Domain",
    ip_geolocation={"country": "Nowhere"},
    shodan_scan={"ports": [80, 443]},
    subdomains=["www.example.com"],
    wayback_urls=["http://example.com/old"],
)


def import_fresh(db_path, admin_username=None, admin_password=None):
    """Import app.py in a clean interpreter, the way a first deploy would."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SECRET_KEY": "bootstrap-test-secret",
        "DATABASE_URL": "sqlite:///" + str(db_path),
        "PYTHONPATH": REPO_ROOT,
    }
    if admin_username is not None:
        env["ADMIN_USERNAME"] = admin_username
    if admin_password is not None:
        env["ADMIN_PASSWORD"] = admin_password
    return subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


def usernames_and_flags(db_path):
    with sqlite3.connect(str(db_path)) as conn:
        return conn.execute("SELECT username, is_admin FROM users").fetchall()


def test_admin_is_created_on_first_run_with_env_credentials(tmp_path):
    db_path = tmp_path / "boot.db"
    result = import_fresh(db_path, admin_username="boot_admin", admin_password="sup3r-secret")
    assert result.returncode == 0, result.stderr
    rows = usernames_and_flags(db_path)
    assert rows == [("boot_admin", 1)]


def test_bootstrap_is_idempotent_on_restart(tmp_path):
    db_path = tmp_path / "boot.db"
    first = import_fresh(db_path, admin_username="boot_admin", admin_password="sup3r-secret")
    assert first.returncode == 0, first.stderr
    second = import_fresh(db_path, admin_username="boot_admin", admin_password="sup3r-secret")
    assert second.returncode == 0, second.stderr
    rows = usernames_and_flags(db_path)
    assert rows == [("boot_admin", 1)]


def test_no_admin_is_created_without_env_credentials(tmp_path):
    db_path = tmp_path / "boot.db"
    result = import_fresh(db_path)
    assert result.returncode == 0, result.stderr
    assert usernames_and_flags(db_path) == []
    assert "no admin user created" in result.stderr


@pytest.fixture()
def owner(monkeypatch):
    monkeypatch.setattr(rx, "scan_reports", {})
    rx.limiter.reset()
    with rx.app.app_context():
        existing = rx.User.query.filter_by(username=OWNER).first()
        if existing:
            rx.db.session.delete(existing)
            rx.db.session.commit()
        user = rx.User(username=OWNER)
        user.set_password("pass1234")
        rx.db.session.add(user)
        rx.db.session.commit()
        yield user.id
        leftover = rx.User.query.filter_by(username=OWNER).first()
        if leftover:
            rx.db.session.delete(leftover)
            rx.db.session.commit()


def test_pdf_build_failure_flashes_and_redirects_to_workspace(owner, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("reportlab blew up")

    monkeypatch.setattr(rx, "SimpleDocTemplate", broken)
    rx.scan_reports["rid"] = (owner, dict(FULL_REPORT))

    rx.app.config["TESTING"] = True
    client = rx.app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(owner)
        sess["report_id"] = "rid"

    resp = client.get("/download_pdf")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/workspace")

    followed = client.get("/download_pdf", follow_redirects=True)
    assert b"Error generating PDF" in followed.data
