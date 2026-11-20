"""Startup guards: SECRET_KEY is mandatory, and deactivated accounts cannot scan."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")

import subprocess
import sys

import pytest

import app as rx

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERNAME = "guard_deactivated_user"


def test_missing_secret_key_aborts_startup(tmp_path):
    env = {
        "PATH": os.environ.get("PATH", ""),
        "DATABASE_URL": "sqlite:///" + str(tmp_path / "guard.db"),
        "PYTHONPATH": REPO_ROOT,
    }
    result = subprocess.run(
        [sys.executable, "-c", "import app"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode != 0
    assert "SECRET_KEY is not set" in result.stderr


@pytest.fixture()
def deactivated_user():
    """Creates a deactivated user, leaving every app context before the request."""
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
        user_id = account.id
        account.is_active = False
        rx.db.session.commit()
    yield user_id
    with rx.app.app_context():
        leftover = rx.User.query.filter_by(username=USERNAME).first()
        if leftover:
            rx.db.session.delete(leftover)
            rx.db.session.commit()


def test_deactivated_user_session_cannot_scan(deactivated_user):
    # Auth layer blocks inactive users before the scan view runs: a stolen or
    # pre-deactivation session must not be able to launch a scan.
    rx.app.config["TESTING"] = True
    client = rx.app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(deactivated_user)
        sess["_csrf"] = "guard-csrf"
    resp = client.post("/workspace",
                       data={"domain": "example.com", "csrf_token": "guard-csrf"},
                       follow_redirects=True)
    assert resp.request.path == "/login"
    assert b"result.html" not in resp.data
    assert b"Whois" not in resp.data
