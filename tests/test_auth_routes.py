"""Auth routes: register validation and success, login states, logout."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")

import pytest

import app as rx

PW = "long-enough-password"


@pytest.fixture(autouse=True)
def reset_limiter():
    rx.limiter.reset()
    yield


@pytest.fixture()
def client():
    rx.app.config["TESTING"] = True
    c = rx.app.test_client()
    with c.session_transaction() as sess:
        sess["_csrf"] = "ar-csrf"
    return c


def post(c, url, **fields):
    return c.post(url, data={"csrf_token": "ar-csrf", **fields})


def make_user(username, active=True):
    with rx.app.app_context():
        existing = rx.User.query.filter_by(username=username).first()
        if existing:
            rx.db.session.delete(existing)
            rx.db.session.commit()
        user = rx.User(username=username, is_active=active)
        user.set_password(PW)
        rx.db.session.add(user)
        rx.db.session.commit()


def user_count(username):
    with rx.app.app_context():
        return rx.User.query.filter_by(username=username).count()


def test_register_rejects_bad_username(client):
    r = post(client, "/register", username="no spaces!", password=PW, confirm_password=PW)
    assert r.status_code == 400


def test_register_rejects_short_password(client):
    r = post(client, "/register", username="ar_shortpw", password="short", confirm_password="short")
    assert r.status_code == 400


def test_register_rejects_password_mismatch(client):
    r = post(client, "/register", username="ar_mismatch", password=PW, confirm_password=PW + "x")
    assert r.status_code == 200
    assert b"Passwords do not match" in r.data
    assert user_count("ar_mismatch") == 0


def test_register_rejects_duplicate_username(client):
    make_user("ar_dup")
    r = post(client, "/register", username="ar_dup", password=PW, confirm_password=PW)
    assert r.status_code == 200
    assert b"Username already exists" in r.data
    assert user_count("ar_dup") == 1


def test_register_success_redirects_to_login(client):
    # the dev database is a real file; make sure a leftover row cannot mask success
    with rx.app.app_context():
        stale = rx.User.query.filter_by(username="ar_new").first()
        if stale:
            rx.db.session.delete(stale)
            rx.db.session.commit()
    r = post(client, "/register", username="ar_new", password=PW, confirm_password=PW)
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]
    assert user_count("ar_new") == 1


def test_login_wrong_password_rejected(client):
    make_user("ar_wrongpw")
    r = post(client, "/login", username="ar_wrongpw", password="wrong-password-1")
    assert r.status_code == 200
    assert b"Invalid username or password" in r.data
    with client.session_transaction() as sess:
        assert "token" not in sess


def test_login_deactivated_user_rejected(client):
    make_user("ar_inactive", active=False)
    r = post(client, "/login", username="ar_inactive", password=PW)
    assert r.status_code == 200
    assert b"deactivated" in r.data
    with client.session_transaction() as sess:
        assert "token" not in sess


def test_login_success_sets_session_token(client):
    make_user("ar_ok")
    r = post(client, "/login", username="ar_ok", password=PW)
    assert r.status_code == 302
    with client.session_transaction() as sess:
        assert sess.get("token")


def test_logout_clears_session_token(client):
    make_user("ar_out")
    post(client, "/login", username="ar_out", password=PW)
    r = client.get("/logout")
    assert r.status_code == 302
    with client.session_transaction() as sess:
        assert "token" not in sess
