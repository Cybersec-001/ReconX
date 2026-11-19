"""Simple route surfaces: public pages, admin panel access, and the deactivated-account guard."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")

import pytest

import app as rx

NORMAL = "surface_normal_user"
ADMIN = "surface_admin_user"


@pytest.fixture()
def users():
    rx.limiter.reset()
    with rx.app.app_context():
        for name in (NORMAL, ADMIN):
            existing = rx.User.query.filter_by(username=name).first()
            if existing:
                rx.db.session.delete(existing)
        rx.db.session.commit()
        normal = rx.User(username=NORMAL)
        normal.set_password("pass1234")
        admin = rx.User(username=ADMIN, is_admin=True)
        admin.set_password("pass1234")
        rx.db.session.add_all([normal, admin])
        rx.db.session.commit()
        yield {"normal": normal.id, "admin": admin.id}
        for name in (NORMAL, ADMIN):
            leftover = rx.User.query.filter_by(username=name).first()
            if leftover:
                rx.db.session.delete(leftover)
        rx.db.session.commit()


def client_for(user_id=None):
    rx.app.config["TESTING"] = True
    client = rx.app.test_client()
    with client.session_transaction() as sess:
        if user_id is not None:
            sess["_user_id"] = str(user_id)
        sess["_csrf"] = "surface-csrf"
    return client


def test_landing_page_is_public():
    resp = client_for().get("/")
    assert resp.status_code == 200
    assert b"not a vulnerability or port scanner" in resp.data


def test_demo_page_renders_sample_results():
    resp = client_for().get("/demo")
    assert resp.status_code == 200
    assert b"example.com" in resp.data


def test_register_page_renders():
    resp = client_for().get("/register")
    assert resp.status_code == 200
    assert b"Register" in resp.data or b"register" in resp.data


def test_workspace_get_renders_for_a_logged_in_user(users):
    resp = client_for(users["normal"]).get("/workspace")
    assert resp.status_code == 200


def test_admin_login_lands_on_the_admin_panel(users):
    client = client_for()
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    resp = client.post("/login", data={"username": ADMIN, "password": "pass1234", "csrf_token": csrf})
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/admin")


def test_admin_panel_lists_users_for_an_admin(users):
    resp = client_for(users["admin"]).get("/admin")
    assert resp.status_code == 200
    assert NORMAL.encode() in resp.data


def test_non_admin_cannot_delete_a_user(users):
    client = client_for(users["normal"])
    with client.session_transaction() as sess:
        csrf = sess["_csrf"]
    resp = client.post(f"/admin/user/{users['normal']}/delete", data={"csrf_token": csrf},
                       follow_redirects=True)
    assert b"Access denied" in resp.data
    with rx.app.app_context():
        assert rx.User.query.filter_by(username=NORMAL).first() is not None
