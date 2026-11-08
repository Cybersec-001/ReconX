"""Admin area: health probe, role gating and the protected admin account."""
import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")
os.environ.setdefault("ADMIN_USERNAME", "adm-protected-account")

import pytest

import app as rx

PROTECTED = "adm-protected-account"
ADMIN = "adm_test_admin"
NORMAL = "adm_test_user"


@pytest.fixture()
def users():
    with rx.app.app_context():
        for name in (ADMIN, NORMAL):
            existing = rx.User.query.filter_by(username=name).first()
            if existing:
                rx.db.session.delete(existing)
        rx.db.session.commit()
        admin = rx.User(username=ADMIN, is_admin=True)
        admin.set_password("pass1234")
        normal = rx.User(username=NORMAL)
        normal.set_password("pass1234")
        rx.db.session.add_all([admin, normal])
        rx.db.session.commit()
        protected = rx.User.query.filter_by(username=PROTECTED).first()
        if protected is None:
            protected = rx.User(username=PROTECTED)
            protected.set_password("pass1234")
            rx.db.session.add(protected)
            rx.db.session.commit()
        yield {"admin": admin.id, "normal": normal.id, "protected": protected.id}


def client_as(user_id):
    rx.app.config["TESTING"] = True
    client = rx.app.test_client()
    with client.session_transaction() as sess:
        sess["_user_id"] = str(user_id)
        sess["_csrf"] = "test-csrf"
    return client


def post(client, url):
    return client.post(url, data={"csrf_token": "test-csrf"})


def is_active(user_id):
    with rx.app.app_context():
        return rx.User.query.get(user_id).is_active


def test_health_reports_ok():
    rx.app.config["TESTING"] = True
    resp = rx.app.test_client().get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_anonymous_is_sent_to_login(users):
    rx.app.config["TESTING"] = True
    resp = rx.app.test_client().get("/admin")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_non_admin_cannot_open_admin_or_toggle(users):
    client = client_as(users["normal"])
    assert client.get("/admin").status_code == 302
    before = is_active(users["normal"])
    assert post(client, f"/admin/user/{users['admin']}/toggle").status_code == 302
    assert is_active(users["admin"]) is True
    assert is_active(users["normal"]) == before


def test_admin_toggles_a_user(users):
    client = client_as(users["admin"])
    assert is_active(users["normal"]) is True
    resp = post(client, f"/admin/user/{users['normal']}/toggle")
    assert resp.status_code == 302
    assert is_active(users["normal"]) is False
    post(client, f"/admin/user/{users['normal']}/toggle")
    assert is_active(users["normal"]) is True


def test_protected_admin_account_cannot_be_toggled_or_deleted(users):
    client = client_as(users["admin"])
    before = is_active(users["protected"])
    post(client, f"/admin/user/{users['protected']}/toggle")
    assert is_active(users["protected"]) == before
    post(client, f"/admin/user/{users['protected']}/delete")
    with rx.app.app_context():
        assert rx.User.query.get(users["protected"]) is not None


def test_admin_can_delete_a_normal_user(users):
    client = client_as(users["admin"])
    resp = post(client, f"/admin/user/{users['normal']}/delete")
    assert resp.status_code == 302
    with rx.app.app_context():
        assert rx.User.query.get(users["normal"]) is None
