import os

os.environ.setdefault("SECRET_KEY", "test-secret-key")

import jwt
import pytest

import app


@app.app.route("/_test_token_ping")
@app.token_required
def _token_ping(current_user):
    return {"ok": True, "username": current_user.username}


@pytest.fixture()
def user_id():
    with app.app.app_context():
        existing = app.User.query.filter_by(username="token_test_user").first()
        if existing:
            app.db.session.delete(existing)
            app.db.session.commit()
        u = app.User(username="token_test_user")
        u.set_password("pass1234")
        app.db.session.add(u)
        app.db.session.commit()
        yield u.id


def _token(uid):
    return jwt.encode({"user_id": uid}, app.app.config["SECRET_KEY"],
                      algorithm="HS256")


class TestValidateEmail:
    @pytest.mark.parametrize("email", [
        "user@example.com",
        "first.last+tag@sub.domain.co",
        "a@b-cd.io",
    ])
    def test_valid_formats(self, email):
        result = app.validate_email(email)
        assert result.startswith("Valid email format")
        assert "does not verify" in result

    @pytest.mark.parametrize("email", [
        "no-at-sign",
        "user@",
        "@example.com",
        "user@example",
        "user@example.c",
        "user @example.com",
        "",
    ])
    def test_invalid_formats(self, email):
        assert app.validate_email(email) == "Invalid email format."


class TestLoadUser:
    def test_returns_user_for_valid_id(self, user_id):
        with app.app.app_context():
            loaded = app.load_user(str(user_id))
            assert loaded is not None
            assert loaded.username == "token_test_user"

    def test_none_for_non_numeric_id(self, user_id):
        with app.app.app_context():
            assert app.load_user("not-a-number") is None

    def test_none_for_unknown_id(self, user_id):
        with app.app.app_context():
            assert app.load_user("424242424") is None


class TestTokenRequired:
    def test_missing_token_rejected(self, user_id):
        resp = app.app.test_client().get("/_test_token_ping")
        assert resp.status_code == 401
        assert resp.get_json()["message"] == "Token is missing"

    def test_garbage_token_rejected(self, user_id):
        resp = app.app.test_client().get("/_test_token_ping?token=not-a-jwt")
        assert resp.status_code == 401
        assert resp.get_json()["message"] == "Token is invalid"

    def test_token_for_unknown_user_rejected(self, user_id):
        resp = app.app.test_client().get("/_test_token_ping?token=" + _token(424242424))
        assert resp.status_code == 401
        assert resp.get_json()["message"] == "Token is invalid"

    def test_valid_token_passes_user(self, user_id):
        resp = app.app.test_client().get("/_test_token_ping?token=" + _token(user_id))
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True, "username": "token_test_user"}

    def test_token_via_header_accepted(self, user_id):
        resp = app.app.test_client().get("/_test_token_ping",
                                         headers={"X-API-Token": _token(user_id)})
        assert resp.status_code == 200
