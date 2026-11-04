"""CSRF: form posts need the session token, and the token stays stable."""
from flask import session

import app as rx


def client():
    rx.app.config["TESTING"] = True
    return rx.app.test_client()


def test_post_without_csrf_token_is_rejected():
    c = client()
    r = c.post("/login", data={"username": "x", "password": "y"})
    assert r.status_code == 400
    assert b"Form expired" in r.data


def test_post_with_wrong_csrf_token_is_rejected():
    c = client()
    with c.session_transaction() as sess:
        sess["_csrf"] = "expected-token"
    r = c.post("/login", data={"username": "x", "password": "y", "csrf_token": "wrong-token"})
    assert r.status_code == 400


def test_post_with_matching_csrf_token_passes_csrf_check():
    c = client()
    with c.session_transaction() as sess:
        sess["_csrf"] = "expected-token"
    r = c.post("/login", data={"username": "no-such-user", "password": "bad", "csrf_token": "expected-token"})
    assert r.status_code != 400


def test_csrf_token_is_created_once_and_stable():
    rx.app.config["TESTING"] = True
    with rx.app.test_request_context("/"):
        session.setdefault("_probe", True)
        token_fn = rx.csrf_context()["csrf_token"]
        first = token_fn()
        assert token_fn() == first
        assert len(first) > 20
