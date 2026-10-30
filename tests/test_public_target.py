import os
import socket

os.environ.setdefault("SECRET_KEY", "test-secret-key")

import pytest

import app


def fake_dns(mapping):
    def _getaddrinfo(host, port, *args, **kwargs):
        ip = mapping.get(host)
        if ip is None:
            raise socket.gaierror(f"unknown host: {host}")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
    return _getaddrinfo


def test_accepts_public_url(monkeypatch):
    monkeypatch.setattr(app.socket, "getaddrinfo", fake_dns({"example.com": "93.184.216.34"}))
    assert app.public_target("https://example.com/") == "https://example.com/"


@pytest.mark.parametrize("url", [
    "ftp://example.com",
    "https://user:pw@example.com",
    "https://example.com:22/",
])
def test_rejects_odd_schemes_credentials_and_ports(url):
    with pytest.raises(ValueError):
        app.public_target(url)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.10", "169.254.169.254", "0.0.0.0"])
def test_blocks_private_and_reserved_targets(monkeypatch, ip):
    monkeypatch.setattr(app.socket, "getaddrinfo", fake_dns({"internal.example.com": ip}))
    with pytest.raises(ValueError):
        app.public_target("http://internal.example.com/")


def test_blocks_when_any_dns_answer_is_private(monkeypatch):
    answers = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 80)),
    ]
    monkeypatch.setattr(app.socket, "getaddrinfo", lambda *a, **k: answers)
    with pytest.raises(ValueError):
        app.public_target("http://mixed.example.com/")


def test_unresolvable_host_raises_valueerror(monkeypatch):
    monkeypatch.setattr(app.socket, "getaddrinfo", fake_dns({}))
    with pytest.raises(ValueError):
        app.public_target("http://does-not-exist.example/")