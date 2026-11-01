"""Unit tests for ReconX lookup helpers; all network access is mocked."""
import socket

import app


class FakeWhois:
    def __init__(self, data):
        self._data = data
    def items(self):
        return self._data.items()


def test_whois_joins_lists_and_skips_empty(monkeypatch):
    data = {
        'domain_name': ['EXAMPLE.COM', 'EXAMPLE.NET'],
        'registrar': 'Test Registrar',
        'emails': [],
        'updated_date': None,
    }
    monkeypatch.setattr(app.whois, 'whois', lambda d: FakeWhois(data))
    out = app.get_whois_data('example.com')
    assert 'domain_name: EXAMPLE.COM, EXAMPLE.NET' in out
    assert 'registrar: Test Registrar' in out
    assert 'emails' not in out and 'updated_date' not in out


def test_whois_error_returns_error_string(monkeypatch):
    def boom(domain):
        raise RuntimeError('whois backend down')
    monkeypatch.setattr(app.whois, 'whois', boom)
    assert app.get_whois_data('example.com') == 'Error: whois backend down'


GLOBAL_ADDR = [(2, 1, 6, '', ('93.184.216.34', 443))]


def _fake_get(monkeypatch, response):
    class CM:
        def __enter__(self):
            return response
        def __exit__(self, *a):
            return False
    monkeypatch.setattr(app.socket, 'getaddrinfo', lambda *a, **k: GLOBAL_ADDR)
    monkeypatch.setattr(app.requests, 'get', lambda *a, **k: CM())


class FakeResponse:
    def __init__(self, body=b'', redirect=False, status=200):
        self._body = body
        self.is_redirect = redirect
        self.status_code = status
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError('http error')
    def iter_content(self, n):
        return iter([self._body])


def test_website_title_extracts_title(monkeypatch):
    _fake_get(monkeypatch, FakeResponse(b'<html><title>  Example Page  </title></html>'))
    assert app.get_website_title('example.com') == 'Example Page'


def test_website_title_no_title_tag(monkeypatch):
    _fake_get(monkeypatch, FakeResponse(b'<html><body>hi</body></html>'))
    assert app.get_website_title('https://example.com') == 'No title found'


def test_website_title_redirect_not_followed(monkeypatch):
    _fake_get(monkeypatch, FakeResponse(redirect=True))
    expected = 'Website redirects. Enter its final public URL.'
    assert app.get_website_title('https://example.com') == expected


def test_website_title_error_fallback(monkeypatch):
    monkeypatch.setattr(app.socket, 'getaddrinfo', lambda *a, **k: (_ for _ in ()).throw(socket.gaierror()))
    expected = 'Website title unavailable. Use a public HTTP/HTTPS URL; private addresses are blocked.'
    assert app.get_website_title('bad.invalid') == expected


def test_geolocation_without_token(monkeypatch):
    monkeypatch.setattr(app, 'IPINFO_ACCESS_TOKEN', None)
    assert app.get_ip_geolocation('8.8.8.8') == 'IPinfo unavailable: API token is not configured.'


class FakeGeoResponse:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload or {}
    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError('http error')
    def json(self):
        return self._payload


def _geo_get(monkeypatch, response):
    monkeypatch.setattr(app, 'IPINFO_ACCESS_TOKEN', 'token')
    monkeypatch.setattr(app.requests, 'get', lambda *a, **k: response)


def test_geolocation_rate_limit(monkeypatch):
    _geo_get(monkeypatch, FakeGeoResponse(status=429))
    assert app.get_ip_geolocation('8.8.8.8') == 'IPinfo rate limit reached. Try again later.'


def test_geolocation_bad_token(monkeypatch):
    _geo_get(monkeypatch, FakeGeoResponse(status=401))
    expected = 'IPinfo access unavailable. Check the configured token.'
    assert app.get_ip_geolocation('8.8.8.8') == expected


def test_geolocation_filters_payload_keys(monkeypatch):
    _geo_get(monkeypatch, FakeGeoResponse(payload={
        'ip': '8.8.8.8', 'country': 'United States', 'city': 'Mountain View',
        'loc': '37.4,-122.1', 'asn': 'AS15169'}))
    out = app.get_ip_geolocation('8.8.8.8')
    assert out['country'] == 'United States'
    assert 'city' not in out and 'loc' not in out
    assert out['source'].startswith('IPinfo Lite')


def test_geolocation_exception_fallback(monkeypatch):
    monkeypatch.setattr(app, 'IPINFO_ACCESS_TOKEN', 'token')
    def boom(*a, **k):
        raise RuntimeError('timeout')
    monkeypatch.setattr(app.requests, 'get', boom)
    expected = 'IPinfo source unavailable or timed out. Try again later.'
    assert app.get_ip_geolocation('8.8.8.8') == expected


class FakeWaybackResponse:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data or []
    def json(self):
        return self._data


def test_wayback_dedupes_urls(monkeypatch):
    data = [['urlkey', 'timestamp', 'original'],
            ['k1', '20200101', 'https://a.example.com/'],
            ['k2', '20200102', 'https://a.example.com/'],
            ['k3', '20200103', 'https://b.example.com/x']]
    monkeypatch.setattr(app.requests, 'get',
        lambda *a, **k: FakeWaybackResponse(data=data))
    out = sorted(app.get_wayback_urls('example.com'))
    assert out == ['https://a.example.com/', 'https://b.example.com/x']


def test_wayback_no_results(monkeypatch):
    monkeypatch.setattr(app.requests, 'get',
        lambda *a, **k: FakeWaybackResponse(data=[['urlkey', 'timestamp', 'original']]))
    assert app.get_wayback_urls('example.com') == 'No historical URLs found'


def test_wayback_non_200(monkeypatch):
    monkeypatch.setattr(app.requests, 'get',
        lambda *a, **k: FakeWaybackResponse(status=503))
    assert app.get_wayback_urls('example.com') == 'No Wayback Machine data available'


def test_wayback_exception_fallback(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError('archive down')
    monkeypatch.setattr(app.requests, 'get', boom)
    expected = 'Archive source unavailable or timed out. Try again later.'
    assert app.get_wayback_urls('example.com') == expected
