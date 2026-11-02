"""Unit tests for ReconX intel helpers (shodan/censys/hibp/crt.sh/virustotal); network is mocked."""
import app


class FakeResp:
    def __init__(self, status=200, payload=None):
        self.status_code = status
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


def fake_get(monkeypatch, resp=None, exc=None):
    def _get(*args, **kwargs):
        if exc is not None:
            raise exc
        return resp
    monkeypatch.setattr(app.requests, 'get', _get)


def test_shodan_unavailable_without_key(monkeypatch):
    monkeypatch.setattr(app, 'shodan_api', None)
    assert 'SHODAN_API_KEY' in app.get_shodan_scan('1.2.3.4')


def test_shodan_aggregates_host_data(monkeypatch):
    class FakeAPI:
        def host(self, ip):
            return {
                'ip_str': ip, 'org': 'Example Org', 'isp': 'Example ISP', 'asn': 'AS123',
                'city': 'Pune', 'country_name': 'India',
                'hostnames': ['a.example.com'], 'ports': [443, 80],
                'data': [{'port': 443}, {'port': 80, 'transport': 'tcp'}, {'port': 443}],
                'last_update': '2026-10-01',
            }
    monkeypatch.setattr(app, 'shodan_api', FakeAPI())
    out = app.get_shodan_scan('1.2.3.4')
    assert out['organization'] == 'Example Org'
    assert out['location'] == 'Pune, India'
    assert out['open_ports'] == [80, 443]
    assert out['services'] == ['443/tcp', '80/tcp']


def test_shodan_api_error_returns_string(monkeypatch):
    class FakeAPI:
        def host(self, ip):
            raise app.shodan.APIError('no information available')
    monkeypatch.setattr(app, 'shodan_api', FakeAPI())
    assert app.get_shodan_scan('1.2.3.4') == 'Error: no information available'


def test_censys_success_and_empty(monkeypatch):
    payload = {'result': {'hits': []}}
    fake_get(monkeypatch, resp=FakeResp(200, payload))
    assert app.get_censys_data('example.com') == payload
    fake_get(monkeypatch, resp=FakeResp(403))
    assert app.get_censys_data('example.com') == 'No Censys data available'


def test_censys_exception_fallback(monkeypatch):
    fake_get(monkeypatch, exc=RuntimeError('timeout'))
    assert app.get_censys_data('example.com') == 'Censys Error: timeout'


def test_hibp_status_branches(monkeypatch):
    fake_get(monkeypatch, resp=FakeResp(200, [{'Name': 'SomeBreach'}]))
    assert app.get_hibp_breaches('a@b.com') == [{'Name': 'SomeBreach'}]
    fake_get(monkeypatch, resp=FakeResp(404))
    assert app.get_hibp_breaches('a@b.com') == 'No breaches found'
    fake_get(monkeypatch, resp=FakeResp(429))
    assert app.get_hibp_breaches('a@b.com') == 'Unable to check breaches'


def test_hibp_exception_fallback(monkeypatch):
    fake_get(monkeypatch, exc=RuntimeError('down'))
    assert app.get_hibp_breaches('a@b.com') == 'HIBP Error: down'


def test_crt_subdomains_split_deduped_sorted(monkeypatch):
    payload = [
        {'name_value': 'b.example.com\na.example.com'},
        {'name_value': 'a.example.com'},
        {'name_value': ' c.example.com '},
    ]
    fake_get(monkeypatch, resp=FakeResp(200, payload))
    assert app.get_crt_subdomains('example.com') == ['a.example.com', 'b.example.com', 'c.example.com']
    fake_get(monkeypatch, resp=FakeResp(502))
    assert app.get_crt_subdomains('example.com') == 'No subdomain data available'


def test_crt_subdomains_exception_fallback(monkeypatch):
    fake_get(monkeypatch, exc=RuntimeError('boom'))
    assert 'unavailable' in app.get_crt_subdomains('example.com')


def test_virustotal_branches(monkeypatch):
    payload = {'data': {'id': 'example.com'}}
    fake_get(monkeypatch, resp=FakeResp(200, payload))
    assert app.get_virustotal_data('example.com') == payload
    fake_get(monkeypatch, resp=FakeResp(401))
    assert app.get_virustotal_data('example.com') == 'No VirusTotal data available'
    fake_get(monkeypatch, exc=RuntimeError('nope'))
    assert app.get_virustotal_data('example.com') == 'VirusTotal Error: nope'