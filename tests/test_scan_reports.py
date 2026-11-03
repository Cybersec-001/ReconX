"""store_results_in_session: report replacement and the 50-entry cap."""
import pytest
from flask import session

import app as rx


class StubUser:
    id = 7


@pytest.fixture(autouse=True)
def isolated_reports(monkeypatch):
    monkeypatch.setattr(rx, "scan_reports", {})
    monkeypatch.setattr(rx, "current_user", StubUser())
    yield


def store(title="t"):
    rx.store_results_in_session({}, {}, title, {}, {}, [], [])


def test_stores_report_with_owner_and_all_sections():
    with rx.app.test_request_context("/"):
        store()
        rid = session["report_id"]
    assert rid in rx.scan_reports
    uid, data = rx.scan_reports[rid]
    assert uid == 7
    assert set(data) == {
        "whois_data", "email_validation", "website_title", "ip_geolocation",
        "shodan_scan", "subdomains", "wayback_urls",
    }


def test_new_scan_replaces_previous_session_report():
    with rx.app.test_request_context("/"):
        store("first")
        first = session["report_id"]
        store("second")
        second = session["report_id"]
    assert first != second
    assert first not in rx.scan_reports
    assert rx.scan_reports[second][1]["website_title"] == "second"


def test_store_caps_at_50_evicting_oldest():
    rx.scan_reports.update({f"old{i}": (7, {}) for i in range(50)})
    with rx.app.test_request_context("/"):
        store("new")
    assert len(rx.scan_reports) == 50
    assert "old0" not in rx.scan_reports
    assert "old49" in rx.scan_reports