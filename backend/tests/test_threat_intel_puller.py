"""
Tests for the NetAPI feed and the abuse.ch status warnings of the threat intel puller.
"""
import importlib
import json
import logging
import sys

import pytest

NETAPI_CSV = (
    "ip,first_seen,last_seen,category,top_threat,threats,country,asn,as_name,sensors\n"
    "192.0.2.10,2026-11-03T08:53:00Z,2026-11-19T07:42:23Z,C,ms17-010-exploit,ms17-010-exploit,TH,23969,\"TOT-NET, Thailand\",2\n"
    "192.0.2.20,2026-11-18T10:00:00Z,2026-11-20T06:40:54Z,A,ssh-bruteforce,ssh-bruteforce|phpunit-rce,US,14618,AMAZON-AES,5\n"
    "192.0.2.30,2026-11-20T05:51:56Z,2026-11-20T06:15:12Z,B,env-file-hunting,env-file-hunting,DE,24940,HETZNER-AS,1\n"
)


class FakeResponse:
    def __init__(self, status_code=200, text="", payload=None):
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self):
        return self._payload


@pytest.fixture()
def puller(tmp_path, monkeypatch):
    """The puller module with its data directory in a temp folder, and an open DB."""
    name = "app.services.threat_intel_puller"
    already_loaded = name in sys.modules
    # The module creates its data directory on import
    monkeypatch.setenv("CS_DATA_DIR", str(tmp_path))
    module = importlib.import_module(name)
    monkeypatch.setattr(module, "DATA_DIR", tmp_path)
    monkeypatch.setattr(module, "DB_PATH", tmp_path / "threat_intel.db")
    conn = module.init_db()
    yield module, conn
    conn.close()
    if not already_loaded:
        sys.modules.pop(name, None)


def test_netapi_stores_the_most_recent_ips(puller, monkeypatch):
    module, conn = puller
    calls = []

    def fake_get(url, timeout=None):
        calls.append(url)
        return FakeResponse(200, NETAPI_CSV)

    monkeypatch.setattr(module.requests, "get", fake_get)

    assert module.pull_netapi(conn, limit=2) == 2
    assert calls == ["https://netapi.com/api2/?method=compromised&dataset_type=ip&format=csv"]

    rows = conn.execute("""
        SELECT indicator, type, source, threat_type, confidence, tags, first_seen, last_seen
        FROM iocs ORDER BY last_seen DESC
    """).fetchall()
    assert rows == [
        ("192.0.2.20", "ip", "netapi", "ssh-bruteforce", 90, json.dumps(["ssh-bruteforce", "phpunit-rce"]),
         "2026-11-18T10:00:00Z", "2026-11-20T06:40:54Z"),
        ("192.0.2.30", "ip", "netapi", "env-file-hunting", 80, json.dumps(["env-file-hunting"]),
         "2026-11-20T05:51:56Z", "2026-11-20T06:15:12Z"),
    ]
    status = conn.execute("SELECT records_pulled, status, error_msg FROM feed_status WHERE feed_name='netapi'").fetchone()
    assert status == (2, "success", "")


def test_netapi_second_pull_updates_instead_of_duplicating(puller, monkeypatch):
    module, conn = puller
    monkeypatch.setattr(module.requests, "get", lambda url, timeout=None: FakeResponse(200, NETAPI_CSV))
    module.pull_netapi(conn)

    later = NETAPI_CSV.replace("2026-11-19T07:42:23Z", "2026-11-21T01:02:03Z")
    monkeypatch.setattr(module.requests, "get", lambda url, timeout=None: FakeResponse(200, later))
    assert module.pull_netapi(conn) == 3

    assert conn.execute("SELECT COUNT(*) FROM iocs WHERE source='netapi'").fetchone()[0] == 3
    assert conn.execute("SELECT last_seen FROM iocs WHERE indicator='192.0.2.10'").fetchone()[0] == "2026-11-21T01:02:03Z"


@pytest.mark.parametrize("response, error", [
    (FakeResponse(503, "Service Unavailable"), "HTTP 503"),
    (FakeResponse(200, "<html><body>maintenance</body></html>"), "Unexpected response (no CSV header)"),
])
def test_netapi_bad_response_is_reported(puller, monkeypatch, response, error):
    module, conn = puller
    monkeypatch.setattr(module.requests, "get", lambda url, timeout=None: response)

    assert module.pull_netapi(conn) == 0
    assert conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0] == 0
    status = conn.execute("SELECT records_pulled, status, error_msg FROM feed_status WHERE feed_name='netapi'").fetchone()
    assert status == (0, "error", error)


def test_netapi_network_error_is_reported(puller, monkeypatch):
    module, conn = puller

    def fake_get(url, timeout=None):
        raise module.requests.exceptions.ConnectionError("connection refused")

    monkeypatch.setattr(module.requests, "get", fake_get)

    assert module.pull_netapi(conn) == 0
    status = conn.execute("SELECT status, error_msg FROM feed_status WHERE feed_name='netapi'").fetchone()
    assert status == ("error", "connection refused")


def test_abusech_logs_the_feeds_that_need_a_key(puller, monkeypatch, caplog):
    module, conn = puller
    feodo = [{"ip_address": "192.0.2.50", "port": 443, "status": "online", "malware": "QakBot",
              "first_seen": "2025-12-30 13:56:31", "last_online": "2026-11-20", "country": "US", "as_number": 14618}]

    def fake_get(url, timeout=None):
        if "feodotracker" in url:
            return FakeResponse(200, payload=feodo)
        return FakeResponse(410, "Gone")

    monkeypatch.setattr(module.requests, "get", fake_get)
    monkeypatch.setattr(module.requests, "post", lambda url, timeout=None: FakeResponse(401, payload={"error": "Unauthorized"}))

    with caplog.at_level(logging.WARNING, logger="ThreatIntel"):
        assert module.pull_abusech(conn) == 1

    assert "URLhaus returned HTTP 401" in caplog.text
    assert "Malware Bazaar returned HTTP 410" in caplog.text
