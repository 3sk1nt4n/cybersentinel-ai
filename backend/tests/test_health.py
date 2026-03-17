"""
Tests for GET /health endpoint.
"""


def test_health_returns_200(client):
    """GET /health should return HTTP 200 with status ok."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"


def test_health_includes_version(client):
    """GET /health should include a version field."""
    resp = client.get("/health")
    data = resp.json()
    assert "version" in data
    assert isinstance(data["version"], str)
    assert len(data["version"]) > 0
