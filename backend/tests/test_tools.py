"""
Tests for the /api/tools/ endpoints.
"""


class TestListTools:
    def test_returns_tools_list(self, client):
        """GET /api/tools/ should return a list of tools."""
        resp = client.get("/api/tools/")
        assert resp.status_code == 200
        data = resp.json()
        assert "tools" in data
        assert isinstance(data["tools"], list)

    def test_correct_tool_count(self, client):
        """The total tool count should be 33."""
        resp = client.get("/api/tools/")
        data = resp.json()
        assert data["total"] == 33
        assert len(data["tools"]) == 33


class TestToolQueries:
    def test_queries_for_nmap(self, client):
        """GET /api/tools/queries?name=Nmap Scanner should return sample queries."""
        resp = client.get("/api/tools/queries", params={"name": "Nmap Scanner"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["tool"] == "Nmap Scanner"
        assert isinstance(data["queries"], list)
        assert len(data["queries"]) > 0


class TestToolCategories:
    def test_categories_returned(self, client):
        """GET /api/tools/categories should return category counts."""
        resp = client.get("/api/tools/categories")
        assert resp.status_code == 200
        data = resp.json()
        assert "categories" in data
        cats = data["categories"]
        assert isinstance(cats, dict)
        # Verify known categories exist
        assert "scan" in cats
        assert "intel" in cats
        assert "siem" in cats
