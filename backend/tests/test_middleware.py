"""
Tests for app.core.middleware - RateLimitStore and AuthMiddleware behaviour.
"""
import time
from unittest.mock import patch

from app.core.middleware import RateLimitStore


# ───────────────────────────────────────────
# RateLimitStore unit tests
# ───────────────────────────────────────────

class TestRateLimitStoreAllow:
    def test_allows_requests_under_limit(self):
        """Requests within the max count should be allowed."""
        store = RateLimitStore()
        for _ in range(5):
            assert store.is_allowed("test-ip", max_requests=5, window_seconds=60) is True

    def test_blocks_requests_over_limit(self):
        """The request that exceeds max_requests should be denied."""
        store = RateLimitStore()
        for _ in range(3):
            store.is_allowed("test-ip", max_requests=3, window_seconds=60)
        assert store.is_allowed("test-ip", max_requests=3, window_seconds=60) is False

    def test_requests_expire_after_window(self):
        """After the window elapses, old requests should no longer count."""
        store = RateLimitStore()
        # Fill up the limit
        for _ in range(3):
            store.is_allowed("test-ip", max_requests=3, window_seconds=1)

        # Should be blocked now
        assert store.is_allowed("test-ip", max_requests=3, window_seconds=1) is False

        # Wait for the window to expire
        time.sleep(1.1)

        # Should be allowed again
        assert store.is_allowed("test-ip", max_requests=3, window_seconds=1) is True


# ───────────────────────────────────────────
# AuthMiddleware integration tests
# ───────────────────────────────────────────

class TestAuthMiddlewareNoKey:
    def test_requests_pass_when_api_key_not_set(self, client):
        """When CYBERSENTINEL_API_KEY is not configured, all requests should pass."""
        with patch("app.core.middleware.settings") as mock_settings:
            mock_settings.cybersentinel_api_key = None
            mock_settings.rate_limit_rpm = 9999
            mock_settings.rate_limit_scan_rpm = 9999
            resp = client.get("/api/tools/")
            assert resp.status_code == 200


class TestAuthMiddlewareWithKey:
    def test_missing_key_returns_401(self, client):
        """When API key is required and not provided, expect 401."""
        with patch("app.core.middleware.settings") as mock_settings:
            mock_settings.cybersentinel_api_key = "test-secret-key"
            mock_settings.rate_limit_rpm = 9999
            mock_settings.rate_limit_scan_rpm = 9999
            resp = client.get("/api/tools/")
            assert resp.status_code == 401
            data = resp.json()
            assert "error" in data
