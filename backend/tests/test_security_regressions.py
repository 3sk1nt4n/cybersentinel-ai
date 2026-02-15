import asyncio
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

from fastapi import HTTPException

from app.core.auth import require_api_key
from app.core.config import settings, is_api_auth_active, is_production, validate_security_settings
from app.routers.health import full_health_check
from app.services import scanner


class ConfigSecurityTests(unittest.TestCase):
    def setUp(self):
        self.orig_env = settings.app_env
        self.orig_secret = settings.secret_key
        self.orig_auth = settings.api_auth_enabled
        self.orig_key = settings.api_key

    def tearDown(self):
        settings.app_env = self.orig_env
        settings.secret_key = self.orig_secret
        settings.api_auth_enabled = self.orig_auth
        settings.api_key = self.orig_key

    def test_production_validation_requires_secret_and_api_key(self):
        settings.app_env = "production"
        settings.secret_key = ""
        settings.api_auth_enabled = True
        settings.api_key = None

        errs = validate_security_settings()

        self.assertTrue(any("SECRET_KEY" in e for e in errs))
        self.assertTrue(any("API_KEY" in e for e in errs))

    def test_dev_mode_does_not_require_secret_or_api_key(self):
        settings.app_env = "development"
        settings.secret_key = ""
        settings.api_auth_enabled = True
        settings.api_key = None

        errs = validate_security_settings()

        self.assertEqual(errs, [])
        self.assertFalse(is_api_auth_active())
        self.assertFalse(is_production())


class AuthDependencyTests(unittest.TestCase):
    def setUp(self):
        self.orig_auth = settings.api_auth_enabled
        self.orig_key = settings.api_key

    def tearDown(self):
        settings.api_auth_enabled = self.orig_auth
        settings.api_key = self.orig_key

    def test_auth_skips_when_disabled(self):
        settings.api_auth_enabled = False
        settings.api_key = None

        asyncio.run(require_api_key(None))

    def test_auth_skips_when_enabled_but_key_missing(self):
        settings.api_auth_enabled = True
        settings.api_key = None

        asyncio.run(require_api_key(None))

    def test_auth_blocks_when_active_and_key_invalid(self):
        settings.api_auth_enabled = True
        settings.api_key = "good-key"

        with self.assertRaises(HTTPException) as ctx:
            asyncio.run(require_api_key("bad-key"))

        self.assertEqual(ctx.exception.status_code, 401)

    def test_auth_allows_when_active_and_key_valid(self):
        settings.api_auth_enabled = True
        settings.api_key = "good-key"

        asyncio.run(require_api_key("good-key"))


class HealthEndpointTests(unittest.TestCase):
    def setUp(self):
        self.orig_env = settings.app_env
        self.orig_secret = settings.secret_key
        self.orig_auth = settings.api_auth_enabled
        self.orig_key = settings.api_key

    def tearDown(self):
        settings.app_env = self.orig_env
        settings.secret_key = self.orig_secret
        settings.api_auth_enabled = self.orig_auth
        settings.api_key = self.orig_key

    def test_health_reports_degraded_for_prod_security_errors(self):
        settings.app_env = "production"
        settings.secret_key = ""
        settings.api_auth_enabled = True
        settings.api_key = None

        fake_graph = types.ModuleType("app.services.graph")
        fake_rag = types.ModuleType("app.services.rag")

        async def _graph_health():
            return {"status": "connected"}

        async def _rag_health():
            return {"status": "ok", "collections": 1}

        fake_graph.check_neo4j_health = _graph_health
        fake_rag.get_collection_stats = _rag_health

        with patch("app.routers.health.check_ollama_health", new=AsyncMock(return_value={"status": "ok"})):
            with patch.dict(sys.modules, {
                "app.services.graph": fake_graph,
                "app.services.rag": fake_rag,
            }):
                data = asyncio.run(full_health_check())

        self.assertEqual(data["status"], "degraded")
        self.assertEqual(data["security"]["status"], "error")
        self.assertGreaterEqual(len(data["security"]["errors"]), 1)


class ScannerExecutionSemanticsTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_in_sandbox_marks_nonzero_exit_as_failure(self):
        class FakeProc:
            returncode = 2

            async def communicate(self):
                return b"", b"some error"

            def kill(self):
                return None

        with patch("app.services.scanner.asyncio.create_subprocess_exec", new=AsyncMock(return_value=FakeProc())):
            result = await scanner._run_in_sandbox("echo test", timeout=2)

        self.assertFalse(result["success"])
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["exit_code"], 2)
        self.assertIn("some error", result["stderr"])


if __name__ == "__main__":
    unittest.main()
