"""
CyberSentinel v3.0 - Test Configuration
Provides shared fixtures for all test modules.
"""
import sys
import os
import pytest

# Ensure the backend package is importable regardless of working directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient
from app.main import app


@pytest.fixture()
def client():
    """Yield a FastAPI TestClient wired to the CyberSentinel app."""
    with TestClient(app) as c:
        yield c
