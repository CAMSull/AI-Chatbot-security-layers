"""
Test environment must be configured *before* app.config.get_settings() is
first called anywhere (it's lru_cache'd), so we set env vars at collection
time, here, before any `app.*` module gets imported by a test file.
"""
import os

os.environ["API_KEYS"] = "test-key:tester,other-key:other"
os.environ["MOCK_MODE"] = "true"
os.environ["RATE_LIMIT_REQUESTS"] = "1000"
os.environ["RATE_LIMIT_WINDOW_SECONDS"] = "60"
os.environ["LOG_FILE"] = "test_audit.log"
os.environ["AZURE_CONTENT_SAFETY_ENDPOINT"] = ""
os.environ["AZURE_CONTENT_SAFETY_KEY"] = ""

import pytest

from app.config import get_settings

get_settings.cache_clear()


@pytest.fixture
def settings():
    get_settings.cache_clear()
    return get_settings()
