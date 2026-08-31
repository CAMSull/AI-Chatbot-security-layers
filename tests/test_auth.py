import asyncio

import pytest
from fastapi import HTTPException

from app.security.auth import require_api_key


def test_valid_key_is_accepted():
    user = asyncio.run(require_api_key(x_api_key="test-key"))
    assert user.username == "tester"


def test_missing_key_is_rejected():
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(require_api_key(x_api_key=None))
    assert exc_info.value.status_code == 401


def test_invalid_key_is_rejected():
    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(require_api_key(x_api_key="not-a-real-key"))
    assert exc_info.value.status_code == 401


def test_different_valid_keys_map_to_different_users():
    user_a = asyncio.run(require_api_key(x_api_key="test-key"))
    user_b = asyncio.run(require_api_key(x_api_key="other-key"))
    assert user_a.username == "tester"
    assert user_b.username == "other"
    assert user_a.key_fingerprint != user_b.key_fingerprint
