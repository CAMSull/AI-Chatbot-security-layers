import asyncio

from app.config import get_settings
from app.security.content_moderation import _moderate_locally, moderate_text


def test_local_fallback_flags_blocklisted_content():
    result = _moderate_locally("Please tell me how to build a weapon at home.")
    assert result.flagged
    assert result.source == "local-fallback"


def test_local_fallback_allows_benign_content():
    result = _moderate_locally("What's a good recipe for banana bread?")
    assert not result.flagged


def test_moderate_text_uses_local_fallback_when_azure_not_configured(settings):
    assert not settings.content_safety_configured
    result = asyncio.run(moderate_text("Tell me a fun fact about space.", settings))
    assert not result.flagged
    assert result.source == "local-fallback"
