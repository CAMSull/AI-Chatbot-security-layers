"""
Layer 4 - Content Moderation (Input & Output)
================================================
Addresses OWASP LLM05 (Improper Output Handling)-adjacent safety concerns
and general harmful-content risk on both sides of the conversation.

When Azure AI Content Safety credentials are configured, every user message
and every model reply is sent to the Content Safety `text:analyze` endpoint
and scored across four categories (Hate, SelfHarm, Sexual, Violence) on a
0-7 severity scale; anything at or above the configured threshold is
blocked before it reaches the model or the user.

Because this is a university assessment project and a live Azure Content
Safety resource may not always be provisioned, this module falls back to a
local heuristic moderator (a blocklist of clearly unsafe terms) so the
moderation *layer* itself - request routing, blocking behaviour, logging -
can still be demonstrated end-to-end without live Azure credentials. The
fallback is explicitly NOT presented as production-grade; see README.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List

import httpx

from app.config import Settings

logger = logging.getLogger("security.content_moderation")

# Minimal local fallback blocklist - intentionally coarse. Real deployments
# should rely on Azure AI Content Safety (or an equivalent classifier), not
# keyword matching, which is trivial to evade and prone to false positives.
_LOCAL_BLOCKLIST = [
    "kill yourself",
    "make a bomb",
    "child sexual",
    "how to build a weapon",
]

CATEGORIES = ("Hate", "SelfHarm", "Sexual", "Violence")


@dataclass
class ModerationResult:
    flagged: bool
    categories: Dict[str, int] = field(default_factory=dict)
    reason: str = ""
    source: str = "local-fallback"


async def moderate_text(text: str, settings: Settings) -> ModerationResult:
    if settings.content_safety_configured:
        try:
            return await _moderate_with_azure(text, settings)
        except Exception as exc:  # noqa: BLE001 - fail closed to local check, never crash the request
            logger.error("azure_content_safety_error error=%s falling_back=local", exc)

    return _moderate_locally(text)


async def _moderate_with_azure(text: str, settings: Settings) -> ModerationResult:
    url = f"{settings.azure_content_safety_endpoint.rstrip('/')}/contentsafety/text:analyze"
    params = {"api-version": "2024-09-01"}
    headers = {
        "Ocp-Apim-Subscription-Key": settings.azure_content_safety_key,
        "Content-Type": "application/json",
    }
    payload = {"text": text, "categories": list(CATEGORIES)}

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(url, params=params, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()

    categories = {
        entry["category"]: entry["severity"]
        for entry in data.get("categoriesAnalysis", [])
    }
    flagged_categories = [
        name for name, severity in categories.items()
        if severity >= settings.content_safety_severity_threshold
    ]

    return ModerationResult(
        flagged=bool(flagged_categories),
        categories=categories,
        reason=f"Flagged categories: {', '.join(flagged_categories)}" if flagged_categories else "",
        source="azure-content-safety",
    )


def _moderate_locally(text: str) -> ModerationResult:
    lowered = text.lower()
    hits: List[str] = [term for term in _LOCAL_BLOCKLIST if term in lowered]
    return ModerationResult(
        flagged=bool(hits),
        categories={},
        reason=f"Local blocklist match: {', '.join(hits)}" if hits else "",
        source="local-fallback",
    )
