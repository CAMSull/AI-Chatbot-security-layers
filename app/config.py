"""
Central configuration, loaded from environment variables (and a local .env
file if present). Nothing sensitive is hardcoded here — every secret is
read from the environment so it can be swapped for a real Azure resource
(or Azure Key Vault reference) without touching code.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from typing import Dict, List

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- Layer 1: Authentication -------------------------------------------------
    # Comma-separated "key:username" pairs, e.g. "sk_demo_123:alice,sk_demo_456:bob"
    api_keys_raw: str = Field(default="dev-local-key:demo-user", alias="API_KEYS")

    # --- Layer 2: Input validation -------------------------------------------------
    max_input_length: int = Field(default=2000, alias="MAX_INPUT_LENGTH")

    # --- Layer 3: Rate limiting -----------------------------------------------------
    rate_limit_requests: int = Field(default=10, alias="RATE_LIMIT_REQUESTS")
    rate_limit_window_seconds: int = Field(default=60, alias="RATE_LIMIT_WINDOW_SECONDS")

    # --- Layer 4: Content moderation -------------------------------------------------
    azure_content_safety_endpoint: str = Field(default="", alias="AZURE_CONTENT_SAFETY_ENDPOINT")
    azure_content_safety_key: str = Field(default="", alias="AZURE_CONTENT_SAFETY_KEY")
    content_safety_severity_threshold: int = Field(default=4, alias="CONTENT_SAFETY_SEVERITY_THRESHOLD")

    # --- Layer 5: Output filtering / logging -----------------------------------------
    log_file: str = Field(default="audit.log", alias="LOG_FILE")
    log_raw_messages: bool = Field(default=False, alias="LOG_RAW_MESSAGES")

    # --- Azure OpenAI (the model itself) ----------------------------------------------
    azure_openai_endpoint: str = Field(default="", alias="AZURE_OPENAI_ENDPOINT")
    azure_openai_api_key: str = Field(default="", alias="AZURE_OPENAI_API_KEY")
    azure_openai_deployment: str = Field(default="", alias="AZURE_OPENAI_DEPLOYMENT")
    azure_openai_api_version: str = Field(default="2024-10-21", alias="AZURE_OPENAI_API_VERSION")

    # If true (or auto-detected when Azure OpenAI credentials are absent), the
    # app returns deterministic mock replies instead of calling Azure. This lets
    # every security layer be demonstrated end-to-end without live credentials.
    mock_mode: bool = Field(default=False, alias="MOCK_MODE")

    cors_allowed_origins: str = Field(default="http://localhost:3000", alias="CORS_ALLOWED_ORIGINS")

    @property
    def api_keys(self) -> Dict[str, str]:
        """Map API key (sha256 hex digest) -> username."""
        keys: Dict[str, str] = {}
        for pair in self.api_keys_raw.split(","):
            pair = pair.strip()
            if not pair or ":" not in pair:
                continue
            raw_key, username = pair.split(":", 1)
            raw_key = raw_key.strip()
            username = username.strip()
            if raw_key and username:
                keys[_hash_key(raw_key)] = username
        return keys

    @property
    def cors_origins(self) -> List[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    @property
    def effective_mock_mode(self) -> bool:
        if self.mock_mode:
            return True
        return not (self.azure_openai_endpoint and self.azure_openai_api_key and self.azure_openai_deployment)

    @property
    def content_safety_configured(self) -> bool:
        return bool(self.azure_content_safety_endpoint and self.azure_content_safety_key)


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


@lru_cache
def get_settings() -> Settings:
    return Settings()
