"""
PromptWall configuration. All settings loaded from environment variables via Pydantic.
No hardcoded secrets; UPSTREAM_API_KEY must be set in .env or environment.
"""

import logging
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    UPSTREAM_API_KEY: str = Field(..., min_length=1, description="API key for upstream LLM provider")
    UPSTREAM_BASE_URL: str = Field(
        default="https://api.groq.com/openai/v1",
        description="Base URL for upstream OpenAI-compatible API",
    )
    UPSTREAM_MODEL: str = Field(
        default="llama-3.3-70b-versatile",
        description="Model to use when forwarding requests",
    )
    JUDGE_MODEL: str = Field(
        default="llama-3.1-8b-instant",
        description="Model used by LLM judge for borderline cases",
    )
    REDIS_URL: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL for session storage",
    )
    BLOCK_THRESHOLD: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Combined score above which requests are blocked",
    )
    REGEX_HARD_BLOCK: float = Field(
        default=0.90,
        ge=0.0,
        le=1.0,
        description="Regex-only score above which request is blocked without ML",
    )
    ML_ENABLED: bool = Field(default=True, description="Whether ML classifier is used")
    ML_MODEL_PATH: str = Field(
        default="./injection-classifier",
        description="Path to custom DistilBERT classifier directory",
    )
    LLM_JUDGE_ENABLED: bool = Field(
        default=True,
        description="Whether LLM judge is used for borderline scores",
    )
    SESSION_TTL: int = Field(
        default=3600,
        ge=60,
        le=86400,
        description="Session TTL in seconds for Redis",
    )
    DEFAULT_TENANT_ID: str = Field(
        default="default",
        min_length=1,
        description="Tenant ID when X-Tenant-ID header is missing (multi-tenant)",
    )


def get_settings() -> Settings:
    """Load and return application settings. Raises if required vars missing."""
    try:
        return Settings()
    except Exception as e:
        logger.error("Failed to load settings: %s", e)
        raise


settings: Optional[Settings] = None


def init_settings() -> Settings:
    """Initialize global settings. Call once at startup."""
    global settings
    settings = get_settings()
    return settings
