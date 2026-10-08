import os
from typing import List
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Centralized configuration management for Backend Security Core.
    Validates environment settings during application startup.
    """
    # Application Info
    PROJECT_NAME: str = "Backend Security Core"
    PROJECT_VERSION: str = "1.0.0"
    APP_ENV: str = Field(default="development", description="Environment: development, test, staging, production")
    API_PORT: int = Field(default=8000, description="Listening port for backend")
    DEBUG: bool = Field(default=True, description="Enable debug mode")

    # Database
    DATABASE_URL: str = Field(
        default="sqlite:///./security_core.db",
        description="Database connection string (SQLite or PostgreSQL)"
    )

    # Authentication & Cryptography
    JWT_SECRET: str = Field(
        default="dev-insecure-jwt-secret-replace-in-production-only-key-32chars",
        description="Secret key used for signing JWT tokens"
    )
    JWT_ALGORITHM: str = Field(default="HS256", description="Algorithm for JWT encryption")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=1440, description="Token validity duration in minutes")

    # Integrations
    AI_VIDEO_SERVICE_URL: str = Field(
        default="http://localhost:8010",
        description="Base URL for AI Video ingestion & inference service"
    )
    AI_AGENT_SERVICE_URL: str = Field(
        default="http://localhost:8020",
        description="Base URL for AI Agent / Reasoning engine"
    )
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for caching and pub/sub event bus"
    )
    STORAGE_URL: str = Field(
        default="http://localhost:9000/evidence",
        description="Object storage URL for evidentiary clips and snapshots"
    )

    # CORS Configuration
    CORS_ORIGINS: str = Field(
        default="http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173",
        description="Comma-delimited CORS allowed origins"
    )

    # Seeding / Demo
    DEMO_MODE: bool = Field(default=True, description="Enable deterministic mock/demo seeds")

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]

    @field_validator("JWT_SECRET")
    @classmethod
    def validate_jwt_secret(cls, v: str, info) -> str:
        # Enforce minimum length and avoid insecure default in production
        env = os.getenv("APP_ENV", "development").lower()
        if env == "production":
            if "dev-insecure" in v or len(v) < 32:
                raise ValueError("In production, JWT_SECRET must be a secure key with at least 32 characters")
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
