import pytest
from src.config.settings import Settings, settings


def test_settings_load_defaults():
    assert settings.PROJECT_NAME == "Backend Security Core"
    assert settings.API_PORT == 8000
    assert "sqlite" in settings.DATABASE_URL or ":memory:" in settings.DATABASE_URL
    assert len(settings.cors_origins_list) > 0


def test_cors_origins_parsing():
    s = Settings(CORS_ORIGINS="http://localhost:3000, http://example.com , ")
    assert s.cors_origins_list == ["http://localhost:3000", "http://example.com"]


def test_production_jwt_secret_validation(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    with pytest.raises(ValueError, match="JWT_SECRET must be a secure key"):
        Settings(
            APP_ENV="production",
            JWT_SECRET="dev-insecure-secret"
        )
