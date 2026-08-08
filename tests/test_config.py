from app.config import Settings


def test_settings_defaults():
    settings = Settings(_env_file=None)
    assert settings.database_path == "./data/alerts.db"
    assert settings.log_level == "INFO"


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("DATABASE_PATH", "/tmp/custom.db")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
    settings = Settings(_env_file=None)
    assert settings.database_path == "/tmp/custom.db"
    assert settings.log_level == "DEBUG"


def test_settings_abuseipdb_api_key_defaults_to_none():
    settings = Settings(_env_file=None)
    assert settings.abuseipdb_api_key is None


def test_settings_abuseipdb_api_key_env_override(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-key-123")
    settings = Settings(_env_file=None)
    assert settings.abuseipdb_api_key == "test-key-123"
