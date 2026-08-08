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
