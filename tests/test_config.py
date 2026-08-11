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


def test_settings_wazuh_fields_default_to_none_and_verify_ssl_false():
    settings = Settings(_env_file=None)
    assert settings.wazuh_indexer_url is None
    assert settings.wazuh_indexer_username is None
    assert settings.wazuh_indexer_password is None
    assert settings.wazuh_manager_url is None
    assert settings.wazuh_manager_username is None
    assert settings.wazuh_manager_password is None
    assert settings.wazuh_verify_ssl is False


def test_settings_wazuh_fields_env_override(monkeypatch):
    monkeypatch.setenv("WAZUH_INDEXER_URL", "https://localhost:9200")
    monkeypatch.setenv("WAZUH_INDEXER_USERNAME", "admin")
    monkeypatch.setenv("WAZUH_INDEXER_PASSWORD", "test-password")
    monkeypatch.setenv("WAZUH_MANAGER_URL", "https://localhost:55000")
    monkeypatch.setenv("WAZUH_MANAGER_USERNAME", "wazuh-wui")
    monkeypatch.setenv("WAZUH_MANAGER_PASSWORD", "test-password-2")
    monkeypatch.setenv("WAZUH_VERIFY_SSL", "true")
    settings = Settings(_env_file=None)
    assert settings.wazuh_indexer_url == "https://localhost:9200"
    assert settings.wazuh_indexer_username == "admin"
    assert settings.wazuh_indexer_password == "test-password"
    assert settings.wazuh_manager_url == "https://localhost:55000"
    assert settings.wazuh_manager_username == "wazuh-wui"
    assert settings.wazuh_manager_password == "test-password-2"
    assert settings.wazuh_verify_ssl is True


def test_settings_llm_fields_have_expected_defaults():
    settings = Settings(_env_file=None)
    assert settings.llm_base_url == "http://localhost:11434/v1/"
    assert settings.llm_model == "gemma4:12b"
    assert settings.llm_timeout_seconds == 120.0


def test_settings_llm_fields_env_override(monkeypatch):
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:9999/v1/")
    monkeypatch.setenv("LLM_MODEL", "some-other-model:latest")
    monkeypatch.setenv("LLM_TIMEOUT_SECONDS", "30")
    settings = Settings(_env_file=None)
    assert settings.llm_base_url == "http://localhost:9999/v1/"
    assert settings.llm_model == "some-other-model:latest"
    assert settings.llm_timeout_seconds == 30.0


def test_settings_virustotal_api_key_defaults_to_none():
    settings = Settings(_env_file=None)
    assert settings.virustotal_api_key is None


def test_settings_virustotal_api_key_env_override(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    settings = Settings(_env_file=None)
    assert settings.virustotal_api_key == "test-vt-key"
