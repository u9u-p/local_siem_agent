from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_path: str = "./data/alerts.db"
    log_level: str = "INFO"
    abuseipdb_api_key: str | None = None
    wazuh_indexer_url: str | None = None
    wazuh_indexer_username: str | None = None
    wazuh_indexer_password: str | None = None
    wazuh_manager_url: str | None = None
    wazuh_manager_username: str | None = None
    wazuh_manager_password: str | None = None
    wazuh_verify_ssl: bool = False
    llm_base_url: str = "http://localhost:11434/v1/"
    llm_model: str = "qwen3.5:9b"
    llm_timeout_seconds: float = 120.0


def get_settings() -> Settings:
    return Settings()
