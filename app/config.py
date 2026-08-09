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


def get_settings() -> Settings:
    return Settings()
