from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    database_url: str
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    ollama_timeout: float = 180.0

    cisco_ssh_username: str | None = None
    cisco_ssh_password: str | None = None
    cisco_ssh_secret: str | None = None
    fortinet_ssh_username: str | None = None
    fortinet_ssh_password: str | None = None
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

settings = Settings()
