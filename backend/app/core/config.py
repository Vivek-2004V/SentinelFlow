from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelFlow"
    environment: str = "development"
    api_version: str = "v1"

    cors_origins: str = "http://localhost:3000"

    max_upload_size_mb: int = 50
    processing_timeout_seconds: int = 30

    model_dir: str = "../models"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )


settings = Settings()
