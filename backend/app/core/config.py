from __future__ import annotations

from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SentinelFlow"
    environment: str = "development"
    env: str = "development"
    api_version: str = "v1"

    allowed_origins: list[str] = [
        "https://sentinelflow.vercel.app",
        "https://www.sentinelflow.vercel.app",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ]
    cors_origins: str = "https://sentinelflow.vercel.app,https://www.sentinelflow.vercel.app,http://localhost:3000,http://127.0.0.1:3000"
    api_key: str = "sentinelflow-soc-dev-key"
    enforce_api_key: bool = False

    max_upload_size_mb: int = 50
    processing_timeout_seconds: int = 30

    model_dir: str = "../models"

    # LLM Explainer Provider Settings (Ollama / Local / OpenAI / Gemini / Fallback)
    llm_provider: str = "fallback"  # fallback | ollama | openai | gemini
    llm_model: str = "llama3.2"
    ollama_base_url: str = "http://localhost:11434"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    openai_api_key: Optional[str] = None
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4o-mini"
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-1.5-flash"
    llm_timeout_seconds: float = 30.0

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    def get_cors_origins(self) -> list[str]:
        """
        Parse and sanitize allowed CORS origins.
        Strictly prevents wildcard origins in production environments.
        """
        combined = set(self.allowed_origins)
        for o in self.cors_origins.split(","):
            if o.strip():
                combined.add(o.strip())

        origins = sorted(combined)
        is_prod = self.environment.lower() == "production" or self.env.lower() == "production"
        if is_prod:
            # Disallow wildcard in production
            filtered = [o for o in origins if o != "*"]
            return filtered or ["https://sentinelflow.vercel.app"]
        return origins


settings = Settings()
