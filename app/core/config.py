from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Video Surveillance Backend"
    app_env: str = "development"
    debug: bool = False

    database_url: str

    jwt_secret_key: str
    jwt_algorithm: str = "HS256"    
    jwt_issuer: str = "video-surveillance-backend"
    jwt_audience: str = "video-surveillance-api"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    allow_public_registration: bool = True

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
