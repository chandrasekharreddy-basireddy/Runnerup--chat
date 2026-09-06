"""Runtime configuration. Every secret arrives from the environment; there are no
defaults that would work in production, so a missing secret fails at boot rather than
silently degrading security."""
from functools import lru_cache
from typing import Literal

from pydantic import Field, PostgresDsn, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"

    # --- cryptographic material -------------------------------------------------
    jwt_signing_key: str
    otp_pepper: str
    cookie_signing_key: str

    access_token_ttl_seconds: int = 600           # 10 minutes
    refresh_token_ttl_seconds: int = 2_592_000    # 30 days
    otp_ttl_seconds: int = 300
    otp_max_attempts: int = 5
    ws_ticket_ttl_seconds: int = 30

    # --- datastores -------------------------------------------------------------
    database_url: PostgresDsn
    db_pool_size: int = 10
    db_max_overflow: int = 10
    redis_url: str

    # --- object storage ---------------------------------------------------------
    s3_endpoint: str
    s3_region: str = "us-east-1"
    s3_bucket: str
    s3_access_key: str
    s3_secret_key: str
    max_upload_bytes: int = 52_428_800            # 50 MiB
    upload_url_ttl_seconds: int = 300
    download_url_ttl_seconds: int = 300

    # --- sms --------------------------------------------------------------------
    sms_provider: Literal["console", "twilio"] = "console"
    sms_api_key: str = ""
    sms_sender_id: str = ""

    # --- web --------------------------------------------------------------------
    allowed_origins: list[str] = Field(default_factory=list)
    public_web_origin: str = "https://localhost"

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _split_origins(cls, v):
        if isinstance(v, str):
            return [o.strip() for o in v.split(",") if o.strip()]
        return v

    @field_validator("jwt_signing_key", "otp_pepper", "cookie_signing_key")
    @classmethod
    def _reject_weak_keys(cls, v: str) -> str:
        if len(v) < 32 or v == "replace-me":
            raise ValueError("signing keys must be at least 32 characters and not the placeholder")
        return v

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def cookie_secure(self) -> bool:
        # Only ever relaxed on a developer's localhost.
        return self.environment != "development"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
