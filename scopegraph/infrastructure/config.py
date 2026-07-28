from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SCOPEGRAPH_",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    app_name: str = "ScopeGraph"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql+asyncpg://scopegraph:scopegraph@127.0.0.1:5432/scopegraph"
    redis_url: str = "redis://127.0.0.1:6379/0"
    data_root: Path = Path("data")
    api_url: str = Field(default="http://127.0.0.1:8000")
    public_bind: bool = False
    api_key: SecretStr | None = None
    mcp_host: str = "127.0.0.1"
    mcp_port: int = Field(default=8001, ge=1, le=65535)
    mcp_transport: Literal["stdio", "streamable-http"] = "stdio"
    mcp_allow_scan_start: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
