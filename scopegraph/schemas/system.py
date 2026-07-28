from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.security import normalize_proxy_url


class ToolStatusRead(BaseModel):
    name: str
    category: str
    installed: bool
    installation_path: str | None
    version_output: str | None
    compatible: bool
    minimum_version: str | None
    automatic_update: bool = False
    error: str | None = None


class ToolUpdateRequest(BaseModel):
    confirmation: bool


class ToolUpdateRead(BaseModel):
    name: str
    update_performed: bool = False
    manual_required: bool = True
    message: str


class SystemSettingsRead(BaseModel):
    proxy_url: str | None = None
    proxy_credentials_supported: bool = False
    public_bind: bool
    api_key_configured: bool


class SystemSettingsPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proxy_url: str | None = Field(default=None, max_length=2048)

    @field_validator("proxy_url")
    @classmethod
    def validate_proxy(cls, value: str | None) -> str | None:
        return normalize_proxy_url(value) if value else None
