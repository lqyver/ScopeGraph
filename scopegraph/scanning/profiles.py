import json
import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import ScanProfile

SAFE_WEB_PORTS = (80, 443, 8080, 8443)


class ScanProfileConfig(BaseModel):
    """Validated execution policy; fields map to known adapter options only."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    passive_subdomain: bool = True
    domain_variants: bool = False
    dns_bruteforce: bool = False
    dns_enrichment: bool = True
    port_scan_enabled: bool = False
    service_detection: bool = False
    http_probe: bool = True
    dns_wordlist_limit: int = Field(default=0, ge=0, le=100_000)
    variant_limit: int = Field(default=0, ge=0, le=5_000)
    resolver_count: int = Field(default=5, ge=1, le=50)
    dns_rate: int = Field(default=500, ge=1, le=10_000)
    ports: tuple[int, ...] = SAFE_WEB_PORTS
    port_rate: int = Field(default=200, ge=1, le=5_000)
    port_concurrency: int = Field(default=20, ge=1, le=100)
    job_timeout_seconds: int = Field(default=600, ge=30, le=3_600)
    max_assets: int = Field(default=10_000, ge=1, le=1_000_000)
    http_concurrency: int = Field(default=30, ge=1, le=100)
    http_rate: int = Field(default=50, ge=1, le=500)
    http_timeout_seconds: int = Field(default=15, ge=3, le=60)
    max_redirects: int = Field(default=3, ge=0, le=10)
    max_response_body_bytes: int = Field(default=2_097_152, ge=65_536, le=10_485_760)
    screenshot_enabled: bool = True
    crawler_enabled: bool = False
    crawler_depth: int = Field(default=1, ge=1, le=5)
    crawler_max_urls_per_site: int = Field(default=200, ge=1, le=10_000)
    crawler_max_duration_seconds: int = Field(default=300, ge=30, le=1_800)
    crawler_rate: int = Field(default=20, ge=1, le=100)
    icp_extraction: bool = True
    nuclei_allowed: bool = False
    nuclei_strategy: Literal["automatic", "broad"] = "automatic"
    nuclei_concurrency: int = Field(default=10, ge=1, le=25)
    nuclei_rate: int = Field(default=20, ge=1, le=100)
    nuclei_timeout_seconds: int = Field(default=10, ge=3, le=30)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if len(value) > 1_000:
            raise ValueError("A profile may select at most 1000 ports")
        if any(port < 1 or port > 65_535 for port in value):
            raise ValueError("Ports must be between 1 and 65535")
        if len(set(value)) != len(value):
            raise ValueError("Ports must not contain duplicates")
        return tuple(sorted(value))


def _profile_directory() -> Path:
    configured = os.getenv("SCOPEGRAPH_SCAN_PROFILE_DIR")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[2] / "configs" / "scan_profiles"


def load_profile(
    profile: ScanProfile, custom_config: dict[str, Any] | None = None
) -> ScanProfileConfig:
    if profile is ScanProfile.CUSTOM:
        if custom_config is None:
            raise ValueError("custom_config is required for the custom profile")
        return ScanProfileConfig.model_validate(custom_config)
    if custom_config is not None:
        raise ValueError("custom_config is only valid for the custom profile")

    path = _profile_directory() / f"{profile.value}.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(f"Scan profile configuration is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Scan profile configuration is invalid JSON: {path}") from exc
    return ScanProfileConfig.model_validate(payload)
