import json
from datetime import datetime
from hashlib import sha256
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers.assets import normalize_asset


class ObservationObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: AssetType
    value: str = Field(min_length=1, max_length=2048)

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str, info: Any) -> str:
        asset_type = info.data.get("type")
        return (
            normalize_asset(asset_type, value).normalized_value
            if isinstance(asset_type, AssetType)
            else value
        )


class ObservationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: UUID
    scan_run_id: UUID
    source_tool: str = Field(min_length=1, max_length=100)
    source_version: str = Field(min_length=1, max_length=100)
    observed_at: datetime
    subject: ObservationObject
    predicate: str = Field(pattern=r"^[A-Z][A-Z0-9_]{1,99}$")
    object: ObservationObject | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_artifact_path: str = Field(min_length=1, max_length=4096)
    confidence: float = Field(default=1.0, ge=0, le=1)

    def observation_hash(self) -> str:
        identity = {
            "object": self.object.model_dump(mode="json") if self.object else None,
            "predicate": self.predicate,
            "project_id": str(self.project_id),
            "scan_run_id": str(self.scan_run_id),
            "source_tool": self.source_tool,
            "subject": self.subject.model_dump(mode="json"),
        }
        canonical = json.dumps(identity, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        return sha256(canonical.encode("utf-8")).hexdigest()
