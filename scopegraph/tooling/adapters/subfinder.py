from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers.assets import normalize_domain, registrable_root_domain
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.tooling.base import AdapterContext, OutputParseError, ToolAdapter, ToolManifest
from scopegraph.tooling.jsonl import read_jsonl


class SubfinderInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_domain: str = Field(min_length=1, max_length=253)

    @field_validator("root_domain")
    @classmethod
    def normalize_root(cls, value: str) -> str:
        return registrable_root_domain(value)


class SubfinderAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="subfinder",
        category="domain_discovery",
        execution_modes=("docker", "host", "fixture"),
        input_types=("root_domain",),
        output_types=("domain_observation",),
        preferred_output="jsonl",
        version_command=("subfinder", "-version"),
        version_markers=("subfinder", "current version"),
        timeout_seconds=1800,
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        return SubfinderInput.model_validate(payload)

    def build_command(self, validated_input: BaseModel) -> list[str]:
        data = cast(SubfinderInput, validated_input)
        return ["subfinder", "-d", data.root_domain, "-json", "-silent"]

    def stdin_bytes(self, validated_input: BaseModel) -> None:
        return None

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        observations: list[ObservationPayload] = []
        for line_number, record in read_jsonl(path):
            raw_host = record.get("host")
            if not isinstance(raw_host, str):
                raise OutputParseError(f"subfinder line {line_number} has no string host")
            host = normalize_domain(raw_host)
            raw_root = record.get("input")
            root = (
                registrable_root_domain(raw_root)
                if isinstance(raw_root, str)
                else registrable_root_domain(host)
            )
            observations.append(
                ObservationPayload(
                    project_id=context.project_id,
                    scan_run_id=context.scan_run_id,
                    source_tool=self.manifest.name,
                    source_version=context.source_version,
                    observed_at=datetime.now(UTC),
                    subject=ObservationObject(type=AssetType.DOMAIN, value=root),
                    predicate="HAS_SUBDOMAIN",
                    object=ObservationObject(type=AssetType.DOMAIN, value=host),
                    attributes={"sources": record.get("source", [])},
                    raw_artifact_path=context.raw_artifact_path,
                )
            )
        return observations
