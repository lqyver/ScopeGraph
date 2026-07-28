from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers.assets import normalize_domain, registrable_root_domain
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.tooling.base import AdapterContext, OutputParseError, ToolAdapter, ToolManifest


class AlterxInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domains: list[str] = Field(min_length=1, max_length=10_000)
    limit: int = Field(default=500, ge=1, le=5_000)

    @field_validator("domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_domain(value) for value in values))


class AlterxAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="alterx",
        category="domain_permutation",
        execution_modes=("docker", "host", "fixture"),
        input_types=("domain_batch",),
        output_types=("candidate_domain_observation",),
        preferred_output="text",
        version_command=("alterx", "-version"),
        version_markers=("alterx", "current version"),
        timeout_seconds=900,
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        return AlterxInput.model_validate(payload)

    def build_command(self, validated_input: BaseModel) -> list[str]:
        data = cast(AlterxInput, validated_input)
        return ["alterx", "-silent", "-limit", str(data.limit)]

    def stdin_bytes(self, validated_input: BaseModel) -> bytes:
        data = cast(AlterxInput, validated_input)
        return ("\n".join(data.domains) + "\n").encode()

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        if path.stat().st_size > 100 * 1024 * 1024:
            raise OutputParseError("AlterX artifact exceeds parser limit")
        observations: list[ObservationPayload] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                normalized = normalize_domain(line)
                root = registrable_root_domain(normalized)
            except ValueError as exc:
                raise OutputParseError(f"alterx line {line_number} is not a domain") from exc
            observations.append(
                ObservationPayload(
                    project_id=context.project_id,
                    scan_run_id=context.scan_run_id,
                    source_tool=self.manifest.name,
                    source_version=context.source_version,
                    observed_at=datetime.now(UTC),
                    subject=ObservationObject(type=AssetType.DOMAIN, value=root),
                    predicate="GENERATED_VARIANT",
                    object=ObservationObject(type=AssetType.DOMAIN, value=normalized),
                    attributes={"validated": False},
                    raw_artifact_path=context.raw_artifact_path,
                    confidence=0.2,
                )
            )
        return observations
