from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers.assets import normalize_domain, registrable_root_domain
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.tooling.base import AdapterContext, OutputParseError, ToolAdapter, ToolManifest


class PurednsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_domain: str = Field(min_length=1, max_length=253)
    candidates: list[str] = Field(min_length=1, max_length=100_000)
    rate: int = Field(default=500, ge=1, le=10_000)

    @field_validator("root_domain")
    @classmethod
    def normalize_root(cls, value: str) -> str:
        return registrable_root_domain(value)

    @field_validator("candidates")
    @classmethod
    def normalize_candidates(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_domain(value) for value in values))


class PurednsAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="puredns",
        category="dns_validation",
        execution_modes=("docker", "host", "fixture"),
        input_types=("candidate_domain_batch",),
        output_types=("validated_domain_observation",),
        preferred_output="text",
        version_command=("puredns", "--version"),
        version_markers=("puredns",),
        timeout_seconds=1800,
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        validated = PurednsInput.model_validate(payload)
        try:
            roots = {registrable_root_domain(value) for value in validated.candidates}
        except ValueError as exc:
            raise ValueError(
                "PureDNS candidates must remain under the authorized root domain"
            ) from exc
        if roots != {validated.root_domain}:
            raise ValueError("PureDNS candidates must remain under the authorized root domain")
        return validated

    def build_command(self, validated_input: BaseModel) -> list[str]:
        data = cast(PurednsInput, validated_input)
        return [
            "puredns",
            "resolve",
            "/dev/stdin",
            "--resolvers",
            "configs/resolvers.txt",
            "--rate-limit",
            str(data.rate),
            "--quiet",
        ]

    def stdin_bytes(self, validated_input: BaseModel) -> bytes:
        data = cast(PurednsInput, validated_input)
        return ("\n".join(data.candidates) + "\n").encode()

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        if path.stat().st_size > 100 * 1024 * 1024:
            raise OutputParseError("PureDNS artifact exceeds parser limit")
        observations: list[ObservationPayload] = []
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                domain = normalize_domain(line)
                root = registrable_root_domain(domain)
            except ValueError as exc:
                raise OutputParseError(f"puredns line {line_number} is not a domain") from exc
            observations.append(
                ObservationPayload(
                    project_id=context.project_id,
                    scan_run_id=context.scan_run_id,
                    source_tool=self.manifest.name,
                    source_version=context.source_version,
                    observed_at=datetime.now(UTC),
                    subject=ObservationObject(type=AssetType.DOMAIN, value=root),
                    predicate="HAS_SUBDOMAIN",
                    object=ObservationObject(type=AssetType.DOMAIN, value=domain),
                    attributes={"dns_validated": True, "wildcard_filtered": True},
                    raw_artifact_path=context.raw_artifact_path,
                    confidence=0.9,
                )
            )
        return observations
