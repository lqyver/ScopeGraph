from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from scopegraph.domain.enums import AssetType, TransportProtocol
from scopegraph.normalizers.assets import normalize_ip
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.tooling.base import (
    AdapterContext,
    OutputParseError,
    ParsedObservations,
    ToolAdapter,
    ToolManifest,
)
from scopegraph.tooling.jsonl import read_jsonl


class NaabuInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ips: list[str] = Field(min_length=1, max_length=10_000)
    ports: tuple[int, ...] = Field(default=(), max_length=1_000)
    full_port_scan: bool = False
    rate: int = Field(default=200, ge=1, le=5_000)
    concurrency: int = Field(default=20, ge=1, le=100)
    policy_summary: dict[str, int] = Field(default_factory=dict)

    @field_validator("ips")
    @classmethod
    def normalize_ips(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_ip(value) for value in values))

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(value < 1 or value > 65_535 for value in values):
            raise ValueError("Ports must be between 1 and 65535")
        return tuple(sorted(set(values)))

    @model_validator(mode="after")
    def validate_port_selection(self) -> "NaabuInput":
        if self.full_port_scan and self.ports:
            raise ValueError("Full-port mode and an explicit port list are mutually exclusive")
        if not self.full_port_scan and not self.ports:
            raise ValueError("An explicit port list is required unless full-port mode is enabled")
        return self


class NaabuAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="naabu",
        category="port_discovery",
        execution_modes=("docker", "host", "fixture"),
        input_types=("ip_port_batch",),
        output_types=("port_observation",),
        preferred_output="jsonl",
        version_command=("naabu", "-version"),
        version_markers=("naabu", "current version"),
        timeout_seconds=1800,
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        return NaabuInput.model_validate(payload)

    def build_command(self, validated_input: BaseModel) -> list[str]:
        data = cast(NaabuInput, validated_input)
        return [
            "naabu",
            "-json",
            "-silent",
            "-no-color",
            "-p",
            "-" if data.full_port_scan else ",".join(str(port) for port in data.ports),
            "-rate",
            str(data.rate),
            "-c",
            str(data.concurrency),
        ]

    def stdin_bytes(self, validated_input: BaseModel) -> bytes:
        data = cast(NaabuInput, validated_input)
        return ("\n".join(data.ips) + "\n").encode()

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        observations: list[ObservationPayload] = []
        endpoints: set[tuple[str, int, TransportProtocol]] = set()
        duplicate_records = 0
        raw_records = 0
        for line_number, record in read_jsonl(path):
            raw_records += 1
            raw_ip = record.get("ip") or record.get("host")
            raw_port = record.get("port")
            raw_protocol = str(record.get("protocol", "tcp")).casefold()
            if not isinstance(raw_ip, str) or not isinstance(raw_port, int):
                raise OutputParseError(f"naabu line {line_number} requires ip and integer port")
            try:
                protocol = TransportProtocol(raw_protocol)
            except ValueError as exc:
                raise OutputParseError(f"naabu line {line_number} has invalid protocol") from exc
            if raw_port < 1 or raw_port > 65_535:
                raise OutputParseError(f"naabu line {line_number} has invalid port")
            ip = normalize_ip(raw_ip)
            endpoint_key = (ip, raw_port, protocol)
            if endpoint_key in endpoints:
                duplicate_records += 1
                continue
            endpoints.add(endpoint_key)
            endpoint = f"{protocol.value}://{ip}:{raw_port}"
            observations.append(
                ObservationPayload(
                    project_id=context.project_id,
                    scan_run_id=context.scan_run_id,
                    source_tool=self.manifest.name,
                    source_version=context.source_version,
                    observed_at=datetime.now(UTC),
                    subject=ObservationObject(type=AssetType.IP, value=ip),
                    predicate="HOSTS_SERVICE",
                    object=ObservationObject(type=AssetType.SERVICE, value=endpoint),
                    attributes={
                        "port": raw_port,
                        "protocol": protocol.value,
                        "state": "OPEN",
                    },
                    raw_artifact_path=context.raw_artifact_path,
                )
            )
        return ParsedObservations(
            observations,
            diagnostics={
                "raw_tool_records": raw_records,
                "duplicate_tool_records": duplicate_records,
                "unique_open_endpoints": len(observations),
            },
        )
