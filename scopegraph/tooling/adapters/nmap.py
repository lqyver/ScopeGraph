import json
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers.assets import normalize_ip
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.tooling.base import AdapterContext, OutputParseError, ToolAdapter, ToolManifest


class NmapTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ip: str
    ports: tuple[int, ...] = Field(min_length=1, max_length=1_000)

    @field_validator("ip")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        return normalize_ip(value)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(value < 1 or value > 65_535 for value in values):
            raise ValueError("Ports must be between 1 and 65535")
        return tuple(sorted(set(values)))


class NmapInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    targets: list[NmapTarget] = Field(min_length=1, max_length=10_000)


def nmap_command(target: NmapTarget) -> list[str]:
    return [
        "nmap",
        "-Pn",
        "-sV",
        "--version-light",
        "--noninteractive",
        "-oX",
        "-",
        "-p",
        ",".join(str(port) for port in target.ports),
        target.ip,
    ]


class NmapAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="nmap",
        category="service_detection",
        execution_modes=("docker", "host", "fixture"),
        input_types=("single_ip_open_ports",),
        output_types=("service_observation",),
        preferred_output="xml",
        version_command=("nmap", "--version"),
        version_markers=("nmap version",),
        timeout_seconds=1800,
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        return NmapInput.model_validate(payload)

    def build_command(self, validated_input: BaseModel) -> list[str]:
        return [sys.executable, "-m", "scopegraph.tooling.nmap_batch"]

    def stdin_bytes(self, validated_input: BaseModel) -> bytes:
        data = cast(NmapInput, validated_input)
        return json.dumps(data.model_dump(mode="json"), separators=(",", ":")).encode()

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        if path.stat().st_size > 100 * 1024 * 1024:
            raise OutputParseError("Nmap XML artifact exceeds parser limit")
        raw = path.read_bytes()
        folded = raw[:4096].upper()
        if b"<!DOCTYPE" in folded or b"<!ENTITY" in folded:
            raise OutputParseError("Nmap XML contains a forbidden document declaration")
        try:
            # Size, DTD, and entity guards above constrain the stdlib parser input.
            root = ET.fromstring(raw)  # noqa: S314
        except ET.ParseError as exc:
            raise OutputParseError(f"Nmap XML is invalid: {exc}") from exc

        if root.tag == "nmaprun":
            hosts = root.findall("host")
        elif root.tag == "scopegraph-nmap-batch":
            hosts = root.findall("./nmaprun/host")
        else:
            raise OutputParseError("Nmap XML has an unexpected root element")
        observations: list[ObservationPayload] = []
        for host in hosts:
            address = host.find("address[@addrtype='ipv4']")
            if address is None:
                address = host.find("address[@addrtype='ipv6']")
            if address is None or not address.get("addr"):
                continue
            ip = normalize_ip(str(address.get("addr")))
            for port_node in host.findall("./ports/port"):
                state = port_node.find("state")
                if state is None or state.get("state") != "open":
                    continue
                try:
                    port = int(str(port_node.get("portid")))
                except ValueError as exc:
                    raise OutputParseError("Nmap XML contains an invalid port") from exc
                protocol = str(port_node.get("protocol", "tcp")).casefold()
                service = port_node.find("service")
                attributes = {
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                    "state": "OPEN",
                    "name": service.get("name") if service is not None else None,
                    "product": service.get("product") if service is not None else None,
                    "version": service.get("version") if service is not None else None,
                    "tunnel": service.get("tunnel") if service is not None else None,
                    "cpe": service.findtext("cpe") if service is not None else None,
                }
                observations.append(
                    ObservationPayload(
                        project_id=context.project_id,
                        scan_run_id=context.scan_run_id,
                        source_tool=self.manifest.name,
                        source_version=context.source_version,
                        observed_at=datetime.now(UTC),
                        subject=ObservationObject(
                            type=AssetType.SERVICE, value=f"{protocol}://{ip}:{port}"
                        ),
                        predicate="IDENTIFIES_SERVICE",
                        attributes=attributes,
                        raw_artifact_path=context.raw_artifact_path,
                    )
                )
        return observations
