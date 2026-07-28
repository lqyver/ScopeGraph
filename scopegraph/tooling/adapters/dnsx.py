import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers.assets import normalize_domain
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.tooling.base import AdapterContext, OutputParseError, ToolAdapter, ToolManifest
from scopegraph.tooling.jsonl import read_jsonl
from scopegraph.tooling.network_policy import direct_resolver_argument, is_environment_mapping_ip


class DnsxInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domains: list[str] = Field(min_length=1, max_length=10_000)

    @field_validator("domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_domain(value) for value in values))


class DnsxAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="dnsx",
        category="dns_enrichment",
        execution_modes=("docker", "host", "fixture"),
        input_types=("domain_batch",),
        output_types=("dns_observation",),
        preferred_output="jsonl",
        version_command=("dnsx", "-version"),
        version_markers=("dnsx", "current version"),
        timeout_seconds=900,
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        return DnsxInput.model_validate(payload)

    def build_command(self, validated_input: BaseModel) -> list[str]:
        return ["dnsx", "-json", "-silent", "-r", direct_resolver_argument()]

    def stdin_bytes(self, validated_input: BaseModel) -> bytes:
        data = cast(DnsxInput, validated_input)
        return ("\n".join(data.domains) + "\n").encode()

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        observations: list[ObservationPayload] = []
        for line_number, record in read_jsonl(path):
            raw_host = record.get("host")
            if not isinstance(raw_host, str):
                raise OutputParseError(f"dnsx line {line_number} has no string host")
            host = normalize_domain(raw_host)
            observations.extend(self._address_observations(host, record, context))
            observations.extend(self._cname_observations(host, record, context))
            observations.extend(self._additional_record_observations(host, record, context))
        return observations

    def _address_observations(
        self, host: str, record: dict[str, Any], context: AdapterContext
    ) -> list[ObservationPayload]:
        results: list[ObservationPayload] = []
        for record_type, asset_type in (("a", AssetType.IP), ("aaaa", AssetType.IP)):
            values = record.get(record_type, [])
            if not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, str) and not is_environment_mapping_ip(value):
                    results.append(
                        self._observation(
                            host,
                            "RESOLVES_TO",
                            asset_type,
                            value,
                            {
                                "record_type": record_type.upper(),
                                "record_value": value,
                                "ttl": record.get("ttl"),
                                "resolver": record.get("resolver"),
                                "cname": record.get("cname"),
                            },
                            context,
                        )
                    )
        return results

    def _cname_observations(
        self, host: str, record: dict[str, Any], context: AdapterContext
    ) -> list[ObservationPayload]:
        values = record.get("cname", [])
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, list):
            return []
        return [
            self._observation(
                host,
                "CNAME_TO",
                AssetType.DOMAIN,
                value,
                {
                    "record_type": "CNAME",
                    "record_value": value,
                    "ttl": record.get("ttl"),
                    "resolver": record.get("resolver"),
                },
                context,
            )
            for value in values
            if isinstance(value, str)
        ]

    def _observation(
        self,
        host: str,
        predicate: str,
        object_type: AssetType,
        object_value: str,
        attributes: dict[str, Any],
        context: AdapterContext,
    ) -> ObservationPayload:
        return ObservationPayload(
            project_id=context.project_id,
            scan_run_id=context.scan_run_id,
            source_tool=self.manifest.name,
            source_version=context.source_version,
            observed_at=datetime.now(UTC),
            subject=ObservationObject(type=AssetType.DOMAIN, value=host),
            predicate=predicate,
            object=ObservationObject(type=object_type, value=object_value),
            attributes=attributes,
            raw_artifact_path=context.raw_artifact_path,
        )

    def _additional_record_observations(
        self, host: str, record: dict[str, Any], context: AdapterContext
    ) -> list[ObservationPayload]:
        observations: list[ObservationPayload] = []
        for record_type in ("MX", "NS", "TXT", "SOA", "PTR"):
            for raw_value in self._record_values(record.get(record_type.casefold())):
                value = raw_value
                object_value: str | None = None
                if record_type in {"MX", "NS", "PTR"}:
                    candidate = raw_value.rsplit(maxsplit=1)[-1].rstrip(".")
                    try:
                        object_value = normalize_domain(candidate)
                    except ValueError as exc:
                        raise OutputParseError(
                            f"dnsx {record_type} record has an invalid domain target"
                        ) from exc
                    value = object_value
                if len(value) > 4096:
                    raise OutputParseError(f"dnsx {record_type} record exceeds storage limit")
                observations.append(
                    ObservationPayload(
                        project_id=context.project_id,
                        scan_run_id=context.scan_run_id,
                        source_tool=self.manifest.name,
                        source_version=context.source_version,
                        observed_at=datetime.now(UTC),
                        subject=ObservationObject(type=AssetType.DOMAIN, value=host),
                        predicate="HAS_DNS_RECORD",
                        object=(
                            ObservationObject(type=AssetType.DOMAIN, value=object_value)
                            if object_value
                            else None
                        ),
                        attributes={
                            "record_type": record_type,
                            "record_value": value,
                            "ttl": record.get("ttl"),
                            "resolver": record.get("resolver"),
                        },
                        raw_artifact_path=context.raw_artifact_path,
                    )
                )
        return observations

    @staticmethod
    def _record_values(raw: Any) -> list[str]:
        if raw is None:
            return []
        values = raw if isinstance(raw, list) else [raw]
        normalized: list[str] = []
        for value in values:
            if isinstance(value, str):
                normalized.append(value)
            elif isinstance(value, dict):
                candidate = next(
                    (
                        value[key]
                        for key in ("host", "name", "target", "exchange", "value")
                        if isinstance(value.get(key), str)
                    ),
                    None,
                )
                normalized.append(
                    candidate
                    if candidate is not None
                    else json.dumps(value, ensure_ascii=True, sort_keys=True)
                )
        return normalized
