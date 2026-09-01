import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType, FindingSeverity
from scopegraph.normalizers import (
    NormalizationError,
    normalize_domain,
    normalize_ip,
    normalize_url,
)
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.security import normalize_proxy_url
from scopegraph.tooling.base import (
    AdapterContext,
    OutputParseError,
    ParsedObservations,
    ToolAdapter,
    ToolManifest,
)

ALLOWED_TAGS = ("tech", "exposure", "misconfig", "ssl", "cve", "vulnerability")
BLOCKED_TAGS = ("dos", "fuzz", "file-upload", "default-login", "intrusive", "rce")
BLOCKED_PROTOCOLS = ("code", "file", "headless", "javascript", "whois")
_BUNDLED_TEMPLATE_DIRECTORY = Path("/app/nuclei-templates")
_MAX_RAW_ARTIFACT_BYTES = 100 * 1024 * 1024
_NON_FATAL_LOG_PREFIXES = ("[INF]", "[WRN]", "[VER]", "[DBG]")
_FATAL_LOG_PREFIXES = ("[FTL]", "[ERR]")


def _nuclei_records(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], dict[str, int]]:
    """Read Nuclei JSONL without mistaking its own diagnostics for findings.

    Nuclei 3.x can emit an engine-version banner and other diagnostic lines to
    stdout even when ``-jsonl`` is selected.  The generic JSONL parser is
    intentionally strict for other adapters; this small, Nuclei-specific
    boundary keeps a harmless banner from discarding an otherwise successful
    result set while still rejecting unknown malformed output.
    """

    if path.stat().st_size > _MAX_RAW_ARTIFACT_BYTES:
        raise OutputParseError(
            f"Raw artifact exceeds parser limit of {_MAX_RAW_ARTIFACT_BYTES} bytes"
        )

    records: list[tuple[int, dict[str, Any]]] = []
    diagnostics: dict[str, int] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            content = line.strip()
            if not content:
                continue
            try:
                value = json.loads(content)
            except json.JSONDecodeError as exc:
                if content.startswith(_NON_FATAL_LOG_PREFIXES):
                    diagnostics["parser_skipped_diagnostic_lines"] = (
                        diagnostics.get("parser_skipped_diagnostic_lines", 0) + 1
                    )
                    continue
                if content.startswith(_FATAL_LOG_PREFIXES):
                    raise OutputParseError(
                        f"Nuclei reported an error at line {line_number}: {content[:500]}"
                    ) from exc
                raise OutputParseError(
                    f"Invalid Nuclei JSONL at line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise OutputParseError(f"Expected an object at Nuclei JSONL line {line_number}")
            if "template-id" not in value and "level" in value and "message" in value:
                level = str(value.get("level", "")).casefold()
                if level in {"fatal", "error"}:
                    raise OutputParseError(
                        f"Nuclei reported a structured {level} diagnostic at line {line_number}"
                    )
                diagnostics["parser_skipped_diagnostic_records"] = (
                    diagnostics.get("parser_skipped_diagnostic_records", 0) + 1
                )
                continue
            records.append((line_number, value))
    return records, diagnostics


def _finding_subject(record: dict[str, Any]) -> ObservationObject:
    candidates = [record.get("url"), record.get("host"), record.get("matched-at")]
    for candidate in candidates:
        if not isinstance(candidate, str):
            continue
        try:
            return ObservationObject(type=AssetType.URL, value=normalize_url(candidate))
        except NormalizationError:
            continue

    raw_host = next((item for item in candidates if isinstance(item, str) and item), None)
    if raw_host is None:
        raise OutputParseError("Nuclei record does not identify a target")
    hostname = urlsplit(f"//{raw_host}").hostname or raw_host
    try:
        return ObservationObject(type=AssetType.DOMAIN, value=normalize_domain(hostname))
    except NormalizationError:
        try:
            return ObservationObject(type=AssetType.IP, value=normalize_ip(hostname))
        except NormalizationError as exc:
            raise OutputParseError("Nuclei target is not a supported URL, domain, or IP") from exc


class NucleiInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    urls: list[str] = Field(min_length=1, max_length=10_000)
    concurrency: int = Field(default=10, ge=1, le=25)
    rate: int = Field(default=20, ge=1, le=100)
    timeout_seconds: int = Field(default=10, ge=3, le=30)
    strategy: Literal["automatic", "broad"] = "automatic"
    proxy_url: str | None = None

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_url(value) for value in values))

    @field_validator("proxy_url")
    @classmethod
    def validate_proxy(cls, value: str | None) -> str | None:
        return normalize_proxy_url(value) if value else None


class NucleiAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="nuclei",
        category="safe_security_discovery",
        execution_modes=("docker", "host", "fixture"),
        input_types=("authorized_url_batch",),
        output_types=("unverified_finding_observation",),
        preferred_output="jsonl",
        version_command=("nuclei", "-version"),
        version_markers=("nuclei",),
        timeout_seconds=1_800,
        minimum_version="3.4.0",
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        return NucleiInput.model_validate(payload)

    def build_command(self, validated_input: BaseModel) -> list[str]:
        data = cast(NucleiInput, validated_input)
        command = [
            self.require_installed(),
            "-jsonl",
            "-silent",
            "-disable-update-check",
            "-exclude-tags",
            ",".join(BLOCKED_TAGS),
            "-exclude-type",
            ",".join(BLOCKED_PROTOCOLS),
            "-severity",
            ",".join(
                item.value
                for item in FindingSeverity
                if item not in {FindingSeverity.INFO, FindingSeverity.UNKNOWN}
            ),
            "-concurrency",
            str(data.concurrency),
            "-rate-limit",
            str(data.rate),
            "-timeout",
            str(data.timeout_seconds),
            "-retries",
            "0",
            "-max-host-error",
            "10",
            "-bulk-size",
            str(data.concurrency),
            "-probe-concurrency",
            str(min(100, data.concurrency * 2)),
            "-no-interactsh",
            "-restrict-local-network-access",
        ]
        if data.strategy == "automatic":
            # Nuclei first fingerprints each host and then loads only templates
            # mapped to the detected technologies. This avoids the previous
            # sites x whole-template-corpus explosion.
            command.append("-automatic-scan")
        else:
            command.extend(["-tags", ",".join(ALLOWED_TAGS)])
        # Nuclei reads targets from stdin when neither -u nor -list is supplied.
        # `-list -` is interpreted as a literal filename by Nuclei 3.8 and makes
        # every scan fail before the first request. Docker images include a
        # pinned template set; host installs can continue using their normal
        # Nuclei template discovery path.
        if _BUNDLED_TEMPLATE_DIRECTORY.is_dir():
            command.extend(["-templates", str(_BUNDLED_TEMPLATE_DIRECTORY)])
        if data.proxy_url:
            command.extend(["-proxy", data.proxy_url])
        return command

    def stdin_bytes(self, validated_input: BaseModel) -> bytes:
        data = cast(NucleiInput, validated_input)
        return ("\n".join(data.urls) + "\n").encode()

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        observations: list[ObservationPayload] = []
        records, diagnostics = _nuclei_records(path)
        for _, record in records:
            template_id = record.get("template-id")
            info = record.get("info")
            if not isinstance(template_id, str) or not isinstance(info, dict):
                raise OutputParseError("Nuclei record is missing template-id or info")
            subject = _finding_subject(record)
            severity_value = str(info.get("severity") or "unknown").casefold()
            severity = (
                FindingSeverity(severity_value)
                if severity_value in FindingSeverity
                else FindingSeverity.UNKNOWN
            )
            tags = [str(item).casefold() for item in info.get("tags", []) if isinstance(item, str)]
            if any(tag in BLOCKED_TAGS for tag in tags):
                raise OutputParseError("Nuclei output contains a blocked template tag")
            observed_at = datetime.now(UTC)
            timestamp = record.get("timestamp")
            if isinstance(timestamp, str):
                try:
                    observed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except ValueError:
                    pass
            observations.append(
                ObservationPayload(
                    project_id=context.project_id,
                    scan_run_id=context.scan_run_id,
                    source_tool="nuclei",
                    source_version=context.source_version,
                    observed_at=observed_at,
                    subject=subject,
                    predicate="HAS_FINDING",
                    attributes={
                        "template_id": template_id[:300],
                        "template_name": str(info.get("name") or template_id)[:500],
                        "severity": severity.value,
                        "matched_at": str(record.get("matched-at") or subject.value)[:4096],
                        "matcher_name": str(record.get("matcher-name") or "")[:300],
                        "tags": tags[:50],
                        "finding_status": "UNVERIFIED",
                    },
                    raw_artifact_path=context.raw_artifact_path,
                    confidence=0.5,
                )
            )
        return ParsedObservations(observations, diagnostics=diagnostics)
