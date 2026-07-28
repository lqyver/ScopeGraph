import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers.assets import NormalizationError, normalize_url
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.security import normalize_proxy_url
from scopegraph.tooling.base import AdapterContext, OutputParseError, ToolAdapter, ToolManifest
from scopegraph.tooling.network_policy import direct_resolver_argument

_DENIED_NETWORKS = (
    "0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,"
    "172.16.0.0/12,192.168.0.0/16,198.18.0.0/15,224.0.0.0/4,::/128,::1/128,fc00::/7,"
    "fe80::/10,ff00::/8"
)


class ScreenshotInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    urls: list[str] = Field(min_length=1, max_length=10_000)
    concurrency: int = Field(default=2, ge=1, le=5)
    rate: int = Field(default=5, ge=1, le=20)
    timeout_seconds: int = Field(default=20, ge=5, le=60)
    max_redirects: int = Field(default=3, ge=0, le=10)
    proxy_url: str | None = None

    @field_validator("urls")
    @classmethod
    def normalize_urls(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_url(value) for value in values))

    @field_validator("proxy_url")
    @classmethod
    def validate_proxy(cls, value: str | None) -> str | None:
        return normalize_proxy_url(value) if value else None


def _safe_relative_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or len(value) > 1_024:
        return None
    normalized = value.replace("\\", "/")
    # httpx emits an absolute path when its screenshot directory is absolute.
    # Store only the job-attempt-relative suffix so WebSnapshot remains both
    # portable and confined to ScopeGraph's data root.
    marker = "/screenshots/screenshot/"
    if normalized.startswith("/"):
        marker_index = normalized.find(marker)
        if marker_index < 0:
            return None
        normalized = normalized[marker_index + 1 :]
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        return None
    return path.as_posix()


def _screenshot_records(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Read httpx JSONL while isolating a concurrently interleaved record.

    Some httpx releases can interleave two JSON records on stdout when more
    than one screenshot worker finishes at the same time. Normal JSONL stays
    strict; for a malformed line we recover only complete top-level objects
    that independently contain a URL. This prevents one corrupt line from
    discarding every otherwise valid screenshot in the job.
    """

    if path.stat().st_size > 100 * 1024 * 1024:
        raise OutputParseError("Screenshot artifact exceeds parser limit")
    decoder = json.JSONDecoder()
    nonempty_lines = 0
    yielded = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        nonempty_lines += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            seen: set[str] = set()
            for offset, character in enumerate(line):
                if character != "{":
                    continue
                try:
                    candidate, _ = decoder.raw_decode(line[offset:])
                except json.JSONDecodeError:
                    continue
                if not isinstance(candidate, dict) or not isinstance(
                    candidate.get("url") or candidate.get("input"), str
                ):
                    continue
                identity = json.dumps(candidate, sort_keys=True, separators=(",", ":"))
                if identity in seen:
                    continue
                seen.add(identity)
                yielded += 1
                yield line_number, candidate
            continue
        if not isinstance(record, dict):
            raise OutputParseError(f"screenshot line {line_number} must be a JSON object")
        yielded += 1
        yield line_number, record
    if nonempty_lines and yielded == 0:
        raise OutputParseError("Screenshot artifact contains no recoverable JSON records")


class ScreenshotAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="screenshot",
        category="website_screenshot",
        execution_modes=("docker", "host", "fixture"),
        input_types=("url_batch",),
        output_types=("screenshot_observation",),
        preferred_output="jsonl",
        version_command=("httpx", "-version"),
        version_markers=("projectdiscovery", "current version"),
        timeout_seconds=1_800,
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        return ScreenshotInput.model_validate(payload)

    def build_command(self, validated_input: BaseModel) -> list[str]:
        data = cast(ScreenshotInput, validated_input)
        command = [
            "httpx",
            "-json",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-screenshot",
            "-system-chrome",
            "-exclude-screenshot-bytes",
            "-exclude-headless-body",
            "-headless-options",
            (
                "--disable-background-networking,--disable-component-update,"
                "--disable-default-apps,--disable-extensions,--disable-sync,"
                "--no-default-browser-check,--no-first-run"
            ),
            "-store-response-dir",
            "screenshots",
            "-follow-host-redirects",
            "-max-redirects",
            str(data.max_redirects),
            "-deny",
            _DENIED_NETWORKS,
            "-r",
            direct_resolver_argument(),
            "-threads",
            str(data.concurrency),
            "-rate-limit",
            str(data.rate),
            "-timeout",
            str(data.timeout_seconds),
        ]
        if data.proxy_url:
            command.extend(["-proxy", data.proxy_url])
        return command

    def stdin_bytes(self, validated_input: BaseModel) -> bytes:
        data = cast(ScreenshotInput, validated_input)
        return ("\n".join(data.urls) + "\n").encode()

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        observations: list[ObservationPayload] = []
        for line_number, record in _screenshot_records(path):
            raw_url = record.get("url") or record.get("input")
            if not isinstance(raw_url, str):
                raise OutputParseError(f"screenshot line {line_number} requires a URL")
            try:
                url = normalize_url(raw_url)
            except NormalizationError as exc:
                raise OutputParseError(
                    f"screenshot line {line_number} contains an invalid URL"
                ) from exc
            path_value = (
                record.get("screenshot_path")
                or record.get("screenshot-path")
                or record.get("screenshot")
            )
            screenshot_path = _safe_relative_path(path_value)
            error = record.get("screenshot_error") or record.get("error")
            observations.append(
                ObservationPayload(
                    project_id=context.project_id,
                    scan_run_id=context.scan_run_id,
                    source_tool=self.manifest.name,
                    source_version=context.source_version,
                    observed_at=datetime.now(UTC),
                    subject=ObservationObject(type=AssetType.URL, value=url),
                    predicate="SCREENSHOT_CAPTURED" if screenshot_path else "SCREENSHOT_FAILED",
                    attributes={
                        "screenshot_path": screenshot_path,
                        "screenshot_error": str(error)[:2_000] if error else None,
                    },
                    raw_artifact_path=context.raw_artifact_path,
                )
            )
        return observations
