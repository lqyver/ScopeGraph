from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType, EndpointKind
from scopegraph.normalizers.assets import (
    NormalizationError,
    normalize_url,
    registrable_root_domain,
)
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.security import normalize_proxy_url
from scopegraph.tooling.base import (
    AdapterContext,
    ParsedObservations,
    ToolAdapter,
    ToolManifest,
)
from scopegraph.tooling.jsonl import read_jsonl
from scopegraph.tooling.network_policy import direct_resolver_argument


class KatanaInput(BaseModel):
    """Closed crawl policy mapped only to Katana's non-mutating options."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    urls: list[str] = Field(min_length=1, max_length=10_000)
    depth: int = Field(default=3, ge=1, le=5)
    max_urls_per_site: int = Field(default=2_000, ge=1, le=10_000)
    duration_seconds: int = Field(default=120, ge=15, le=1_800)
    rate: int = Field(default=20, ge=1, le=100)
    concurrency: int = Field(default=5, ge=1, le=10)
    parallelism: int = Field(default=1, ge=1, le=10)
    timeout_seconds: int = Field(default=15, ge=3, le=60)
    max_response_body_bytes: int = Field(default=2_097_152, ge=65_536, le=10_485_760)
    proxy_url: str | None = None

    @field_validator("urls")
    @classmethod
    def normalize_urls(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_url(value) for value in values))

    @field_validator("proxy_url")
    @classmethod
    def validate_proxy(cls, value: str | None) -> str | None:
        return normalize_proxy_url(value) if value else None


def _safe_url(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 4_096:
        return None
    try:
        return normalize_url(value)
    except NormalizationError:
        return None


def _websocket_to_https(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme.casefold() not in {"ws", "wss"} or not parsed.hostname:
        return None
    scheme = "https" if parsed.scheme.casefold() == "wss" else "http"
    return _safe_url(urlunsplit((scheme, parsed.netloc, parsed.path or "/", parsed.query, "")))


def _endpoint_kind(endpoint: str, record: dict[str, Any]) -> EndpointKind:
    parsed = urlsplit(endpoint)
    scheme = parsed.scheme.casefold()
    path = parsed.path.casefold()
    tag = str(record.get("tag") or "").casefold()
    attribute = str(record.get("attribute") or "").casefold()
    if scheme in {"ws", "wss"}:
        return EndpointKind.WEBSOCKET
    if path.endswith("robots.txt"):
        return EndpointKind.ROBOTS
    if path.endswith("sitemap.xml") or "sitemap" in path and path.endswith(".xml"):
        return EndpointKind.SITEMAP
    if path.endswith((".js", ".mjs", ".cjs")) or tag == "script" or attribute == "src":
        return EndpointKind.JAVASCRIPT
    if tag in {"xhr", "fetch"} or str(record.get("type") or "").casefold() in {
        "xhr",
        "fetch",
    }:
        return EndpointKind.XHR
    if "/api/" in path or path.startswith("/api") or path.endswith((".json", ".graphql")):
        return EndpointKind.API
    return EndpointKind.PAGE


def _is_external(source: str, endpoint: str) -> bool:
    try:
        source_host = urlsplit(source).hostname
        endpoint_host = urlsplit(endpoint).hostname
        if not source_host or not endpoint_host:
            return True
        return registrable_root_domain(source_host) != registrable_root_domain(endpoint_host)
    except NormalizationError:
        return True


class KatanaAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="katana",
        category="web_crawler",
        execution_modes=("docker", "host", "fixture"),
        input_types=("url_batch",),
        output_types=("endpoint_observation",),
        preferred_output="jsonl",
        version_command=("katana", "-version"),
        version_markers=("katana", "projectdiscovery", "current version"),
        timeout_seconds=1_900,
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        return KatanaInput.model_validate(payload)

    def build_command(self, validated_input: BaseModel) -> list[str]:
        data = cast(KatanaInput, validated_input)
        # `-fs fqdn` prevents following other hosts. `-do` only exposes external
        # links in output so ScopeGraph can queue them for review without visiting them.
        command = [
            "katana",
            "-jsonl",
            "-silent",
            "-no-color",
            "-omit-raw",
            "-omit-body",
            "-fs",
            "fqdn",
            "-do",
            "-exclude",
            "private-ips",
            "-d",
            str(data.depth),
            "-jc",
            "-kf",
            "all",
            "-ct",
            str(data.duration_seconds),
            "-mdp",
            str(data.max_urls_per_site),
            "-iqp",
            "-fsu",
            "-mrs",
            str(data.max_response_body_bytes),
            "-timeout",
            str(data.timeout_seconds),
            "-c",
            str(data.concurrency),
            "-p",
            str(data.parallelism),
            "-rl",
            str(data.rate),
            "-r",
            direct_resolver_argument(),
        ]
        if data.proxy_url:
            command.extend(["-proxy", data.proxy_url])
        return command

    def stdin_bytes(self, validated_input: BaseModel) -> bytes:
        data = cast(KatanaInput, validated_input)
        return ("\n".join(data.urls) + "\n").encode()

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        observations: list[ObservationPayload] = []
        skipped_invalid_endpoints = 0
        for _line_number, record in read_jsonl(path):
            request = record.get("request")
            if not isinstance(request, dict):
                request = {}
            raw_endpoint = request.get("endpoint") or record.get("endpoint") or record.get("url")
            if not isinstance(raw_endpoint, str):
                skipped_invalid_endpoints += 1
                continue

            kind = _endpoint_kind(raw_endpoint, record)
            endpoint = (
                _websocket_to_https(raw_endpoint)
                if kind is EndpointKind.WEBSOCKET
                else _safe_url(raw_endpoint)
            )
            if endpoint is None:
                # Katana also emits browser-only schemes such as ``weixin:`` and
                # ``javascript:``. They remain in the raw artifact for audit but
                # are not HTTP(S) endpoints and must not fail the whole batch.
                skipped_invalid_endpoints += 1
                continue

            source_value = record.get("source") or request.get("source")
            source = _safe_url(source_value) or endpoint
            method_value = request.get("method") or record.get("method") or "GET"
            method = str(method_value).upper()
            if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}:
                method = "UNKNOWN"
            response = record.get("response")
            status_code = response.get("status_code") if isinstance(response, dict) else None
            if not isinstance(status_code, int):
                status_code = None
            external = _is_external(source, endpoint)
            actively_visited = (
                method in {"GET", "HEAD"} and status_code is not None and not external
            )
            if external:
                kind = EndpointKind.EXTERNAL_LINK

            observations.append(
                ObservationPayload(
                    project_id=context.project_id,
                    scan_run_id=context.scan_run_id,
                    source_tool=self.manifest.name,
                    source_version=context.source_version,
                    observed_at=datetime.now(UTC),
                    subject=ObservationObject(type=AssetType.URL, value=source),
                    predicate="DISCOVERED_ENDPOINT",
                    object=ObservationObject(type=AssetType.URL, value=endpoint),
                    attributes={
                        "actively_visited": actively_visited,
                        "external_candidate": external,
                        "kind": kind.value,
                        "method": method,
                        "original_scheme": urlsplit(raw_endpoint).scheme.casefold(),
                        "source_url": source,
                        "status_code": status_code,
                        "tag": record.get("tag"),
                        "attribute": record.get("attribute"),
                    },
                    raw_artifact_path=context.raw_artifact_path,
                )
            )
        return ParsedObservations(
            observations,
            diagnostics={"parser_skipped_invalid_endpoints": skipped_invalid_endpoints},
        )
