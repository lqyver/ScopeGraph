import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers.assets import NormalizationError, normalize_domain, normalize_url
from scopegraph.scanning.observations import ObservationObject, ObservationPayload
from scopegraph.security import normalize_proxy_url
from scopegraph.tooling.base import (
    AdapterContext,
    OutputParseError,
    ParsedObservations,
    ToolAdapter,
    ToolManifest,
)
from scopegraph.tooling.jsonl import read_jsonl
from scopegraph.tooling.network_policy import direct_resolver_argument, split_reported_ips
from scopegraph.web.icp import extract_page_identity

_DENIED_NETWORKS = (
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "::/128",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
)
_SAFE_RESPONSE_HEADERS = {
    "access-control-allow-origin",
    "cache-control",
    "content-security-policy",
    "content-type",
    "etag",
    "last-modified",
    "location",
    "permissions-policy",
    "referrer-policy",
    "server",
    "strict-transport-security",
    "via",
    "x-content-type-options",
    "x-frame-options",
    "x-powered-by",
}
_DURATION = re.compile(r"^([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s)?$")
_ICP_EXTRACT_REGEX = (
    r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]"
    r"\s*ICP\s*(备|证)\s*[0-9]{6,12}\s*号(\s*[-－]\s*[0-9]+)?"
)
_PUBLIC_SECURITY_EXTRACT_REGEX = (
    r"[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼]"
    r"\s*公网\s*安备\s*[0-9]{12,18}\s*号?"
)


class HttpxInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    domains: list[str] = Field(min_length=1, max_length=10_000)
    concurrency: int = Field(default=30, ge=1, le=100)
    rate: int = Field(default=50, ge=1, le=500)
    timeout_seconds: int = Field(default=15, ge=3, le=60)
    max_redirects: int = Field(default=3, ge=0, le=10)
    max_response_body_bytes: int = Field(default=2_097_152, ge=65_536, le=10_485_760)
    extract_icp: bool = True
    proxy_url: str | None = None

    @field_validator("domains")
    @classmethod
    def normalize_domains(cls, values: list[str]) -> list[str]:
        return list(dict.fromkeys(normalize_domain(value) for value in values))

    @field_validator("proxy_url")
    @classmethod
    def validate_proxy(cls, value: str | None) -> str | None:
        return normalize_proxy_url(value) if value else None


def _host_from_record(record: dict[str, Any], url: str, line_number: int) -> str:
    for candidate in (record.get("input"), record.get("host"), urlsplit(url).hostname):
        if not isinstance(candidate, str):
            continue
        value = urlsplit(candidate).hostname if "://" in candidate else candidate
        if not value:
            continue
        try:
            return normalize_domain(value)
        except NormalizationError:
            continue
    raise OutputParseError(f"httpx line {line_number} requires a public domain host")


def _number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _response_time_ms(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # httpx numeric durations are seconds.
        return round(float(value) * 1000, 3)
    if not isinstance(value, str):
        return None
    matched = _DURATION.fullmatch(value.strip())
    if not matched:
        return None
    amount = float(matched.group(1))
    factors = {None: 1000.0, "s": 1000.0, "ms": 1.0, "us": 0.001, "µs": 0.001, "ns": 0.000001}
    return round(amount * factors[matched.group(2)], 3)


def _safe_headers(record: dict[str, Any]) -> dict[str, str]:
    collected: dict[str, str] = {}
    structured = record.get("header") or record.get("headers")
    if isinstance(structured, dict):
        for name, value in structured.items():
            folded = str(name).casefold().replace("_", "-")
            if folded in _SAFE_RESPONSE_HEADERS:
                collected[folded] = str(value)[:2_000]
    raw = record.get("response")
    if isinstance(raw, str):
        response_start = raw.rfind("HTTP/")
        header_block = raw[response_start:] if response_start >= 0 else raw
        header_block = header_block.split("\r\n\r\n", 1)[0].split("\n\n", 1)[0]
        for line in header_block.replace("\r\n", "\n").splitlines()[1:]:
            name, separator, value = line.partition(":")
            folded = name.strip().casefold()
            if separator and folded in _SAFE_RESPONSE_HEADERS:
                collected[folded] = value.strip()[:2_000]
    return collected


def _bounded_json(value: Any, *, depth: int = 0) -> Any:
    if depth > 4:
        return None
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:4_096]
    if isinstance(value, list):
        return [_bounded_json(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, dict):
        return {
            str(key)[:100]: _bounded_json(item, depth=depth + 1)
            for key, item in list(value.items())[:100]
        }
    return str(value)[:4_096]


def _body_hash(record: dict[str, Any]) -> str | None:
    direct = record.get("body_sha256") or record.get("body_hash")
    if isinstance(direct, str):
        return direct[:128]
    hashes = record.get("hash")
    if isinstance(hashes, dict):
        value = hashes.get("body_sha256") or hashes.get("sha256")
        if isinstance(value, str):
            return value[:128]
    return None


def _cdn_waf(record: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for key in ("cdn_name", "cdn_type", "waf", "waf_name"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip()[:200])
    cdn = record.get("cdn")
    if isinstance(cdn, str) and cdn.strip():
        values.append(cdn.strip()[:200])
    elif cdn is True and not values:
        values.append("detected")
    return list(dict.fromkeys(values))


def _reported_ip_values(record: dict[str, Any]) -> list[object]:
    values: list[object] = []
    for key in ("a", "aaaa", "ip", "host_ip"):
        value = record.get(key)
        if isinstance(value, list):
            values.extend(value)
        elif value is not None:
            values.append(value)
    return values


def _endpoint_port(url: str) -> int | None:
    parsed = urlsplit(url)
    if parsed.port is not None:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None


class HttpxAdapter(ToolAdapter):
    manifest = ToolManifest(
        name="httpx",
        category="http_probe",
        execution_modes=("docker", "host", "fixture"),
        input_types=("domain_batch",),
        output_types=("website_observation", "icp_observation"),
        preferred_output="jsonl",
        version_command=("httpx", "-version"),
        version_markers=("projectdiscovery", "current version"),
        timeout_seconds=900,
    )

    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        return HttpxInput.model_validate(payload)

    def build_command(self, validated_input: BaseModel) -> list[str]:
        data = cast(HttpxInput, validated_input)
        preview_size = min(data.max_response_body_bytes, 262_144)
        command = [
            "httpx",
            "-json",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-status-code",
            "-content-length",
            "-content-type",
            "-location",
            "-favicon",
            "-hash",
            "sha256",
            "-response-time",
            "-title",
            "-web-server",
            "-tech-detect",
            "-method",
            "-ip",
            "-cname",
            "-cdn",
            "-tls-grab",
            "-include-chain",
            "-include-response-header",
            "-body-preview",
            str(preview_size),
            "-follow-host-redirects",
            "-max-redirects",
            str(data.max_redirects),
            "-deny",
            ",".join(_DENIED_NETWORKS),
            "-r",
            direct_resolver_argument(),
            "-threads",
            str(data.concurrency),
            "-rate-limit",
            str(data.rate),
            "-timeout",
            str(data.timeout_seconds),
            "-response-size-to-read",
            str(data.max_response_body_bytes),
        ]
        if data.proxy_url:
            command.extend(["-proxy", data.proxy_url])
        if data.extract_icp:
            # httpx applies extract-regex to the complete response it read, so
            # a filing number in a long footer is still emitted even when it is
            # outside the bounded body preview kept in JSONL.
            command.extend(["-extract-regex", _ICP_EXTRACT_REGEX])
            command.extend(["-extract-regex", _PUBLIC_SECURITY_EXTRACT_REGEX])
        return command

    def stdin_bytes(self, validated_input: BaseModel) -> bytes:
        data = cast(HttpxInput, validated_input)
        return ("\n".join(data.domains) + "\n").encode()

    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        observations: list[ObservationPayload] = []
        pages_checked = 0
        previews_checked = 0
        extracted_filing_matches = 0
        filing_records = 0
        cross_host_redirects = 0
        for line_number, record in read_jsonl(path):
            pages_checked += 1
            raw_url = record.get("url") or record.get("final_url")
            if not isinstance(raw_url, str):
                raise OutputParseError(f"httpx line {line_number} requires a URL")
            try:
                url = normalize_url(raw_url)
                final_url = normalize_url(str(record.get("final_url") or raw_url))
            except NormalizationError as exc:
                raise OutputParseError(f"httpx line {line_number} contains an invalid URL") from exc
            host = _host_from_record(record, url, line_number)
            technologies = record.get("tech")
            if not isinstance(technologies, list):
                technologies = []
            cname = record.get("cname")
            if isinstance(cname, str):
                cname = [cname]
            elif not isinstance(cname, list):
                cname = []
            tls = record.get("tls")
            if not isinstance(tls, dict):
                tls = {}
            chain = record.get("chain") or record.get("redirect_chain")
            if not isinstance(chain, list):
                chain = []
            favicon = record.get("favicon")
            usable_ips, mapped_ips = split_reported_ips(_reported_ip_values(record))
            attributes = {
                "body_hash": _body_hash(record),
                "cdn_waf": _cdn_waf(record),
                "cname": [str(item)[:253] for item in cname[:50]],
                "content_length": _number(record.get("content_length")),
                "content_type": record.get("content_type"),
                "error": record.get("error") if isinstance(record.get("error"), str) else None,
                "favicon_hash": str(favicon)[:128] if favicon is not None else None,
                "final_url": final_url,
                "input_url": url,
                "ip": usable_ips,
                "environment_mapped_ips": mapped_ips,
                "method": record.get("method") or "GET",
                "port": _endpoint_port(final_url),
                "redirect_chain": _bounded_json(chain),
                "response_headers": _safe_headers(record),
                "response_time_ms": _response_time_ms(
                    record.get("time") or record.get("response_time")
                ),
                "status_code": _number(record.get("status_code")),
                "technologies": [str(item)[:300] for item in technologies[:100]],
                "title": str(record.get("title"))[:1_000] if record.get("title") else None,
                "tls": _bounded_json(tls),
                "webserver": (
                    str(record.get("webserver"))[:500] if record.get("webserver") else None
                ),
            }
            observations.append(
                ObservationPayload(
                    project_id=context.project_id,
                    scan_run_id=context.scan_run_id,
                    source_tool=self.manifest.name,
                    source_version=context.source_version,
                    observed_at=datetime.now(UTC),
                    subject=ObservationObject(type=AssetType.DOMAIN, value=host),
                    predicate="SERVES_WEBSITE",
                    object=ObservationObject(type=AssetType.URL, value=url),
                    attributes=attributes,
                    raw_artifact_path=context.raw_artifact_path,
                )
            )

            preview = record.get("body_preview") or record.get("body-preview")
            evidence_fragments: list[str] = []
            if isinstance(preview, str) and preview:
                previews_checked += 1
                evidence_fragments.append(preview)
            extracts = record.get("extracts")
            if isinstance(extracts, dict):
                for matches in extracts.values():
                    if not isinstance(matches, list):
                        continue
                    clean_matches = [str(item) for item in matches if isinstance(item, str)]
                    extracted_filing_matches += len(clean_matches)
                    evidence_fragments.extend(clean_matches)
            input_host = urlsplit(url).hostname
            location = attributes["response_headers"].get("location")
            if isinstance(location, str):
                redirect_host = urlsplit(location).hostname
                if (
                    redirect_host
                    and input_host
                    and redirect_host.casefold() != input_host.casefold()
                ):
                    cross_host_redirects += 1
            if evidence_fragments:
                identity = extract_page_identity("\n".join(evidence_fragments))
                for extracted in identity.records:
                    filing_records += 1
                    observations.append(
                        ObservationPayload(
                            project_id=context.project_id,
                            scan_run_id=context.scan_run_id,
                            source_tool=self.manifest.name,
                            source_version=context.source_version,
                            observed_at=datetime.now(UTC),
                            subject=ObservationObject(type=AssetType.URL, value=url),
                            predicate="HAS_ICP_RECORD",
                            object=ObservationObject(
                                type=AssetType.ICP_RECORD,
                                value=extracted.normalized_number,
                            ),
                            attributes={
                                "copyright_subjects": list(identity.copyright_subjects),
                                "display_number": extracted.display_number,
                                "excerpt": extracted.excerpt,
                                "record_kind": extracted.kind.value,
                                "source_url": url,
                            },
                            raw_artifact_path=context.raw_artifact_path,
                        )
                    )
        return ParsedObservations(
            observations,
            diagnostics={
                "pages_checked": pages_checked,
                "page_previews_checked": previews_checked,
                "filing_extract_matches": extracted_filing_matches,
                "filing_records_found": filing_records,
                "cross_host_redirects": cross_host_redirects,
            },
        )
