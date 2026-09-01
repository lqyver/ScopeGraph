import json
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from scopegraph.tooling.adapters.alterx import AlterxAdapter
from scopegraph.tooling.adapters.dnsx import DnsxAdapter
from scopegraph.tooling.adapters.httpx import HttpxAdapter
from scopegraph.tooling.adapters.katana import KatanaAdapter
from scopegraph.tooling.adapters.naabu import NaabuAdapter
from scopegraph.tooling.adapters.nmap import (
    NmapAdapter,
    NmapInput,
)
from scopegraph.tooling.adapters.nmap import (
    nmap_command as build_exact_nmap_command,
)
from scopegraph.tooling.adapters.nuclei import NucleiAdapter
from scopegraph.tooling.adapters.puredns import PurednsAdapter
from scopegraph.tooling.adapters.screenshot import ScreenshotAdapter
from scopegraph.tooling.adapters.subfinder import SubfinderAdapter
from scopegraph.tooling.base import (
    AdapterContext,
    OutputParseError,
    ParsedObservations,
    clean_tool_output,
    detected_tool_version,
    version_output_is_compatible,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"


def context() -> AdapterContext:
    return AdapterContext(
        project_id=uuid4(),
        scan_run_id=uuid4(),
        source_version="fixture-1",
        raw_artifact_path="fixtures/raw.jsonl",
    )


def test_adapters_build_only_whitelisted_arguments() -> None:
    subfinder = SubfinderAdapter()
    validated = subfinder.validate_input({"root_domain": "API.Example.COM"})
    assert subfinder.build_command(validated) == [
        "subfinder",
        "-d",
        "example.com",
        "-json",
        "-silent",
    ]
    with pytest.raises(ValidationError):
        subfinder.validate_input({"root_domain": "example.com", "flags": ["--evil"]})


def test_recorded_fixture_parsers_create_unified_observations() -> None:
    subfinder = SubfinderAdapter().parse_output(FIXTURES / "phase2_subfinder.jsonl", context())
    dnsx = DnsxAdapter().parse_output(FIXTURES / "phase2_dnsx.jsonl", context())
    httpx = HttpxAdapter().parse_output(FIXTURES / "phase2_httpx.jsonl", context())

    assert len(subfinder) == 2
    assert {item.object.value for item in subfinder if item.object} == {
        "api.example.com",
        "www.example.com",
    }
    assert len(dnsx) == 3
    assert {item.predicate for item in dnsx} == {"RESOLVES_TO", "CNAME_TO"}
    assert len(httpx) == 2
    assert httpx[0].attributes["status_code"] == 200


def test_jsonl_parser_preserves_bad_raw_file_for_diagnostics(tmp_path: Path) -> None:
    raw = tmp_path / "bad.jsonl"
    raw.write_text('{"host":', encoding="utf-8")
    with pytest.raises(OutputParseError, match="line 1"):
        SubfinderAdapter().parse_output(raw, context())


def test_naabu_parser_deduplicates_repeated_open_endpoints(tmp_path: Path) -> None:
    raw = tmp_path / "naabu.jsonl"
    record = json.dumps({"ip": "203.0.113.10", "port": 443, "protocol": "tcp"})
    raw.write_text(f"{record}\n{record}\n", encoding="utf-8")

    observations = NaabuAdapter().parse_output(raw, context())

    assert len(observations) == 1
    assert isinstance(observations, ParsedObservations)
    assert observations.diagnostics == {
        "raw_tool_records": 2,
        "duplicate_tool_records": 1,
        "unique_open_endpoints": 1,
    }


def test_httpx_adapter_rejects_python_cli_name_collision() -> None:
    manifest = HttpxAdapter.manifest
    assert not version_output_is_compatible(manifest, "HTTPX version 0.28.1 Python client")
    assert version_output_is_compatible(
        manifest, "[INF] Current Version: v1.7.0 by ProjectDiscovery"
    )


def test_httpx_adapter_uses_safe_redirect_and_private_network_policy() -> None:
    adapter = HttpxAdapter()
    validated = adapter.validate_input(
        {
            "domains": ["www.example.com"],
            "concurrency": 25,
            "rate": 40,
            "timeout_seconds": 12,
            "max_redirects": 2,
            "max_response_body_bytes": 1_048_576,
            "extract_icp": True,
        }
    )
    command = adapter.build_command(validated)
    assert "-follow-host-redirects" in command
    assert "-follow-redirects" not in command
    assert "-deny" in command
    denied = command[command.index("-deny") + 1]
    assert "127.0.0.0/8" in denied and "169.254.0.0/16" in denied
    assert "198.18.0.0/15" in denied
    assert command[command.index("-r") + 1].startswith("doh:https://1.1.1.1/")
    assert "-include-response-header" in command
    assert "-include-response" not in command
    assert "-body" not in command
    assert "-unsafe" not in command


def test_httpx_rich_fixture_extracts_web_metadata_and_filing_without_secrets() -> None:
    fixture = Path(__file__).parents[2] / "scopegraph" / "tooling" / "fixtures" / "httpx.jsonl"
    observations = HttpxAdapter().parse_output(fixture, context())
    websites = [item for item in observations if item.predicate == "SERVES_WEBSITE"]
    filings = [item for item in observations if item.predicate == "HAS_ICP_RECORD"]
    assert len(websites) == 2
    assert len(filings) == 2
    www = next(item for item in websites if item.subject.value == "www.example.com")
    assert www.attributes["response_time_ms"] == 350.0
    assert www.attributes["cdn_waf"] == ["vercel"]
    assert "set-cookie" not in www.attributes["response_headers"]
    assert www.attributes["body_hash"] == "c" * 64
    assert {item.attributes["record_kind"] for item in filings} == {
        "ICP",
        "PUBLIC_SECURITY",
    }


def test_httpx_extract_regex_finds_filing_outside_body_preview(tmp_path: Path) -> None:
    raw = tmp_path / "httpx-extract.jsonl"
    raw.write_text(
        '{"url":"https://www.example.com/","input":"www.example.com",'
        '"status_code":200,"body_preview":"<html><main>首页</main>",'
        '"extracts":{"备案正则":["京ICP备12345678号-2",'
        '"京公网安备11010502000001号"]}}\n',
        encoding="utf-8",
    )

    observations = HttpxAdapter().parse_output(raw, context())
    filings = [item for item in observations if item.predicate == "HAS_ICP_RECORD"]

    assert len(filings) == 2
    assert observations.diagnostics["filing_extract_matches"] == 2
    assert observations.diagnostics["filing_records_found"] == 2


def test_phase_three_adapters_use_closed_argv_schemas() -> None:
    alterx = AlterxAdapter()
    alterx_input = alterx.validate_input({"domains": ["api.example.com"], "limit": 20})
    assert alterx.build_command(alterx_input)[0] == "alterx"

    puredns = PurednsAdapter()
    pure_input = puredns.validate_input(
        {"root_domain": "example.com", "candidates": ["dev.example.com"], "rate": 50}
    )
    pure_command = puredns.build_command(pure_input)
    assert pure_command[:3] == ["puredns", "resolve", "/dev/stdin"]
    assert "configs/resolvers.txt" in pure_command

    naabu = NaabuAdapter()
    naabu_input = naabu.validate_input(
        {"ips": ["8.8.8.8"], "ports": [443, 80], "rate": 50, "concurrency": 5}
    )
    command = naabu.build_command(naabu_input)
    assert command[0] == "naabu" and command[command.index("-p") + 1] == "80,443"

    nmap = NmapAdapter()
    nmap_input = nmap.validate_input({"targets": [{"ip": "8.8.8.8", "ports": [443, 80]}]})
    batch_command = nmap.build_command(nmap_input)
    assert batch_command[1:] == ["-m", "scopegraph.tooling.nmap_batch"]
    validated_nmap = NmapInput.model_validate(nmap_input)
    exact_command = build_exact_nmap_command(validated_nmap.targets[0])
    assert exact_command == [
        "nmap",
        "-Pn",
        "-sV",
        "--version-light",
        "--noninteractive",
        "-oX",
        "-",
        "-p",
        "80,443",
        "8.8.8.8",
    ]
    assert "--script" not in exact_command

    multi = nmap.validate_input(
        {
            "targets": [
                {"ip": "8.8.8.8", "ports": [80]},
                {"ip": "1.1.1.1", "ports": [443, 8443]},
            ]
        }
    )
    encoded = nmap.stdin_bytes(multi)
    assert encoded is not None
    assert json.loads(encoded)["targets"] == [
        {"ip": "8.8.8.8", "ports": [80]},
        {"ip": "1.1.1.1", "ports": [443, 8443]},
    ]

    with pytest.raises(ValidationError):
        naabu.validate_input({"ips": ["8.8.8.8"], "ports": [443], "flags": ["--evil"]})
    with pytest.raises(ValueError, match="authorized root"):
        puredns.validate_input(
            {"root_domain": "example.com", "candidates": ["outside.test"], "rate": 50}
        )


def test_phase_three_fixture_parsers_preserve_validation_chain() -> None:
    fixture_dir = Path(__file__).parents[2] / "scopegraph" / "tooling" / "fixtures"
    alterx = AlterxAdapter().parse_output(fixture_dir / "alterx.jsonl", context())
    puredns = PurednsAdapter().parse_output(fixture_dir / "puredns.jsonl", context())
    naabu = NaabuAdapter().parse_output(fixture_dir / "naabu.jsonl", context())
    nmap = NmapAdapter().parse_output(fixture_dir / "nmap.jsonl", context())

    assert all(not item.attributes["validated"] for item in alterx)
    assert all(item.attributes["wildcard_filtered"] for item in puredns)
    assert {item.attributes["port"] for item in naabu} == {80, 443}
    assert {item.attributes["port"] for item in nmap} == {80, 443}
    assert {item.attributes["name"] for item in nmap} == {"http", "https"}


def test_nmap_parser_rejects_document_type_declarations(tmp_path: Path) -> None:
    raw = tmp_path / "unsafe.xml"
    raw.write_text("<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><nmaprun/>")
    with pytest.raises(OutputParseError, match="forbidden"):
        NmapAdapter().parse_output(raw, context())


def test_dnsx_parser_covers_phase_three_record_types(tmp_path: Path) -> None:
    raw = tmp_path / "dns.jsonl"
    raw.write_text(
        '{"host":"example.com","a":["8.8.8.8"],"aaaa":["2001:4860:4860::8888"],'
        '"cname":["www.example.com"],"mx":["10 mail.example.com"],'
        '"ns":["ns1.example.com"],"txt":["verification=ok"],'
        '"soa":[{"mname":"ns1.example.com","serial":1}],'
        '"ptr":["ptr.example.com"]}\n',
        encoding="utf-8",
    )
    observations = DnsxAdapter().parse_output(raw, context())
    assert {item.attributes.get("record_type") for item in observations} == {
        "A",
        "AAAA",
        "CNAME",
        "MX",
        "NS",
        "TXT",
        "SOA",
        "PTR",
    }


def test_proxy_mapping_ips_and_ports_are_not_persisted_as_target_endpoints(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "httpx.jsonl"
    raw.write_text(
        '{"input":"example.com","url":"https://example.com/",'
        '"final_url":"https://example.com/","status_code":200,'
        '"a":["198.18.0.42","93.184.216.34"],"host_ip":"198.18.0.42",'
        '"port":"7890"}\n',
        encoding="utf-8",
    )

    observation = HttpxAdapter().parse_output(raw, context())[0]

    assert observation.attributes["ip"] == ["93.184.216.34"]
    assert observation.attributes["environment_mapped_ips"] == ["198.18.0.42"]
    assert observation.attributes["port"] == 443

    dns_raw = tmp_path / "dnsx.jsonl"
    dns_raw.write_text(
        '{"host":"example.com","a":["198.18.0.42","93.184.216.34"]}\n',
        encoding="utf-8",
    )
    resolved = DnsxAdapter().parse_output(dns_raw, context())
    assert [item.object.value for item in resolved if item.object] == ["93.184.216.34"]


def test_katana_adapter_enforces_bounded_non_mutating_crawl_policy() -> None:
    adapter = KatanaAdapter()
    validated = adapter.validate_input(
        {
            "urls": ["HTTPS://WWW.Example.COM"],
            "depth": 3,
            "max_urls_per_site": 2000,
            "duration_seconds": 600,
            "rate": 20,
            "concurrency": 5,
            "parallelism": 4,
            "timeout_seconds": 15,
            "max_response_body_bytes": 2_097_152,
        }
    )
    command = adapter.build_command(validated)
    assert command[0] == "katana"
    assert command[command.index("-fs") + 1] == "fqdn"
    assert command[command.index("-kf") + 1] == "all"
    assert "-do" in command
    assert command[command.index("-mdp") + 1] == "2000"
    assert command[command.index("-rl") + 1] == "20"
    assert command[command.index("-p") + 1] == "4"
    assert "-omit-raw" in command and "-omit-body" in command
    assert "-iqp" in command and "-fsu" in command
    assert command[command.index("-r") + 1].startswith("doh:https://1.1.1.1/")
    assert command[command.index("-exclude") + 1] == "private-ips"
    assert "-aff" not in command
    assert "-H" not in command
    assert "-headless" not in command
    assert adapter.stdin_bytes(validated) == b"https://www.example.com/\n"
    with pytest.raises(ValidationError):
        adapter.validate_input({"urls": ["https://example.com"], "headers": ["Cookie: x"]})


def test_nuclei_adapter_blocks_local_network_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = NucleiAdapter()
    monkeypatch.setattr(adapter, "installation_path", lambda: "/usr/local/bin/nuclei")
    validated = adapter.validate_input({"urls": ["https://www.example.com/"]})

    command = adapter.build_command(validated)

    assert "-restrict-local-network-access" in command
    assert "-no-interactsh" in command
    assert "-headless" not in command


def test_katana_fixture_distinguishes_external_and_non_get_endpoints() -> None:
    fixture = Path(__file__).parents[2] / "scopegraph" / "tooling" / "fixtures" / "katana.jsonl"
    observations = KatanaAdapter().parse_output(fixture, context())
    assert len(observations) == 5
    by_object = {item.object.value: item for item in observations if item.object}
    assert by_object["https://www.example.com/assets/app.js"].attributes["kind"] == "JAVASCRIPT"
    assert by_object["https://www.example.com/api/v1/profile"].attributes["kind"] == "XHR"
    external = by_object["https://vendor.example.net/help"]
    assert external.attributes["kind"] == "EXTERNAL_LINK"
    assert external.attributes["actively_visited"] is False
    post = by_object["https://www.example.com/api/v1/payment"]
    assert post.attributes["method"] == "POST"
    assert post.attributes["actively_visited"] is False


def test_katana_parser_skips_browser_only_schemes_without_failing_batch(tmp_path: Path) -> None:
    fixture = tmp_path / "katana-browser-schemes.jsonl"
    fixture.write_text(
        "\n".join(
            [
                '{"request":{"method":"GET","endpoint":"weixin:",'
                '"source":"https://example.com/app.js"},"error":"out of scope"}',
                '{"request":{"method":"GET",'
                '"endpoint":"https://example.com/api/status",'
                '"source":"https://example.com/"},"response":{"status_code":200}}',
            ]
        ),
        encoding="utf-8",
    )

    observations = KatanaAdapter().parse_output(fixture, context())

    assert len(observations) == 1
    assert isinstance(observations, ParsedObservations)
    assert observations[0].object is not None
    assert observations[0].object.value == "https://example.com/api/status"
    assert observations.diagnostics == {
        "parser_skipped_invalid_endpoints": 1
    }


def test_screenshot_adapter_is_separate_bounded_and_path_safe(tmp_path: Path) -> None:
    adapter = ScreenshotAdapter()
    validated = adapter.validate_input({"urls": ["https://www.example.com"]})
    command = adapter.build_command(validated)
    assert "-screenshot" in command
    assert "-exclude-screenshot-bytes" in command
    assert "-headless-options" in command
    headless_options = command[command.index("-headless-options") + 1]
    assert "--disable-background-networking" in headless_options
    assert "--disable-extensions" in headless_options
    assert "-follow-host-redirects" in command
    assert "-follow-redirects" not in command
    assert "-H" not in command and "-body" not in command
    fixture = Path(__file__).parents[2] / "scopegraph" / "tooling" / "fixtures" / "screenshot.jsonl"
    observations = adapter.parse_output(fixture, context())
    assert {item.predicate for item in observations} == {
        "SCREENSHOT_CAPTURED",
        "SCREENSHOT_FAILED",
    }
    unsafe = tmp_path / "unsafe.jsonl"
    unsafe.write_text(
        '{"url":"https://www.example.com/","screenshot_path":"../escape.png"}\n',
        encoding="utf-8",
    )
    assert adapter.parse_output(unsafe, context())[0].predicate == "SCREENSHOT_FAILED"


def test_tool_version_output_is_terminal_safe_and_traceable() -> None:
    raw = "\x1b[34mhttpx version 1.7.2\x1b[0m\nsecond line"

    assert clean_tool_output(raw) == "httpx version 1.7.2\nsecond line"
    assert detected_tool_version(raw) == "httpx version 1.7.2"
    assert detected_tool_version("__ banner __\n[INF] Current Version: v1.9.0") == (
        "[INF] Current Version: v1.9.0"
    )


def test_screenshot_adapter_recovers_interleaved_httpx_record_and_absolute_path(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "interleaved.jsonl"
    raw.write_text(
        '{"url":"https://broken.example.com/","title":"prefix'
        '{"timestamp":"2026-07-17T02:58:28Z","url":"https://ok.example.com/",'
        '"screenshot_path":"/data/projects/p/jobs/j/attempts/1/screenshots/screenshot/'
        'ok.example.com/capture.png"}suffix"}\n',
        encoding="utf-8",
    )

    observations = ScreenshotAdapter().parse_output(raw, context())

    assert len(observations) == 1
    assert observations[0].subject.value == "https://ok.example.com/"
    assert observations[0].attributes["screenshot_path"] == (
        "screenshots/screenshot/ok.example.com/capture.png"
    )
