from pathlib import Path
from uuid import uuid4
from zipfile import ZipFile

import pytest

from scopegraph.application.services.exports import _safe_csv
from scopegraph.application.services.scan_execution import _should_retire_nuclei_findings
from scopegraph.application.services.scans import _stage_timeout_seconds
from scopegraph.domain.enums import ScanProfile, ScanStatus
from scopegraph.exporting.xlsx import write_xlsx
from scopegraph.scanning.profiles import load_profile
from scopegraph.schemas.scans import ScanRunCreate
from scopegraph.tooling.adapters.nuclei import BLOCKED_TAGS, NucleiAdapter
from scopegraph.tooling.base import AdapterContext, OutputParseError


def test_nuclei_requires_second_confirmation() -> None:
    with pytest.raises(ValueError, match="second confirmation"):
        ScanRunCreate.model_validate(
            {
                "root_domain": "example.com",
                "authorization_confirmed": True,
                "nuclei_enabled": True,
            }
        )


def test_nuclei_partial_output_does_not_retire_previous_findings() -> None:
    assert not _should_retire_nuclei_findings("nuclei", ScanStatus.TIMEOUT, True)


def test_nuclei_success_retire_previous_findings() -> None:
    assert _should_retire_nuclei_findings("nuclei", ScanStatus.SUCCESS, False)


def test_nuclei_asset_budget_keeps_previous_findings() -> None:
    assert not _should_retire_nuclei_findings("nuclei", ScanStatus.SUCCESS, False, 1)


def test_nuclei_command_is_allowlisted_and_non_interactive(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = NucleiAdapter()
    monkeypatch.setattr(adapter, "installation_path", lambda: "/usr/local/bin/nuclei")
    validated = adapter.validate_input({"urls": ["https://example.com"]})
    command = adapter.build_command(validated)

    assert "-disable-update-check" in command
    assert "-no-interactsh" in command
    assert "-automatic-scan" in command
    assert "-tags" not in command
    assert "-exclude-tags" in command
    assert all(tag in command[command.index("-exclude-tags") + 1] for tag in BLOCKED_TAGS)
    assert "-exclude-type" in command
    assert "-exclude-protocols" not in command
    assert adapter.stdin_bytes(validated) == b"https://example.com/\n"
    assert "-list" not in command
    assert "-t" not in command


def test_nuclei_broad_strategy_remains_an_explicit_profile_choice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = NucleiAdapter()
    monkeypatch.setattr(adapter, "installation_path", lambda: "/usr/local/bin/nuclei")
    command = adapter.build_command(
        adapter.validate_input({"urls": ["https://example.com"], "strategy": "broad"})
    )

    assert "-automatic-scan" not in command
    assert "-tags" in command
    assert "misconfig" in command[command.index("-tags") + 1]


def test_nuclei_parser_never_marks_a_hit_verified() -> None:
    adapter = NucleiAdapter()
    path = Path("scopegraph/tooling/fixtures/nuclei.jsonl")
    rows = adapter.parse_output(
        path,
        AdapterContext(
            project_id=uuid4(),
            scan_run_id=uuid4(),
            source_version="fixture-1",
            raw_artifact_path="fixture/nuclei.jsonl",
        ),
    )

    assert len(rows) == 1
    assert rows[0].predicate == "HAS_FINDING"
    assert rows[0].attributes["finding_status"] == "UNVERIFIED"
    assert rows[0].confidence == 0.5


def test_nuclei_parser_accepts_bare_dns_targets(tmp_path: Path) -> None:
    output = tmp_path / "nuclei-dns.jsonl"
    output.write_text(
        '{"template-id":"dns-caa","info":{"name":"CAA","severity":"info",'
        '"tags":["ssl"]},"type":"dns","host":"api.example.com",'
        '"matched-at":"api.example.com"}\n',
        encoding="utf-8",
    )

    rows = NucleiAdapter().parse_output(
        output,
        AdapterContext(
            project_id=uuid4(),
            scan_run_id=uuid4(),
            source_version="fixture-1",
            raw_artifact_path="fixture/nuclei-dns.jsonl",
        ),
    )

    assert len(rows) == 1
    assert rows[0].subject.type.value == "domain"
    assert rows[0].subject.value == "api.example.com"


def test_nuclei_parser_ignores_nonfatal_engine_banner_before_jsonl(tmp_path: Path) -> None:
    output = tmp_path / "nuclei-banner.jsonl"
    output.write_text(
        "[INF] Nuclei Engine Version: v3.8.0\n"
        '{"template-id":"http-missing-security-headers","info":{"name":"Headers",'
        '"severity":"low","tags":["misconfig"]},"url":"https://www.example.com/"}\n',
        encoding="utf-8",
    )

    rows = NucleiAdapter().parse_output(
        output,
        AdapterContext(
            project_id=uuid4(),
            scan_run_id=uuid4(),
            source_version="v3.8.0",
            raw_artifact_path="fixture/nuclei-banner.jsonl",
        ),
    )

    assert len(rows) == 1
    assert rows.diagnostics == {"parser_skipped_diagnostic_lines": 1}


def test_nuclei_parser_treats_banner_only_output_as_empty_result(tmp_path: Path) -> None:
    output = tmp_path / "nuclei-empty.jsonl"
    output.write_text("[INF] Nuclei Engine Version: v3.8.0\n", encoding="utf-8")

    rows = NucleiAdapter().parse_output(
        output,
        AdapterContext(
            project_id=uuid4(),
            scan_run_id=uuid4(),
            source_version="v3.8.0",
            raw_artifact_path="fixture/nuclei-empty.jsonl",
        ),
    )

    assert rows == []
    assert rows.diagnostics == {"parser_skipped_diagnostic_lines": 1}


def test_nuclei_parser_rejects_unknown_non_json_output(tmp_path: Path) -> None:
    output = tmp_path / "nuclei-invalid.jsonl"
    output.write_text("not a nuclei diagnostic\n", encoding="utf-8")

    with pytest.raises(OutputParseError, match="Invalid Nuclei JSONL"):
        NucleiAdapter().parse_output(
            output,
            AdapterContext(
                project_id=uuid4(),
                scan_run_id=uuid4(),
                source_version="v3.8.0",
                raw_artifact_path="fixture/nuclei-invalid.jsonl",
            ),
        )


def test_nuclei_uses_profile_budget_instead_of_old_five_minute_cap() -> None:
    deep = load_profile(ScanProfile.DEEP)

    assert deep.job_timeout_seconds == 1_200
    assert _stage_timeout_seconds("nuclei", deep) == 1_200


def test_xlsx_writer_creates_eleven_safe_structured_sheets(tmp_path: Path) -> None:
    path = tmp_path / "export.xlsx"
    names = [
        "项目总览",
        "根域名",
        "子域名",
        "IP资产",
        "端口服务",
        "Web网站",
        "备案信息",
        "第三方服务",
        "待审核资产",
        "安全发现",
        "扫描历史",
    ]
    write_xlsx(
        path,
        {name: (["值", "计数"], [{"值": "=not-a-formula", "计数": 1}]) for name in names},
    )

    with ZipFile(path) as archive:
        workbook = archive.read("xl/workbook.xml").decode()
        first_sheet = archive.read("xl/worksheets/sheet1.xml").decode()
        assert all(name in workbook for name in names)
        assert "=not-a-formula" in first_sheet
        assert "<f>" not in first_sheet
        assert 'state="frozen"' in first_sheet
        assert "autoFilter" in first_sheet


@pytest.mark.parametrize("value", ["=1+1", "+cmd", "-2+3", "@SUM(A1:A2)"])
def test_csv_export_neutralizes_spreadsheet_formulas(value: str) -> None:
    assert _safe_csv(value) == f"'{value}"
