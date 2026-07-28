import pytest

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers.imports import ImportParseError, parse_import_file


def test_txt_import_infers_and_accepts_explicit_types() -> None:
    items = parse_import_file(
        "assets.txt",
        b"# seeds\nexample.com\nurl,https://example.com/login\n192.0.2.1\n",
    )

    assert [item.asset_type for item in items] == [
        AssetType.DOMAIN,
        AssetType.URL,
        AssetType.IP,
    ]


def test_csv_import_requires_value_and_supports_asset_type_header() -> None:
    items = parse_import_file(
        "assets.csv",
        b"asset_type,value\ndomain,api.example.com\nip,192.0.2.10\n",
    )

    assert len(items) == 2
    assert items[1].asset_type is AssetType.IP


def test_json_import_supports_wrapper_and_strings() -> None:
    items = parse_import_file(
        "assets.json",
        b'{"assets":["www.example.com",{"type":"url","value":"https://example.com"}]}',
    )

    assert [item.asset_type for item in items] == [AssetType.DOMAIN, AssetType.URL]


def test_import_rejects_unsupported_or_empty_files() -> None:
    with pytest.raises(ImportParseError):
        parse_import_file("assets.xlsx", b"not-an-xlsx")
    with pytest.raises(ImportParseError):
        parse_import_file("assets.txt", b"")
