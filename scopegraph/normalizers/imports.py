import csv
import io
import json
from dataclasses import dataclass
from pathlib import PurePath
from typing import Any

from scopegraph.domain.enums import AssetType


class ImportParseError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ImportItem:
    asset_type: AssetType
    value: str


def infer_asset_type(value: str) -> AssetType:
    candidate = value.strip()
    if candidate.casefold().startswith(("http://", "https://")):
        return AssetType.URL
    if "/" in candidate:
        return AssetType.CIDR
    try:
        import ipaddress

        ipaddress.ip_address(candidate)
        return AssetType.IP
    except ValueError:
        return AssetType.DOMAIN


def _parse_asset_type(value: str) -> AssetType:
    try:
        return AssetType(value.strip().casefold())
    except ValueError as exc:
        raise ImportParseError(f"Unsupported asset type: {value}") from exc


def _decode(content: bytes) -> str:
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ImportParseError("Import file must be UTF-8 encoded") from exc


def _parse_txt(text: str) -> list[ImportItem]:
    items: list[ImportItem] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        candidate = line.strip()
        if not candidate or candidate.startswith("#"):
            continue
        parts = [part.strip() for part in candidate.split(",", maxsplit=1)]
        if len(parts) == 2 and parts[0].casefold() in {item.value for item in AssetType}:
            item = ImportItem(_parse_asset_type(parts[0]), parts[1])
        else:
            item = ImportItem(infer_asset_type(candidate), candidate)
        if not item.value:
            raise ImportParseError(f"Line {line_number} has an empty value")
        items.append(item)
    return items


def _parse_csv(text: str) -> list[ImportItem]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ImportParseError("CSV header is required")
    normalized_fields = {field.strip().casefold(): field for field in reader.fieldnames}
    type_column = normalized_fields.get("type") or normalized_fields.get("asset_type")
    value_column = normalized_fields.get("value")
    if value_column is None:
        raise ImportParseError("CSV requires a value column")
    items: list[ImportItem] = []
    for line_number, row in enumerate(reader, start=2):
        value = (row.get(value_column) or "").strip()
        if not value:
            raise ImportParseError(f"CSV line {line_number} has an empty value")
        kind = (
            _parse_asset_type(row.get(type_column, "")) if type_column else infer_asset_type(value)
        )
        items.append(ImportItem(kind, value))
    return items


def _json_item(item: Any, index: int) -> ImportItem:
    if isinstance(item, str):
        return ImportItem(infer_asset_type(item), item)
    if isinstance(item, dict):
        value = item.get("value")
        kind = item.get("type", item.get("asset_type"))
        if not isinstance(value, str) or not value.strip():
            raise ImportParseError(f"JSON item {index} requires a non-empty string value")
        if kind is not None and not isinstance(kind, str):
            raise ImportParseError(f"JSON item {index} type must be a string")
        return ImportItem(_parse_asset_type(kind) if kind else infer_asset_type(value), value)
    raise ImportParseError(f"JSON item {index} must be a string or object")


def _parse_json(text: str) -> list[ImportItem]:
    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ImportParseError(f"Invalid JSON at line {exc.lineno}") from exc
    if isinstance(payload, dict):
        payload = payload.get("assets")
    if not isinstance(payload, list):
        raise ImportParseError("JSON must be an array or an object with an assets array")
    return [_json_item(item, index) for index, item in enumerate(payload, start=1)]


def parse_import_file(filename: str, content: bytes) -> list[ImportItem]:
    if not content:
        raise ImportParseError("Import file is empty")
    suffix = PurePath(filename).suffix.casefold()
    text = _decode(content)
    parsers = {".txt": _parse_txt, ".csv": _parse_csv, ".json": _parse_json}
    parser = parsers.get(suffix)
    if parser is None:
        raise ImportParseError("Only .txt, .csv, and .json imports are supported in phase 1")
    items = parser(text)
    if not items:
        raise ImportParseError("Import file contains no assets")
    return items
