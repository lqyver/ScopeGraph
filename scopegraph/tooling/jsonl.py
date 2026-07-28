import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from scopegraph.tooling.base import OutputParseError


def read_jsonl(
    path: Path, *, max_bytes: int = 100 * 1024 * 1024
) -> Iterator[tuple[int, dict[str, Any]]]:
    if path.stat().st_size > max_bytes:
        raise OutputParseError(f"Raw artifact exceeds parser limit of {max_bytes} bytes")
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise OutputParseError(f"Invalid JSONL at line {line_number}: {exc.msg}") from exc
            if not isinstance(value, dict):
                raise OutputParseError(f"Expected an object at JSONL line {line_number}")
            yield line_number, value
