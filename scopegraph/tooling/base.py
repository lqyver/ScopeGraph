import re
import shutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from scopegraph.scanning.observations import ObservationPayload


class ParsedObservations(list[ObservationPayload]):
    """Parsed observations plus bounded, adapter-provided audit counters."""

    def __init__(
        self,
        values: list[ObservationPayload] | None = None,
        *,
        diagnostics: dict[str, int] | None = None,
    ) -> None:
        super().__init__(values or [])
        self.diagnostics = diagnostics or {}


class ToolManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{1,49}$")
    category: str = Field(min_length=1, max_length=100)
    execution_modes: tuple[Literal["docker", "host", "fixture"], ...]
    requires_root: bool = False
    requires_credentials: bool = False
    input_types: tuple[str, ...]
    output_types: tuple[str, ...]
    preferred_output: Literal["json", "jsonl", "text", "xml"]
    version_command: tuple[str, ...]
    version_markers: tuple[str, ...]
    timeout_seconds: int = Field(gt=0, le=86_400)
    minimum_version: str | None = None


def version_output_is_compatible(manifest: ToolManifest, output: str) -> bool:
    folded = output.casefold()
    return any(marker.casefold() in folded for marker in manifest.version_markers)


_ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def clean_tool_output(output: str, *, limit: int = 65_536) -> str:
    """Remove terminal control sequences before storing or displaying tool output."""

    cleaned = _ANSI_ESCAPE.sub("", output).replace("\x00", "")
    return cleaned.strip()[:limit]


def detected_tool_version(output: str) -> str:
    """Return a compact, traceable version string for observations."""

    cleaned = clean_tool_output(output, limit=2_000)
    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    version_line = next(
        (line for line in lines if "version" in line.casefold()),
        lines[0] if lines else "unknown",
    )
    return version_line[:100]


class AdapterContext(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: UUID
    scan_run_id: UUID
    source_version: str = Field(min_length=1, max_length=100)
    raw_artifact_path: str = Field(min_length=1, max_length=4096)


class AdapterError(RuntimeError):
    code = "ADAPTER_ERROR"


class ToolUnavailableError(AdapterError):
    code = "TOOL_UNAVAILABLE"


class OutputParseError(AdapterError):
    code = "OUTPUT_PARSE_ERROR"


class ToolAdapter(ABC):
    manifest: ToolManifest

    def installation_path(self) -> str | None:
        executable = self.manifest.version_command[0]
        return shutil.which(executable)

    def require_installed(self) -> str:
        path = self.installation_path()
        if path is None:
            raise ToolUnavailableError(
                f"{self.manifest.name} is not installed; install it before using host mode"
            )
        return path

    @abstractmethod
    def validate_input(self, payload: dict[str, Any]) -> BaseModel:
        """Validate untrusted job input into a closed schema."""

    @abstractmethod
    def build_command(self, validated_input: BaseModel) -> list[str]:
        """Map validated input to an argv array. Shell strings are forbidden."""

    @abstractmethod
    def stdin_bytes(self, validated_input: BaseModel) -> bytes | None:
        """Return bounded stdin content for tools that read targets from stdin."""

    @abstractmethod
    def parse_output(self, path: Path, context: AdapterContext) -> list[ObservationPayload]:
        """Parse a raw artifact without deleting or rewriting it."""
