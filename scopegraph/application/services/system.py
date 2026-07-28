import asyncio
import json
from pathlib import Path

from scopegraph.application.errors import ScopeGraphError
from scopegraph.infrastructure.config import get_settings
from scopegraph.schemas.system import (
    SystemSettingsPatch,
    SystemSettingsRead,
    ToolStatusRead,
    ToolUpdateRead,
)
from scopegraph.tooling.adapters import ADAPTERS
from scopegraph.tooling.base import (
    clean_tool_output,
    detected_tool_version,
    version_output_is_compatible,
)


async def _tool_status(name: str) -> ToolStatusRead:
    adapter = ADAPTERS[name]
    path = adapter.installation_path()
    if path is None:
        return ToolStatusRead(
            name=name,
            category=adapter.manifest.category,
            installed=False,
            installation_path=None,
            version_output=None,
            compatible=False,
            minimum_version=adapter.manifest.minimum_version,
            error="Tool is not installed in the API runtime PATH",
        )
    command = [path, *adapter.manifest.version_command[1:]]
    try:
        process = await asyncio.create_subprocess_exec(  # noqa: S603
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=8)
        output = clean_tool_output((stdout + stderr).decode("utf-8", errors="replace"))
    except (OSError, TimeoutError) as exc:
        return ToolStatusRead(
            name=name,
            category=adapter.manifest.category,
            installed=True,
            installation_path=path,
            version_output=None,
            compatible=False,
            minimum_version=adapter.manifest.minimum_version,
            error=f"{type(exc).__name__}: {exc}",
        )
    return ToolStatusRead(
        name=name,
        category=adapter.manifest.category,
        installed=True,
        installation_path=path,
        version_output=detected_tool_version(output),
        compatible=process.returncode == 0
        and version_output_is_compatible(adapter.manifest, output),
        minimum_version=adapter.manifest.minimum_version,
        error=None if process.returncode == 0 else f"Version command exited {process.returncode}",
    )


async def list_tools() -> list[ToolStatusRead]:
    return list(await asyncio.gather(*(_tool_status(name) for name in sorted(ADAPTERS))))


async def check_tool(name: str) -> ToolStatusRead:
    if name not in ADAPTERS:
        raise ScopeGraphError("TOOL_NOT_FOUND", "Tool adapter was not found", status_code=404)
    return await _tool_status(name)


def request_tool_update(name: str, confirmation: bool) -> ToolUpdateRead:
    if name not in ADAPTERS:
        raise ScopeGraphError("TOOL_NOT_FOUND", "Tool adapter was not found", status_code=404)
    if not confirmation:
        raise ScopeGraphError(
            "TOOL_UPDATE_CONFIRMATION_REQUIRED",
            "Tool update requires explicit confirmation",
            status_code=409,
        )
    return ToolUpdateRead(
        name=name,
        message=(
            "ScopeGraph never performs silent tool updates. Update the pinned host/container tool "
            "manually, then run check-update; incompatible parsers remain blocked."
        ),
    )


def _settings_path() -> Path:
    root = get_settings().data_root.resolve()
    directory = (root / "system").resolve()
    if not directory.is_relative_to(root):
        raise ValueError("System settings path escaped the data root")
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "settings.json"


def read_system_settings() -> SystemSettingsRead:
    settings = get_settings()
    path = _settings_path()
    proxy_url = None
    if path.is_file():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            proxy_url = payload.get("proxy_url") if isinstance(payload, dict) else None
        except (OSError, json.JSONDecodeError):
            proxy_url = None
    return SystemSettingsRead(
        proxy_url=proxy_url,
        public_bind=settings.public_bind,
        api_key_configured=settings.api_key is not None,
    )


def update_system_settings(payload: SystemSettingsPatch) -> SystemSettingsRead:
    path = _settings_path()
    temporary = path.with_suffix(".tmp")
    temporary.write_text(
        json.dumps({"proxy_url": payload.proxy_url}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    temporary.replace(path)
    return read_system_settings()
