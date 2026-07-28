from datetime import UTC, datetime, timedelta
from pathlib import Path

from scopegraph.application.errors import ScopeGraphError
from scopegraph.infrastructure.config import get_settings
from scopegraph.schemas.phase6 import StorageCleanupRead, StorageRead


def _classified_files(root: Path) -> list[tuple[Path, str]]:
    files: list[tuple[Path, str]] = []
    if not root.exists():
        return files
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).parts
        category = "export" if "exports" in relative else "raw"
        files.append((path, category))
    return files


def storage_status() -> StorageRead:
    root = get_settings().data_root.resolve()
    files = _classified_files(root)
    raw = sum(path.stat().st_size for path, category in files if category == "raw")
    exports = sum(path.stat().st_size for path, category in files if category == "export")
    return StorageRead(
        total_bytes=raw + exports,
        raw_artifact_bytes=raw,
        export_bytes=exports,
        file_count=len(files),
    )


def cleanup_storage(
    *,
    raw_artifacts: bool,
    exports: bool,
    older_than_days: int,
    confirmation: bool,
) -> StorageCleanupRead:
    if not confirmation:
        raise ScopeGraphError(
            "STORAGE_CLEANUP_CONFIRMATION_REQUIRED",
            "Storage cleanup requires explicit confirmation",
            status_code=409,
        )
    if not raw_artifacts and not exports:
        raise ScopeGraphError(
            "STORAGE_CLEANUP_EMPTY",
            "Select raw artifacts or exports for cleanup",
            status_code=422,
        )
    root = get_settings().data_root.resolve()
    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    if older_than_days == 0:
        # Some filesystems round mtime slightly ahead of the process clock.
        cutoff += timedelta(seconds=2)
    deleted = 0
    reclaimed = 0
    for path, category in _classified_files(root):
        if (category == "raw" and not raw_artifacts) or (category == "export" and not exports):
            continue
        modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
        if modified > cutoff:
            continue
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            continue
        size = resolved.stat().st_size
        resolved.unlink()
        deleted += 1
        reclaimed += size
    return StorageCleanupRead(deleted_files=deleted, reclaimed_bytes=reclaimed)
