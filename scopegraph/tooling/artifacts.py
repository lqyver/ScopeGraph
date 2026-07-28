import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from uuid import UUID

_safe_name = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    absolute_path: Path
    relative_path: str
    sha256: str
    size_bytes: int


class ArtifactStore:
    def __init__(self, data_root: Path) -> None:
        self.data_root = data_root.resolve()

    def job_directory(self, project_id: UUID, scan_run_id: UUID, scan_job_id: UUID) -> Path:
        directory = (
            self.data_root
            / "projects"
            / str(project_id)
            / "scan_runs"
            / str(scan_run_id)
            / "jobs"
            / str(scan_job_id)
        ).resolve()
        if not directory.is_relative_to(self.data_root):
            raise ValueError("Generated artifact directory escaped the configured data root")
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def path_for(self, directory: Path, name: str) -> Path:
        if not _safe_name.fullmatch(name):
            raise ValueError("Artifact name contains unsupported characters")
        target = (directory / name).resolve()
        if not target.is_relative_to(self.data_root):
            raise ValueError("Artifact path escaped the configured data root")
        return target

    def attempt_directory(self, job_directory: Path, attempt: int) -> Path:
        if attempt < 1 or attempt > 100:
            raise ValueError("Artifact attempt must be between 1 and 100")
        directory = (job_directory / "attempts" / str(attempt)).resolve()
        if not directory.is_relative_to(self.data_root):
            raise ValueError("Artifact attempt directory escaped the configured data root")
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def export_directory(self, project_id: UUID, export_id: UUID) -> Path:
        directory = (
            self.data_root / "projects" / str(project_id) / "exports" / str(export_id)
        ).resolve()
        if not directory.is_relative_to(self.data_root):
            raise ValueError("Generated export directory escaped the configured data root")
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def describe(self, path: Path) -> StoredArtifact:
        resolved = path.resolve()
        if not resolved.is_file() or not resolved.is_relative_to(self.data_root):
            raise ValueError("Artifact must be a file within the configured data root")
        digest = sha256()
        with resolved.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return StoredArtifact(
            absolute_path=resolved,
            relative_path=resolved.relative_to(self.data_root).as_posix(),
            sha256=digest.hexdigest(),
            size_bytes=resolved.stat().st_size,
        )
