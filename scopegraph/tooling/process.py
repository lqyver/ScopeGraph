import asyncio
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from time import monotonic

from scopegraph.domain.enums import ScanStatus
from scopegraph.tooling.artifacts import ArtifactStore, StoredArtifact


@dataclass(frozen=True, slots=True)
class ProcessOutcome:
    status: ScanStatus
    exit_code: int | None
    duration_seconds: float
    stdout: StoredArtifact
    stderr: StoredArtifact
    error_code: str | None = None
    error_message: str | None = None


class SafeProcessRunner:
    def __init__(self, artifact_store: ArtifactStore, *, max_stdin_bytes: int = 10 * 1024 * 1024):
        self.artifact_store = artifact_store
        self.max_stdin_bytes = max_stdin_bytes

    @staticmethod
    def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
        argv = tuple(command)
        if not argv or len(argv) > 100:
            raise ValueError("Command must contain between 1 and 100 arguments")
        if any(not item or len(item) > 8192 or "\x00" in item for item in argv):
            raise ValueError("Command contains an invalid argument")
        return argv

    async def run(
        self,
        command: Sequence[str],
        *,
        job_directory: Path,
        timeout_seconds: int,
        stdin: bytes | None = None,
        cancellation: asyncio.Event | None = None,
        stdout_name: str = "stdout.raw",
        stderr_name: str = "stderr.log",
        working_directory: Path | None = None,
    ) -> ProcessOutcome:
        argv = self._validate_command(command)
        if timeout_seconds <= 0 or timeout_seconds > 86_400:
            raise ValueError("Timeout must be between 1 and 86400 seconds")
        if stdin is not None and len(stdin) > self.max_stdin_bytes:
            raise ValueError("Tool input exceeds the configured maximum")
        if working_directory is not None and not await asyncio.to_thread(working_directory.is_dir):
            raise ValueError("Working directory must be an existing directory")

        stdout_path = self.artifact_store.path_for(job_directory, stdout_name)
        stderr_path = self.artifact_store.path_for(job_directory, stderr_name)
        started = monotonic()
        outcome_status = ScanStatus.FAILED
        error_code: str | None = None
        error_message: str | None = None
        exit_code: int | None = None

        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            try:
                stdin_target = (
                    asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL
                )
                if os.name == "nt":
                    process = await asyncio.create_subprocess_exec(  # noqa: S603
                        *argv,
                        stdin=stdin_target,
                        stdout=stdout_handle,
                        stderr=stderr_handle,
                        cwd=working_directory,
                        creationflags=0x00000200,  # CREATE_NEW_PROCESS_GROUP
                    )
                else:
                    process = await asyncio.create_subprocess_exec(  # noqa: S603
                        *argv,
                        stdin=stdin_target,
                        stdout=stdout_handle,
                        stderr=stderr_handle,
                        cwd=working_directory,
                        start_new_session=True,
                    )
            except FileNotFoundError as exc:
                error_code = "TOOL_UNAVAILABLE"
                error_message = str(exc)
                outcome_status = ScanStatus.SKIPPED
            else:
                if stdin is not None and process.stdin is not None:
                    process.stdin.write(stdin)
                    await process.stdin.drain()
                    process.stdin.close()

                wait_task = asyncio.create_task(process.wait())
                cancel_task = (
                    asyncio.create_task(cancellation.wait()) if cancellation is not None else None
                )
                wait_set = {wait_task}
                if cancel_task is not None:
                    wait_set.add(cancel_task)
                done, pending = await asyncio.wait(
                    wait_set, timeout=timeout_seconds, return_when=asyncio.FIRST_COMPLETED
                )
                if not done:
                    await self._terminate(process)
                    outcome_status = ScanStatus.TIMEOUT
                    error_code = "TOOL_TIMEOUT"
                    error_message = f"Tool exceeded {timeout_seconds} seconds"
                elif cancel_task is not None and cancel_task in done:
                    await self._terminate(process)
                    outcome_status = ScanStatus.CANCELLED
                    error_code = "USER_CANCELLED"
                    error_message = "Tool execution was cancelled"
                else:
                    exit_code = wait_task.result()
                    outcome_status = ScanStatus.SUCCESS if exit_code == 0 else ScanStatus.FAILED
                    if exit_code != 0:
                        error_code = "TOOL_EXIT_NONZERO"
                        error_message = f"Tool exited with code {exit_code}"
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)

        return ProcessOutcome(
            status=outcome_status,
            exit_code=exit_code,
            duration_seconds=round(monotonic() - started, 3),
            stdout=self.artifact_store.describe(stdout_path),
            stderr=self.artifact_store.describe(stderr_path),
            error_code=error_code,
            error_message=error_message,
        )

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            process.kill()
            await process.wait()
