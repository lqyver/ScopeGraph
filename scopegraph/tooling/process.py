import asyncio
import os
import signal
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Any, BinaryIO

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
    side_artifacts: tuple[StoredArtifact, ...] = ()


class _ArtifactLimitError(ValueError):
    pass


class SafeProcessRunner:
    def __init__(
        self,
        artifact_store: ArtifactStore,
        *,
        max_stdin_bytes: int = 10 * 1024 * 1024,
        max_stdout_bytes: int = 100 * 1024 * 1024,
        max_stderr_bytes: int = 10 * 1024 * 1024,
        max_side_artifact_bytes: int = 100 * 1024 * 1024,
        max_side_artifact_file_bytes: int = 10 * 1024 * 1024,
        max_side_artifact_files: int = 512,
    ) -> None:
        limits = {
            "max_stdin_bytes": max_stdin_bytes,
            "max_stdout_bytes": max_stdout_bytes,
            "max_stderr_bytes": max_stderr_bytes,
            "max_side_artifact_bytes": max_side_artifact_bytes,
            "max_side_artifact_file_bytes": max_side_artifact_file_bytes,
            "max_side_artifact_files": max_side_artifact_files,
        }
        if any(value <= 0 for value in limits.values()):
            raise ValueError("Process and artifact limits must be positive")
        self.artifact_store = artifact_store
        self.max_stdin_bytes = max_stdin_bytes
        self.max_stdout_bytes = max_stdout_bytes
        self.max_stderr_bytes = max_stderr_bytes
        self.max_side_artifact_bytes = max_side_artifact_bytes
        self.max_side_artifact_file_bytes = max_side_artifact_file_bytes
        self.max_side_artifact_files = max_side_artifact_files

    @staticmethod
    def _validate_command(command: Sequence[str]) -> tuple[str, ...]:
        argv = tuple(command)
        if not argv or len(argv) > 100:
            raise ValueError("Command must contain between 1 and 100 arguments")
        if any(not item or len(item) > 8192 or "\x00" in item for item in argv):
            raise ValueError("Command contains an invalid argument")
        return argv

    @staticmethod
    async def _copy_stream(
        reader: asyncio.StreamReader,
        handle: BinaryIO,
        limit: int,
        exceeded: asyncio.Event,
    ) -> None:
        received = 0
        while chunk := await reader.read(64 * 1024):
            remaining = max(0, limit - received)
            if remaining:
                handle.write(chunk[:remaining])
                handle.flush()
            received += len(chunk)
            if received > limit:
                exceeded.set()

    @staticmethod
    async def _feed_stdin(
        writer: asyncio.StreamWriter | None,
        payload: bytes | None,
    ) -> None:
        if writer is None:
            return
        try:
            if payload is not None:
                writer.write(payload)
                await writer.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _inspect_side_artifacts(
        self,
        root: Path,
        *,
        describe: bool,
    ) -> tuple[StoredArtifact, ...]:
        if not root.exists():
            return ()
        if root.is_symlink() or not root.is_dir():
            raise _ArtifactLimitError("Side artifact root is not a regular directory")

        total_bytes = 0
        file_count = 0
        paths: list[Path] = []
        for current_root, directories, files in os.walk(root, topdown=True, followlinks=False):
            directories.sort()
            files.sort()
            safe_directories: list[str] = []
            for name in directories:
                candidate = Path(current_root) / name
                if candidate.is_symlink():
                    raise _ArtifactLimitError("Side artifact directory contains a symlink")
                safe_directories.append(name)
            directories[:] = safe_directories
            for name in files:
                candidate = Path(current_root) / name
                metadata = candidate.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    raise _ArtifactLimitError("Side artifact is not a regular file")
                file_count += 1
                total_bytes += metadata.st_size
                if file_count > self.max_side_artifact_files:
                    raise _ArtifactLimitError(
                        f"Side artifacts exceed {self.max_side_artifact_files} files"
                    )
                if metadata.st_size > self.max_side_artifact_file_bytes:
                    raise _ArtifactLimitError(
                        "A side artifact exceeds the configured per-file byte limit"
                    )
                if total_bytes > self.max_side_artifact_bytes:
                    raise _ArtifactLimitError(
                        "Side artifacts exceed the configured total byte limit"
                    )
                paths.append(candidate)
        if not describe:
            return ()
        return tuple(self.artifact_store.describe(path) for path in paths)

    async def _monitor_side_artifacts(
        self,
        root: Path,
        stop: asyncio.Event,
    ) -> str | None:
        while not stop.is_set():
            try:
                await asyncio.to_thread(self._inspect_side_artifacts, root, describe=False)
            except (OSError, _ArtifactLimitError) as exc:
                return str(exc)
            try:
                await asyncio.wait_for(stop.wait(), timeout=0.1)
            except TimeoutError:
                continue
        return None

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
        side_artifact_directory: Path | None = None,
    ) -> ProcessOutcome:
        argv = self._validate_command(command)
        if timeout_seconds <= 0 or timeout_seconds > 86_400:
            raise ValueError("Timeout must be between 1 and 86400 seconds")
        if stdin is not None and len(stdin) > self.max_stdin_bytes:
            raise ValueError("Tool input exceeds the configured maximum")
        if working_directory is not None and not await asyncio.to_thread(working_directory.is_dir):
            raise ValueError("Working directory must be an existing directory")

        resolved_job_directory = await asyncio.to_thread(job_directory.resolve)
        side_root: Path | None = None
        if side_artifact_directory is not None:
            side_root = await asyncio.to_thread(side_artifact_directory.resolve)
            if not side_root.is_relative_to(resolved_job_directory):
                raise ValueError("Side artifact directory must stay within the job directory")

        stdout_path = self.artifact_store.path_for(job_directory, stdout_name)
        stderr_path = self.artifact_store.path_for(job_directory, stderr_name)
        started = monotonic()
        outcome_status = ScanStatus.FAILED
        error_code: str | None = None
        error_message: str | None = None
        exit_code: int | None = None
        side_artifacts: tuple[StoredArtifact, ...] = ()

        with stdout_path.open("wb", buffering=0) as stdout_handle, stderr_path.open(
            "wb", buffering=0
        ) as stderr_handle:
            try:
                stdin_target = (
                    asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL
                )
                process_options: dict[str, Any] = {
                    "stdin": stdin_target,
                    "stdout": asyncio.subprocess.PIPE,
                    "stderr": asyncio.subprocess.PIPE,
                    "cwd": working_directory,
                }
                if os.name == "nt":
                    process_options["creationflags"] = 0x00000200  # CREATE_NEW_PROCESS_GROUP
                else:
                    process_options["start_new_session"] = True
                process = await asyncio.create_subprocess_exec(  # noqa: S603
                    *argv,
                    **process_options,
                )
            except FileNotFoundError as exc:
                error_code = "TOOL_UNAVAILABLE"
                error_message = str(exc)
                outcome_status = ScanStatus.SKIPPED
            else:
                if process.stdout is None or process.stderr is None:
                    raise RuntimeError("Subprocess output pipes were not created")
                stdout_exceeded = asyncio.Event()
                stderr_exceeded = asyncio.Event()
                side_stop = asyncio.Event()
                stdout_task = asyncio.create_task(
                    self._copy_stream(
                        process.stdout, stdout_handle, self.max_stdout_bytes, stdout_exceeded
                    )
                )
                stderr_task = asyncio.create_task(
                    self._copy_stream(
                        process.stderr, stderr_handle, self.max_stderr_bytes, stderr_exceeded
                    )
                )
                stdin_task = asyncio.create_task(self._feed_stdin(process.stdin, stdin))
                wait_task = asyncio.create_task(process.wait())
                stdout_limit_task = asyncio.create_task(stdout_exceeded.wait())
                stderr_limit_task = asyncio.create_task(stderr_exceeded.wait())
                cancel_task = (
                    asyncio.create_task(cancellation.wait()) if cancellation is not None else None
                )
                side_task = (
                    asyncio.create_task(self._monitor_side_artifacts(side_root, side_stop))
                    if side_root is not None
                    else None
                )
                waiters: list[asyncio.Task[Any]] = [
                    wait_task,
                    stdout_limit_task,
                    stderr_limit_task,
                ]
                if cancel_task is not None:
                    waiters.append(cancel_task)
                if side_task is not None:
                    waiters.append(side_task)

                done, _ = await asyncio.wait(
                    waiters,
                    timeout=timeout_seconds,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                side_error = (
                    side_task.result()
                    if side_task is not None and side_task in done
                    else None
                )
                if not done:
                    await self._terminate(process)
                    outcome_status = ScanStatus.TIMEOUT
                    error_code = "TOOL_TIMEOUT"
                    error_message = f"Tool exceeded {timeout_seconds} seconds"
                elif stdout_limit_task in done or stderr_limit_task in done or side_error:
                    await self._terminate(process)
                    outcome_status = ScanStatus.FAILED
                    error_code = "TOOL_OUTPUT_LIMIT"
                    if side_error:
                        error_message = f"Tool side artifact limit reached: {side_error}"
                    elif stdout_limit_task in done:
                        error_message = (
                            f"Tool stdout exceeded {self.max_stdout_bytes} bytes"
                        )
                    else:
                        error_message = (
                            f"Tool stderr exceeded {self.max_stderr_bytes} bytes"
                        )
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

                side_stop.set()
                await process.wait()
                await asyncio.gather(stdout_task, stderr_task, stdin_task, return_exceptions=True)
                for task in waiters:
                    if task is not wait_task and not task.done():
                        task.cancel()
                await asyncio.gather(*waiters, return_exceptions=True)

                if side_root is not None and error_code != "TOOL_OUTPUT_LIMIT":
                    try:
                        side_artifacts = await asyncio.to_thread(
                            self._inspect_side_artifacts,
                            side_root,
                            describe=True,
                        )
                    except (OSError, _ArtifactLimitError) as exc:
                        outcome_status = ScanStatus.FAILED
                        error_code = "TOOL_OUTPUT_LIMIT"
                        error_message = f"Tool side artifact limit reached: {exc}"
                        side_artifacts = ()

        return ProcessOutcome(
            status=outcome_status,
            exit_code=exit_code,
            duration_seconds=round(monotonic() - started, 3),
            stdout=self.artifact_store.describe(stdout_path),
            stderr=self.artifact_store.describe(stderr_path),
            error_code=error_code,
            error_message=error_message,
            side_artifacts=side_artifacts,
        )

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process) -> None:
        if os.name == "nt":
            if process.returncode is not None:
                return
            try:
                # CREATE_NEW_PROCESS_GROUP makes CTRL_BREAK_EVENT a group-wide
                # signal, so descendants that inherited the group cannot outlive
                # a cancelled wrapper process.
                process.send_signal(signal.CTRL_BREAK_EVENT)
                await asyncio.wait_for(process.wait(), timeout=1)
                return
            except (ProcessLookupError, TimeoutError):
                pass
            try:
                tree_kill = await asyncio.create_subprocess_exec(  # noqa: S603
                    "taskkill",
                    "/PID",
                    str(process.pid),
                    "/T",
                    "/F",
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(tree_kill.wait(), timeout=5)
                if tree_kill.returncode != 0 and process.returncode is None:
                    process.kill()
            except (FileNotFoundError, TimeoutError):
                process.kill()
            await process.wait()
            return

        kill_process_group = getattr(os, "kill" + "pg", None)
        if kill_process_group is None:
            return
        try:
            kill_process_group(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except PermissionError:
            if process.returncode is None:
                process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except TimeoutError:
            try:
                kill_process_group(process.pid, getattr(signal, "SIGKILL", 9))
            except ProcessLookupError:
                pass
            await process.wait()
