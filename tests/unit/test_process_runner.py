import asyncio
import sys
from pathlib import Path
from uuid import uuid4

import pytest

from scopegraph.domain.enums import ScanStatus
from scopegraph.tooling.artifacts import ArtifactStore
from scopegraph.tooling.process import SafeProcessRunner


def make_runner(tmp_path: Path) -> tuple[SafeProcessRunner, Path]:
    store = ArtifactStore(tmp_path)
    directory = store.job_directory(uuid4(), uuid4(), uuid4())
    return SafeProcessRunner(store), directory


@pytest.mark.asyncio
async def test_runner_captures_output_without_a_shell(tmp_path: Path) -> None:
    runner, directory = make_runner(tmp_path)
    outcome = await runner.run(
        [sys.executable, "-c", "print('fixture-output')"],
        job_directory=directory,
        timeout_seconds=5,
    )
    assert outcome.status is ScanStatus.SUCCESS
    assert outcome.exit_code == 0
    assert outcome.stdout.absolute_path.read_text(encoding="utf-8").strip() == "fixture-output"
    assert len(outcome.stdout.sha256) == 64


@pytest.mark.asyncio
async def test_runner_times_out_and_cancels_processes(tmp_path: Path) -> None:
    runner, timeout_directory = make_runner(tmp_path)
    timed_out = await runner.run(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        job_directory=timeout_directory,
        timeout_seconds=1,
    )
    assert timed_out.status is ScanStatus.TIMEOUT

    runner, cancel_directory = make_runner(tmp_path)
    cancellation = asyncio.Event()

    async def request_cancel() -> None:
        await asyncio.sleep(0.05)
        cancellation.set()

    cancel_task = asyncio.create_task(request_cancel())
    cancelled = await runner.run(
        [sys.executable, "-c", "import time; time.sleep(5)"],
        job_directory=cancel_directory,
        timeout_seconds=5,
        cancellation=cancellation,
    )
    await cancel_task
    assert cancelled.status is ScanStatus.CANCELLED


@pytest.mark.asyncio
async def test_runner_caps_stdout_before_artifact_growth(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    directory = store.job_directory(uuid4(), uuid4(), uuid4())
    runner = SafeProcessRunner(store, max_stdout_bytes=1024)

    outcome = await runner.run(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1048576)"],
        job_directory=directory,
        timeout_seconds=5,
    )

    assert outcome.status is ScanStatus.FAILED
    assert outcome.error_code == "TOOL_OUTPUT_LIMIT"
    assert outcome.stdout.size_bytes <= 1024


@pytest.mark.asyncio
async def test_runner_rejects_oversized_side_artifacts(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    directory = store.job_directory(uuid4(), uuid4(), uuid4())
    screenshots = directory / "screenshots"
    runner = SafeProcessRunner(
        store,
        max_side_artifact_bytes=1024,
        max_side_artifact_file_bytes=1024,
    )

    outcome = await runner.run(
        [
            sys.executable,
            "-c",
            (
                "import pathlib,sys; p=pathlib.Path(sys.argv[1]); "
                "p.mkdir(parents=True,exist_ok=True); "
                "(p/'capture.bin').write_bytes(b'x'*4096)"
            ),
            str(screenshots),
        ],
        job_directory=directory,
        timeout_seconds=5,
        side_artifact_directory=screenshots,
    )

    assert outcome.status is ScanStatus.FAILED
    assert outcome.error_code == "TOOL_OUTPUT_LIMIT"
    assert outcome.side_artifacts == ()


@pytest.mark.asyncio
async def test_runner_cancellation_terminates_descendant_processes(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived.txt"
    child_code = (
        "import pathlib,time; time.sleep(1); "
        f"pathlib.Path({str(marker)!r}).write_text('survived'); time.sleep(5)"
    )
    parent_code = (
        "import subprocess,sys,time; "
        f"subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
        "print('ready',flush=True); time.sleep(5)"
    )
    runner, directory = make_runner(tmp_path)
    cancellation = asyncio.Event()

    async def request_cancel() -> None:
        await asyncio.sleep(0.1)
        cancellation.set()

    cancel_task = asyncio.create_task(request_cancel())
    outcome = await runner.run(
        [sys.executable, "-c", parent_code],
        job_directory=directory,
        timeout_seconds=5,
        cancellation=cancellation,
    )
    await cancel_task
    await asyncio.sleep(1.2)

    assert outcome.status is ScanStatus.CANCELLED
    assert not marker.exists()


def test_artifact_store_rejects_user_controlled_names(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    directory = store.job_directory(uuid4(), uuid4(), uuid4())
    with pytest.raises(ValueError):
        store.path_for(directory, "../outside")
    attempt = store.attempt_directory(directory, 1)
    assert attempt.is_relative_to(tmp_path)
    with pytest.raises(ValueError):
        store.attempt_directory(directory, 0)
