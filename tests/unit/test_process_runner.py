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


def test_artifact_store_rejects_user_controlled_names(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path)
    directory = store.job_directory(uuid4(), uuid4(), uuid4())
    with pytest.raises(ValueError):
        store.path_for(directory, "../outside")
    attempt = store.attempt_directory(directory, 1)
    assert attempt.is_relative_to(tmp_path)
    with pytest.raises(ValueError):
        store.attempt_directory(directory, 0)
