import json
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from scopegraph.domain.enums import ScanStatus


class InvalidStateTransition(ValueError):
    pass


TERMINAL_STATUSES = frozenset(
    {
        ScanStatus.PARTIAL_SUCCESS,
        ScanStatus.SUCCESS,
        ScanStatus.FAILED,
        ScanStatus.TIMEOUT,
        ScanStatus.CANCELLED,
        ScanStatus.SKIPPED,
    }
)

_TRANSITIONS: dict[ScanStatus, frozenset[ScanStatus]] = {
    ScanStatus.PENDING: frozenset({ScanStatus.QUEUED, ScanStatus.CANCELLED, ScanStatus.SKIPPED}),
    ScanStatus.QUEUED: frozenset(
        {ScanStatus.RUNNING, ScanStatus.PAUSED, ScanStatus.CANCELLED, ScanStatus.SKIPPED}
    ),
    ScanStatus.RUNNING: frozenset(
        {
            ScanStatus.PAUSED,
            ScanStatus.PARTIAL_SUCCESS,
            ScanStatus.SUCCESS,
            ScanStatus.FAILED,
            ScanStatus.TIMEOUT,
            ScanStatus.CANCELLED,
        }
    ),
    ScanStatus.PAUSED: frozenset({ScanStatus.QUEUED, ScanStatus.CANCELLED}),
    ScanStatus.PARTIAL_SUCCESS: frozenset({ScanStatus.QUEUED}),
    ScanStatus.FAILED: frozenset({ScanStatus.QUEUED}),
    ScanStatus.TIMEOUT: frozenset({ScanStatus.QUEUED}),
    ScanStatus.SKIPPED: frozenset({ScanStatus.QUEUED}),
    # A completed stage may be intentionally refreshed (for example after
    # disabling a transparent proxy). Retry limits are enforced by the service.
    ScanStatus.SUCCESS: frozenset({ScanStatus.QUEUED}),
    ScanStatus.CANCELLED: frozenset(),
}


def transition(current: ScanStatus, target: ScanStatus) -> ScanStatus:
    if target not in _TRANSITIONS[current]:
        raise InvalidStateTransition(f"Cannot transition scan state from {current} to {target}")
    return target


def make_idempotency_key(job_type: str, adapter_name: str, input_ref: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"adapter": adapter_name, "input": input_ref, "job_type": job_type},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RunAggregate:
    status: ScanStatus
    progress: float
    completed_jobs: int
    total_jobs: int


def aggregate_run_state(
    statuses: Iterable[ScanStatus], *, cancellation_requested: bool = False
) -> RunAggregate:
    jobs = list(statuses)
    total = len(jobs)
    if total == 0:
        status = ScanStatus.CANCELLED if cancellation_requested else ScanStatus.PENDING
        return RunAggregate(status, 0.0, 0, 0)

    completed = sum(status in TERMINAL_STATUSES for status in jobs)
    progress = round(completed * 100 / total, 2)
    if cancellation_requested and all(status in TERMINAL_STATUSES for status in jobs):
        status = ScanStatus.CANCELLED
    elif any(status is ScanStatus.RUNNING for status in jobs):
        status = ScanStatus.RUNNING
    elif any(status is ScanStatus.PAUSED for status in jobs):
        status = ScanStatus.PAUSED
    elif any(status in {ScanStatus.PENDING, ScanStatus.QUEUED} for status in jobs):
        status = ScanStatus.QUEUED
    elif all(status is ScanStatus.SKIPPED for status in jobs):
        status = ScanStatus.SKIPPED
    elif all(status is ScanStatus.SUCCESS for status in jobs):
        status = ScanStatus.SUCCESS
    elif all(status in {ScanStatus.FAILED, ScanStatus.TIMEOUT} for status in jobs):
        status = ScanStatus.FAILED
    else:
        status = ScanStatus.PARTIAL_SUCCESS
    return RunAggregate(status, progress, completed, total)
