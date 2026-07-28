import pytest

from scopegraph.domain.enums import ScanStatus
from scopegraph.scanning.state_machine import (
    InvalidStateTransition,
    aggregate_run_state,
    make_idempotency_key,
    transition,
)


def test_valid_and_invalid_transitions() -> None:
    assert transition(ScanStatus.PENDING, ScanStatus.QUEUED) is ScanStatus.QUEUED
    assert transition(ScanStatus.FAILED, ScanStatus.QUEUED) is ScanStatus.QUEUED
    assert transition(ScanStatus.SUCCESS, ScanStatus.QUEUED) is ScanStatus.QUEUED
    with pytest.raises(InvalidStateTransition):
        transition(ScanStatus.SUCCESS, ScanStatus.RUNNING)


def test_run_aggregate_distinguishes_progress_from_outcome() -> None:
    aggregate = aggregate_run_state([ScanStatus.SUCCESS, ScanStatus.FAILED])
    assert aggregate.status is ScanStatus.PARTIAL_SUCCESS
    assert aggregate.progress == 100

    running = aggregate_run_state([ScanStatus.SUCCESS, ScanStatus.RUNNING, ScanStatus.QUEUED])
    assert running.status is ScanStatus.RUNNING
    assert running.progress == pytest.approx(33.33)


def test_run_aggregate_cancellation_and_skips() -> None:
    assert aggregate_run_state([], cancellation_requested=True).status is ScanStatus.CANCELLED
    assert aggregate_run_state([ScanStatus.SKIPPED]).status is ScanStatus.SKIPPED
    assert (
        aggregate_run_state(
            [ScanStatus.SUCCESS, ScanStatus.CANCELLED], cancellation_requested=True
        ).status
        is ScanStatus.CANCELLED
    )


def test_idempotency_key_is_canonical_and_input_sensitive() -> None:
    first = make_idempotency_key("passive_subdomain", "subfinder", {"b": 2, "a": 1})
    reordered = make_idempotency_key("passive_subdomain", "subfinder", {"a": 1, "b": 2})
    changed = make_idempotency_key("passive_subdomain", "subfinder", {"a": 2, "b": 2})
    assert first == reordered
    assert first != changed
    assert len(first) == 64
