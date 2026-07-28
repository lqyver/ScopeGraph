"""Scan runtime primitives shared by the API and worker."""

from scopegraph.scanning.state_machine import aggregate_run_state, transition

__all__ = ["aggregate_run_state", "transition"]
