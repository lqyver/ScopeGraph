"""Safe external-tool adapter framework."""

from scopegraph.tooling.base import AdapterContext, ToolAdapter, ToolManifest
from scopegraph.tooling.process import ProcessOutcome, SafeProcessRunner

__all__ = [
    "AdapterContext",
    "ProcessOutcome",
    "SafeProcessRunner",
    "ToolAdapter",
    "ToolManifest",
]
