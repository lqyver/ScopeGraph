import asyncio
from datetime import UTC, datetime
from uuid import UUID

import dramatiq
from dramatiq.brokers.redis import RedisBroker

from scopegraph.application.services.enterprise import (
    execute_enterprise_discovery as execute_enterprise_service,
)
from scopegraph.application.services.scan_execution import execute_scan_run as execute_run_service
from scopegraph.infrastructure.config import get_settings
from scopegraph.infrastructure.logging import configure_logging

settings = get_settings()
configure_logging(settings.log_level)

broker = RedisBroker(url=settings.redis_url)  # type: ignore[no-untyped-call]
dramatiq.set_broker(broker)


@dramatiq.actor(max_retries=0, time_limit=10_000)
def heartbeat() -> dict[str, str]:
    """Small non-scanning actor used to verify worker wiring in phase 0."""
    return {"status": "ok", "observed_at": datetime.now(UTC).isoformat()}


@dramatiq.actor(max_retries=1, min_backoff=5_000, time_limit=86_400_000)
def execute_scan_run(scan_run_id: str) -> None:
    """Execute a persisted scan DAG; every target is rechecked against Scope in the worker."""
    asyncio.run(execute_run_service(UUID(scan_run_id)))


@dramatiq.actor(max_retries=0, time_limit=120_000)
def execute_enterprise_discovery(discovery_run_id: str) -> None:
    """Collect passive enterprise evidence while persisting each source-stage result."""
    asyncio.run(execute_enterprise_service(UUID(discovery_run_id)))
