import asyncio
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from scopegraph import __version__
from scopegraph.infrastructure.config import get_settings

router = APIRouter(tags=["system"])


class HealthCheck(BaseModel):
    status: Literal["healthy", "unhealthy"]
    latency_ms: float | None = None
    detail: str | None = None


class HealthReport(BaseModel):
    status: Literal["healthy", "unhealthy"]
    version: str
    edition: Literal["internal", "community"]
    environment: str
    checked_at: datetime
    checks: dict[str, HealthCheck]


async def check_database(database_url: str) -> HealthCheck:
    started = perf_counter()
    engine = create_async_engine(database_url, pool_pre_ping=True)
    try:
        async with asyncio.timeout(3):
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        return HealthCheck(status="healthy", latency_ms=round((perf_counter() - started) * 1000, 2))
    except Exception as exc:  # health boundary intentionally classifies all driver failures
        return HealthCheck(status="unhealthy", detail=type(exc).__name__)
    finally:
        await engine.dispose()


async def check_redis(redis_url: str) -> HealthCheck:
    started = perf_counter()
    client = Redis.from_url(redis_url, decode_responses=True)
    try:
        async with asyncio.timeout(3):
            await client.ping()
        return HealthCheck(status="healthy", latency_ms=round((perf_counter() - started) * 1000, 2))
    except Exception as exc:  # health boundary intentionally classifies all driver failures
        return HealthCheck(status="unhealthy", detail=type(exc).__name__)
    finally:
        await client.aclose()


async def check_storage(data_root: Path) -> HealthCheck:
    try:
        system_dir = data_root / "system"
        system_dir.mkdir(parents=True, exist_ok=True)
        probe = system_dir / ".healthcheck"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return HealthCheck(status="healthy")
    except OSError as exc:
        return HealthCheck(status="unhealthy", detail=type(exc).__name__)


async def build_health_report() -> HealthReport:
    settings = get_settings()
    database, redis, storage = await asyncio.gather(
        check_database(settings.database_url),
        check_redis(settings.redis_url),
        check_storage(settings.data_root),
    )
    checks = {
        "api": HealthCheck(status="healthy"),
        "database": database,
        "redis": redis,
        "storage": storage,
    }
    overall = (
        "healthy" if all(check.status == "healthy" for check in checks.values()) else "unhealthy"
    )
    return HealthReport(
        status=overall,
        version=__version__,
        edition=settings.edition,
        environment=settings.environment,
        checked_at=datetime.now(UTC),
        checks=checks,
    )


@router.get("/health", response_model=HealthReport)
@router.get("/api/v1/system/health", response_model=HealthReport)
async def health() -> HealthReport:
    return await build_health_report()
