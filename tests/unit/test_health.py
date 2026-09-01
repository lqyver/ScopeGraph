from pathlib import Path

import pytest

from scopegraph.application import health as health_module
from scopegraph.application.health import HealthCheck
from scopegraph.infrastructure.config import Settings


@pytest.mark.asyncio
async def test_health_report_is_healthy_when_dependencies_are_ready(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def healthy_database(_: str) -> HealthCheck:
        return HealthCheck(status="healthy", latency_ms=1)

    async def healthy_redis(_: str) -> HealthCheck:
        return HealthCheck(status="healthy", latency_ms=1)

    monkeypatch.setattr(health_module, "check_database", healthy_database)
    monkeypatch.setattr(health_module, "check_redis", healthy_redis)
    monkeypatch.setattr(
        health_module,
        "get_settings",
        lambda: Settings(
            edition="internal", environment="test", data_root=tmp_path, _env_file=None
        ),
    )

    report = await health_module.build_health_report()

    assert report.status == "healthy"
    assert report.edition == "internal"
    assert report.checks["storage"].status == "healthy"


@pytest.mark.asyncio
async def test_health_report_is_unhealthy_when_database_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    async def failed_database(_: str) -> HealthCheck:
        return HealthCheck(status="unhealthy", detail="ConnectionError")

    async def healthy_redis(_: str) -> HealthCheck:
        return HealthCheck(status="healthy")

    monkeypatch.setattr(health_module, "check_database", failed_database)
    monkeypatch.setattr(health_module, "check_redis", healthy_redis)
    monkeypatch.setattr(
        health_module,
        "get_settings",
        lambda: Settings(environment="test", data_root=tmp_path, _env_file=None),
    )

    report = await health_module.build_health_report()

    assert report.status == "unhealthy"
    assert report.checks["database"].detail == "ConnectionError"
