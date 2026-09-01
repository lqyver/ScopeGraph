"""Deterministic medium-capacity acceptance benchmark for the Phase 7 release.

Run inside the API image so it uses the same PostgreSQL driver and models as production:
docker compose run --rm -e PYTHONPATH=/app -v ./tests:/app/tests api `
  python tests/performance/phase7_capacity.py
"""

import asyncio
import json
import tempfile
import tracemalloc
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from time import perf_counter
from uuid import UUID, uuid4

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from scopegraph.application.services.history import compare_scan_runs
from scopegraph.domain.enums import (
    AssetType,
    CandidateRootStatus,
    OwnershipStatus,
    ProjectStatus,
    ScanProfile,
    ScanStatus,
    ScopeStatus,
)
from scopegraph.domain.models import Asset, CandidateRootDomain, Observation, Project, ScanRun
from scopegraph.infrastructure.database import async_session_factory, dispose_engine
from scopegraph.tooling.adapters.dnsx import DnsxAdapter
from scopegraph.tooling.adapters.httpx import HttpxAdapter
from scopegraph.tooling.adapters.screenshot import ScreenshotAdapter
from scopegraph.tooling.base import AdapterContext

CANDIDATES = 10_000
BATCH_TARGETS = 1_000
SCREENSHOTS = 500
OBSERVATIONS = 100_000


def elapsed(start: float) -> float:
    return round(perf_counter() - start, 3)


def parse_batches(project_id: UUID, run_id: UUID) -> dict[str, float | int]:
    context = AdapterContext(
        project_id=project_id,
        scan_run_id=run_id,
        source_version="capacity-fixture-1",
        raw_artifact_path="performance/generated.jsonl",
    )
    with tempfile.TemporaryDirectory(prefix="scopegraph-capacity-") as raw_directory:
        directory = Path(raw_directory)
        dns_path = directory / "dnsx.jsonl"
        http_path = directory / "httpx.jsonl"
        dns_path.write_text(
            "\n".join(
                json.dumps({"host": f"d{i}.example.com", "a": [f"198.51.100.{i % 250 + 1}"]})
                for i in range(BATCH_TARGETS)
            )
            + "\n",
            encoding="utf-8",
        )
        http_path.write_text(
            "\n".join(
                json.dumps(
                    {
                        "input": f"d{i}.example.com",
                        "url": f"https://d{i}.example.com/",
                        "final_url": f"https://d{i}.example.com/",
                        "host": f"d{i}.example.com",
                        "port": "443",
                        "status_code": 200,
                        "title": "Capacity fixture",
                        "content_type": "text/html",
                        "content_length": 128,
                        "time": "25ms",
                        "tech": ["nginx"],
                        "a": [f"198.51.100.{i % 250 + 1}"],
                        "cname": [],
                        "cdn": False,
                        "method": "GET",
                    }
                )
                for i in range(BATCH_TARGETS)
            )
            + "\n",
            encoding="utf-8",
        )
        started = perf_counter()
        dns_observations = DnsxAdapter().parse_output(dns_path, context)
        dns_seconds = elapsed(started)
        started = perf_counter()
        http_observations = HttpxAdapter().parse_output(http_path, context)
        http_seconds = elapsed(started)
    assert len(dns_observations) == BATCH_TARGETS
    assert len(http_observations) >= BATCH_TARGETS
    return {
        "dns_targets": BATCH_TARGETS,
        "dns_observations": len(dns_observations),
        "dns_seconds": dns_seconds,
        "http_targets": BATCH_TARGETS,
        "http_observations": len(http_observations),
        "http_seconds": http_seconds,
    }


def plan_screenshots() -> dict[str, float | int]:
    urls = [f"https://shot{i}.example.com/" for i in range(SCREENSHOTS)]
    started = perf_counter()
    adapter = ScreenshotAdapter()
    validated = adapter.validate_input({"urls": urls, "concurrency": 5, "rate": 20})
    command = adapter.build_command(validated)
    stdin = adapter.stdin_bytes(validated)
    seconds = elapsed(started)
    assert stdin is not None and len(stdin.splitlines()) == SCREENSHOTS
    assert command[command.index("-threads") + 1] == "5"
    assert command[command.index("-rate-limit") + 1] == "20"
    return {"planned_tasks": SCREENSHOTS, "seconds": seconds}


async def insert_candidates(session: object, project_id: UUID) -> dict[str, float | int]:
    asset_rows: list[dict[str, object]] = []
    candidate_rows: list[dict[str, object]] = []
    for index in range(CANDIDATES):
        asset_id = uuid4()
        domain = f"candidate-{index}.example.com"
        asset_rows.append(
            {
                "id": asset_id,
                "project_id": project_id,
                "asset_type": AssetType.DOMAIN,
                "normalized_value": domain,
                "display_value": domain,
                "normalized_key": f"domain:{domain}",
                "scope_status": ScopeStatus.PENDING_REVIEW,
                "ownership_status": OwnershipStatus.PENDING_REVIEW,
                "confidence_score": 0,
                "metadata_json": {},
                "is_active": True,
            }
        )
        candidate_rows.append(
            {
                "id": uuid4(),
                "project_id": project_id,
                "discovery_run_id": None,
                "asset_id": asset_id,
                "root_domain": domain,
                "display_domain": domain,
                "score": 0,
                "raw_score": 0,
                "status": CandidateRootStatus.PENDING_REVIEW,
                "source_count": 1,
                "evidence_summary": [],
                "source_failures": [],
            }
        )
    started = perf_counter()
    for offset in range(0, CANDIDATES, 2_000):
        await session.execute(pg_insert(Asset), asset_rows[offset : offset + 2_000])  # type: ignore[attr-defined]
        statement = pg_insert(CandidateRootDomain).values(candidate_rows[offset : offset + 2_000])
        await session.execute(  # type: ignore[attr-defined]
            statement.on_conflict_do_nothing(index_elements=["project_id", "root_domain"])
        )
    await session.commit()  # type: ignore[attr-defined]
    inserted_seconds = elapsed(started)
    started = perf_counter()
    for offset in range(0, CANDIDATES, 2_000):
        statement = pg_insert(CandidateRootDomain).values(candidate_rows[offset : offset + 2_000])
        await session.execute(  # type: ignore[attr-defined]
            statement.on_conflict_do_nothing(index_elements=["project_id", "root_domain"])
        )
    await session.commit()  # type: ignore[attr-defined]
    dedup_seconds = elapsed(started)
    count = await session.scalar(  # type: ignore[attr-defined]
        select(func.count(CandidateRootDomain.id)).where(
            CandidateRootDomain.project_id == project_id
        )
    )
    assert count == CANDIDATES
    return {
        "input": CANDIDATES * 2,
        "unique": int(count),
        "insert_seconds": inserted_seconds,
        "dedup_seconds": dedup_seconds,
    }


def observation_rows(project_id: UUID, run_id: UUID, offset: int) -> list[dict[str, object]]:
    now = datetime.now(UTC)
    rows: list[dict[str, object]] = []
    per_run = OBSERVATIONS // 2
    for index in range(offset, min(offset + 5_000, per_run)):
        identity = f"observed-{index}.example.com"
        digest = sha256(f"{run_id}:{identity}".encode()).hexdigest()
        rows.append(
            {
                "id": uuid4(),
                "project_id": project_id,
                "scan_run_id": run_id,
                "source_tool": "capacity",
                "source_version": "1",
                "subject_type": "domain",
                "subject_value": identity,
                "predicate": "RESOLVES_TO",
                "object_type": "ip",
                "object_value": "198.51.100.1",
                "attributes": {"generation": 2 if index < 5_000 and run_id.int % 2 else 1},
                "raw_artifact_path": "performance/generated.jsonl",
                "observed_at": now,
                "observation_hash": digest,
            }
        )
    return rows


async def insert_and_merge_observations(
    session: object, project_id: UUID, first_run: UUID, second_run: UUID
) -> dict[str, float | int]:
    started = perf_counter()
    for run_id in (first_run, second_run):
        for offset in range(0, OBSERVATIONS // 2, 5_000):
            await session.execute(  # type: ignore[attr-defined]
                pg_insert(Observation), observation_rows(project_id, run_id, offset)
            )
    await session.commit()  # type: ignore[attr-defined]
    insert_seconds = elapsed(started)
    count = await session.scalar(  # type: ignore[attr-defined]
        select(func.count(Observation.id)).where(Observation.project_id == project_id)
    )
    assert count == OBSERVATIONS
    started = perf_counter()
    diff = await compare_scan_runs(session, project_id, first_run, second_run)  # type: ignore[arg-type]
    merge_seconds = elapsed(started)
    assert sum(diff.counts.values()) <= OBSERVATIONS // 2
    return {
        "rows": int(count),
        "insert_seconds": insert_seconds,
        "query_merge_seconds": merge_seconds,
        "diff_items": sum(diff.counts.values()),
    }


async def benchmark() -> None:
    tracemalloc.start()
    project_id = uuid4()
    first_run = uuid4()
    second_run = UUID(int=first_run.int ^ 1)
    now = datetime.now(UTC)
    async with async_session_factory() as session:
        session.add(
            Project(
                id=project_id,
                name="Phase 7 capacity acceptance",
                company_name="ScopeGraph Performance Fixture",
                company_normalized_name="scopegraph performance fixture",
                status=ProjectStatus.DRAFT,
                default_scan_profile=ScanProfile.STANDARD,
                authorization_confirmed_at=now,
                retention_policy={"raw_artifacts": "TEMPORARY"},
            )
        )
        session.add_all(
            [
                ScanRun(
                    id=run_id,
                    project_id=project_id,
                    profile=ScanProfile.STANDARD,
                    execution_mode="fixture",
                    config_snapshot={"execution_mode": "fixture"},
                    status=ScanStatus.SUCCESS,
                    progress=100,
                    started_at=now,
                    finished_at=now,
                    summary={},
                )
                for run_id in (first_run, second_run)
            ]
        )
        await session.commit()
        try:
            candidate_result = await insert_candidates(session, project_id)
            parser_result = parse_batches(project_id, first_run)
            screenshot_result = plan_screenshots()
            observation_result = await insert_and_merge_observations(
                session, project_id, first_run, second_run
            )
        finally:
            await session.execute(delete(Project).where(Project.id == project_id))
            await session.commit()
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result = {
        "candidate_domains": candidate_result,
        "dns_http_batch": parser_result,
        "screenshot_queue_plan": screenshot_result,
        "observations": observation_result,
        "python_peak_mib": round(peak / 1024 / 1024, 1),
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    await dispose_engine()


if __name__ == "__main__":
    asyncio.run(benchmark())
