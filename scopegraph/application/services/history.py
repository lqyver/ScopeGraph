import json
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from scopegraph.application.errors import ScopeGraphError
from scopegraph.application.services.projects import get_project_or_404
from scopegraph.domain.models import Observation, ScanRun
from scopegraph.schemas.phase6 import DiffItem, ScanDiffRead


def _category(observation: Observation) -> str:
    if observation.predicate == "HAS_FINDING":
        return "finding"
    if observation.predicate == "HAS_ICP_RECORD":
        return "filing"
    if observation.source_tool == "naabu":
        return "port"
    if observation.source_tool == "httpx":
        return "website"
    if observation.source_tool in {"dnsx", "puredns"}:
        return "dns"
    if observation.subject_type == "domain":
        return "domain"
    return "observation"


def _snapshot(observation: Observation) -> dict[str, Any]:
    return {
        "subject_type": observation.subject_type,
        "subject": observation.subject_value,
        "predicate": observation.predicate,
        "object_type": observation.object_type,
        "object": observation.object_value,
        "attributes": observation.attributes,
        "source_tool": observation.source_tool,
        "observed_at": observation.observed_at.isoformat(),
    }


def _identity(observation: Observation) -> str:
    parts = [
        observation.subject_type,
        observation.subject_value,
        observation.predicate,
        observation.object_type or "",
        observation.object_value or "",
    ]
    if observation.source_tool == "naabu":
        parts.extend(
            [str(observation.attributes.get("port")), str(observation.attributes.get("protocol"))]
        )
    if observation.predicate == "HAS_FINDING":
        parts.append(str(observation.attributes.get("template_id")))
    return "|".join(parts)


async def compare_scan_runs(
    session: AsyncSession,
    project_id: UUID,
    from_run_id: UUID,
    to_run_id: UUID,
) -> ScanDiffRead:
    await get_project_or_404(session, project_id)
    runs = list(
        (
            await session.scalars(
                select(ScanRun).where(
                    ScanRun.project_id == project_id, ScanRun.id.in_([from_run_id, to_run_id])
                )
            )
        ).all()
    )
    if len(runs) != 2 or from_run_id == to_run_id:
        raise ScopeGraphError(
            "INVALID_DIFF_RUNS", "Two distinct project scan runs are required", status_code=422
        )
    observations = list(
        (
            await session.scalars(
                select(Observation).where(
                    Observation.project_id == project_id,
                    Observation.scan_run_id.in_([from_run_id, to_run_id]),
                )
            )
        ).all()
    )
    before_rows = {item.id: item for item in observations if item.scan_run_id == from_run_id}
    after_rows = {item.id: item for item in observations if item.scan_run_id == to_run_id}
    before = {_identity(item): item for item in before_rows.values()}
    after = {_identity(item): item for item in after_rows.values()}
    added = [
        DiffItem(
            category=_category(after[key]), identity=key, before=None, after=_snapshot(after[key])
        )
        for key in sorted(after.keys() - before.keys())
    ]
    removed = [
        DiffItem(
            category=_category(before[key]), identity=key, before=_snapshot(before[key]), after=None
        )
        for key in sorted(before.keys() - after.keys())
    ]
    changed: list[DiffItem] = []
    for key in sorted(before.keys() & after.keys()):
        left = _snapshot(before[key])
        right = _snapshot(after[key])
        left.pop("observed_at")
        right.pop("observed_at")
        if json.dumps(left, sort_keys=True, default=str) != json.dumps(
            right, sort_keys=True, default=str
        ):
            changed.append(
                DiffItem(category=_category(after[key]), identity=key, before=left, after=right)
            )
    return ScanDiffRead(
        project_id=project_id,
        from_scan_run_id=from_run_id,
        to_scan_run_id=to_run_id,
        added=added,
        removed=removed,
        changed=changed,
        counts={"added": len(added), "removed": len(removed), "changed": len(changed)},
    )
