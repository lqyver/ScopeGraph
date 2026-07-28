from datetime import UTC, datetime
from uuid import uuid4

from scopegraph.domain.enums import AssetType
from scopegraph.scanning.observations import ObservationObject, ObservationPayload


def test_observation_normalizes_values_and_has_stable_hash() -> None:
    project_id = uuid4()
    scan_run_id = uuid4()
    payload = ObservationPayload(
        project_id=project_id,
        scan_run_id=scan_run_id,
        source_tool="dnsx",
        source_version="1.2.3",
        observed_at=datetime.now(UTC),
        subject=ObservationObject(type=AssetType.DOMAIN, value="API.Example.COM."),
        predicate="RESOLVES_TO",
        object=ObservationObject(type=AssetType.IP, value="192.0.2.10"),
        raw_artifact_path="projects/p/runs/r/jobs/j/stdout.jsonl",
    )
    assert payload.subject.value == "api.example.com"
    assert (
        payload.observation_hash()
        == payload.model_copy(
            update={"observed_at": datetime(2020, 1, 1, tzinfo=UTC)}
        ).observation_hash()
    )
    assert (
        payload.observation_hash()
        != payload.model_copy(update={"scan_run_id": uuid4()}).observation_hash()
    )
