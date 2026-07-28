import pytest
from pydantic import ValidationError

from scopegraph.schemas.projects import ProjectCreate, ProjectDeleteRequest


def test_project_creation_requires_authorization_confirmation() -> None:
    with pytest.raises(ValidationError):
        ProjectCreate(
            name="Example",
            company_name="Example Ltd.",
            authorization_confirmed=False,
        )


def test_project_deletion_requires_a_non_empty_confirmation() -> None:
    with pytest.raises(ValidationError):
        ProjectDeleteRequest(confirmation="")
