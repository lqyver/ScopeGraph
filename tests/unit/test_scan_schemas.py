import pytest
from pydantic import ValidationError

from scopegraph.domain.enums import ScanProfile
from scopegraph.schemas.scans import ScanRunCreate


def payload(**overrides: object) -> dict[str, object]:
    return {
        "root_domain": "example.com",
        "profile": "standard",
        "execution_mode": "fixture",
        "authorization_confirmed": True,
    } | overrides


def test_scan_request_requires_host_and_full_port_confirmations() -> None:
    with pytest.raises(ValidationError, match="active-execution"):
        ScanRunCreate.model_validate(payload(execution_mode="host"))
    with pytest.raises(ValidationError, match="second confirmation"):
        ScanRunCreate.model_validate(payload(full_port_scan=True))

    request = ScanRunCreate.model_validate(
        payload(
            execution_mode="host",
            allow_active_execution=True,
            full_port_scan=True,
            full_port_confirmation=True,
        )
    )
    assert request.full_port_scan and request.allow_active_execution


def test_custom_profile_is_closed_and_only_valid_for_custom_runs() -> None:
    with pytest.raises(ValidationError, match="required"):
        ScanRunCreate.model_validate(payload(profile="custom"))
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ScanRunCreate.model_validate(
            payload(profile="custom", custom_config={"shell_command": "nmap -A"})
        )
    with pytest.raises(ValidationError, match="only valid"):
        ScanRunCreate.model_validate(payload(custom_config={"port_scan_enabled": False}))

    request = ScanRunCreate.model_validate(
        payload(
            profile="custom",
            custom_config={"port_scan_enabled": False, "ports": [443]},
        )
    )
    assert request.profile is ScanProfile.CUSTOM
    assert request.custom_config and request.custom_config.ports == (443,)


def test_deep_profile_requires_second_confirmation() -> None:
    with pytest.raises(ValidationError, match="Deep scanning requires"):
        ScanRunCreate.model_validate(payload(profile="deep"))
    request = ScanRunCreate.model_validate(payload(profile="deep", deep_confirmation=True))
    assert request.profile is ScanProfile.DEEP and request.deep_confirmation
