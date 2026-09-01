from pathlib import Path

from pydantic import SecretStr

from scopegraph.infrastructure.config import Settings


def test_settings_have_safe_local_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.api_url == "http://127.0.0.1:8000"
    assert settings.data_root == Path("data")
    assert settings.edition == "community"
    assert settings.environment == "development"


def test_settings_accept_scopegraph_prefix(monkeypatch: object) -> None:
    monkeypatch.setenv("SCOPEGRAPH_ENVIRONMENT", "test")  # type: ignore[attr-defined]
    monkeypatch.setenv("SCOPEGRAPH_EDITION", "internal")  # type: ignore[attr-defined]
    settings = Settings(_env_file=None)

    assert settings.edition == "internal"
    assert settings.environment == "test"


def test_blank_api_key_is_normalized_to_unconfigured() -> None:
    assert Settings(_env_file=None, api_key="").api_key is None
    assert Settings(_env_file=None, api_key="   ").api_key is None
    configured = Settings(_env_file=None, api_key=SecretStr("local-secret"))
    assert configured.api_key is not None
    assert configured.api_key.get_secret_value() == "local-secret"
