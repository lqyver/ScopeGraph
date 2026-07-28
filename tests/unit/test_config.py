from pathlib import Path

from scopegraph.infrastructure.config import Settings


def test_settings_have_safe_local_defaults() -> None:
    settings = Settings(_env_file=None)

    assert settings.api_url == "http://127.0.0.1:8000"
    assert settings.data_root == Path("data")
    assert settings.environment == "development"


def test_settings_accept_scopegraph_prefix(monkeypatch: object) -> None:
    monkeypatch.setenv("SCOPEGRAPH_ENVIRONMENT", "test")  # type: ignore[attr-defined]
    settings = Settings(_env_file=None)

    assert settings.environment == "test"
