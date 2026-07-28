import pytest

from scopegraph.domain.enums import AssetType
from scopegraph.normalizers import (
    NormalizationError,
    normalize_asset,
    normalize_cidr,
    normalize_domain,
    normalize_ip,
    normalize_url,
    registrable_root_domain,
)


def test_domain_normalization_handles_case_dot_and_idna() -> None:
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain("例子.中国") == "xn--fsqu00a.xn--fiqs8s"


def test_domain_normalization_rejects_wildcards_and_paths() -> None:
    with pytest.raises(NormalizationError):
        normalize_domain("*.example.com")
    with pytest.raises(NormalizationError):
        normalize_domain("https://example.com")


def test_public_suffix_root_is_offline_and_deterministic() -> None:
    assert registrable_root_domain("api.eu.example.co.uk") == "example.co.uk"


def test_ip_and_cidr_are_canonical() -> None:
    assert normalize_ip("2001:0db8:0:0::1") == "2001:db8::1"
    assert normalize_cidr("192.0.2.17/24") == "192.0.2.0/24"


def test_url_removes_fragment_default_port_and_dot_segments() -> None:
    assert normalize_url("HTTPS://Example.COM:443/a/../b/#section") == "https://example.com/b/"


def test_url_rejects_user_information_and_non_http_schemes() -> None:
    with pytest.raises(NormalizationError):
        normalize_url("https://user:pass@example.com/")
    with pytest.raises(NormalizationError):
        normalize_url("file:///etc/passwd")


def test_asset_key_is_stable() -> None:
    asset = normalize_asset(AssetType.DOMAIN, "WWW.Example.com.")
    assert asset.normalized_key == "domain:www.example.com"
