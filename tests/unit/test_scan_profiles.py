import pytest
from pydantic import ValidationError

from scopegraph.domain.enums import ScanProfile
from scopegraph.scanning.profiles import load_profile


def test_versioned_profiles_are_valid_and_increasingly_broad() -> None:
    quick = load_profile(ScanProfile.QUICK)
    standard = load_profile(ScanProfile.STANDARD)
    deep = load_profile(ScanProfile.DEEP)

    assert quick.port_scan_enabled
    assert quick.nuclei_allowed and quick.nuclei_strategy == "automatic"
    assert set((80, 443, 8080, 8443)).issubset(quick.ports)
    assert standard.port_scan_enabled
    assert standard.nuclei_strategy == deep.nuclei_strategy == "automatic"
    assert deep.dns_wordlist_limit > standard.dns_wordlist_limit > quick.dns_wordlist_limit
    assert deep.variant_limit > standard.variant_limit
    assert not quick.crawler_enabled
    assert standard.crawler_enabled and deep.crawler_depth > standard.crawler_depth


def test_custom_profile_rejects_unknown_and_unsafe_values() -> None:
    with pytest.raises(ValidationError):
        load_profile(ScanProfile.CUSTOM, {"shell_command": "naabu --evil"})
    with pytest.raises(ValidationError):
        load_profile(ScanProfile.CUSTOM, {"ports": [0, 443]})
    with pytest.raises(ValueError, match="required"):
        load_profile(ScanProfile.CUSTOM)
    with pytest.raises(ValueError, match="only valid"):
        load_profile(ScanProfile.QUICK, {"ports": [443]})
