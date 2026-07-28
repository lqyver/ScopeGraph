from scopegraph.domain.enums import IPClassification, ScanProfile, ScopeStatus
from scopegraph.scanning.port_policy import classify_ip, decide_port_scan
from scopegraph.scanning.profiles import load_profile
from scopegraph.scanning.third_party import classify_cname, load_cname_rules


def test_ip_classification_is_conservative() -> None:
    assert classify_ip("127.0.0.1") is IPClassification.PRIVATE_RESERVED
    assert classify_ip("192.0.2.1") is IPClassification.PRIVATE_RESERVED
    assert classify_ip("8.8.8.8", cname="edge.cloudflare.net") is IPClassification.CDN_WAF


def test_versioned_cname_rules_distinguish_cdn_and_saas() -> None:
    rules = load_cname_rules()
    assert rules.version == 1
    cdn = classify_cname("d111111abcdef8.cloudfront.net", rules)
    saas = classify_cname("customer.github.io", rules)
    assert cdn is not None and cdn.category == "CDN"
    assert saas is not None and saas.category == "SAAS"
    assert classify_cname("owned.example.com", rules) is None
    assert classify_ip("8.8.8.8") is IPClassification.UNKNOWN
    assert (
        classify_ip("8.8.8.8", explicit_classification=IPClassification.OWNED)
        is IPClassification.OWNED
    )


def test_cdn_out_of_scope_and_disabled_scans_are_denied() -> None:
    profile = load_profile(ScanProfile.STANDARD)
    common = {
        "profile": profile,
        "port_scan_enabled": True,
        "full_port_scan": False,
        "full_port_confirmation": False,
    }
    assert not decide_port_scan(
        classification=IPClassification.CDN_WAF,
        scope_status=ScopeStatus.IN_SCOPE,
        **common,
    ).allowed
    assert not decide_port_scan(
        classification=IPClassification.OWNED,
        scope_status=ScopeStatus.OUT_OF_SCOPE,
        **common,
    ).allowed
    assert not decide_port_scan(
        classification=IPClassification.OWNED,
        scope_status=ScopeStatus.IN_SCOPE,
        **(common | {"port_scan_enabled": False}),
    ).allowed


def test_unknown_ip_is_restricted_to_web_ports() -> None:
    decision = decide_port_scan(
        classification=IPClassification.UNKNOWN,
        scope_status=ScopeStatus.IN_SCOPE,
        profile=load_profile(ScanProfile.STANDARD),
        port_scan_enabled=True,
        full_port_scan=False,
        full_port_confirmation=False,
    )
    assert decision.allowed
    assert decision.effective_ports == (80, 443, 8080, 8443)


def test_full_port_requires_owned_scope_and_second_confirmation() -> None:
    profile = load_profile(ScanProfile.DEEP)
    base = {
        "scope_status": ScopeStatus.IN_SCOPE,
        "profile": profile,
        "port_scan_enabled": True,
        "full_port_scan": True,
    }
    assert not decide_port_scan(
        classification=IPClassification.OWNED,
        full_port_confirmation=False,
        **base,
    ).allowed
    assert not decide_port_scan(
        classification=IPClassification.CLOUD_SERVER,
        full_port_confirmation=True,
        **base,
    ).allowed
    allowed = decide_port_scan(
        classification=IPClassification.OWNED,
        full_port_confirmation=True,
        **base,
    )
    assert allowed.allowed and allowed.full_port_scan
    assert len(allowed.effective_ports) == 65_535
