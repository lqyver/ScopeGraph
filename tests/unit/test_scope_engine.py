import pytest

from scopegraph.application.errors import ScopeGraphError
from scopegraph.domain.enums import AssetType, ScopeAction, ScopeRuleType, ScopeStatus
from scopegraph.scope_engine import ScopeRuleValue, evaluate_scope, require_active_scope


def test_root_domain_includes_subdomains() -> None:
    decision = evaluate_scope(
        AssetType.DOMAIN,
        "api.example.com",
        [ScopeRuleValue(ScopeRuleType.ROOT_DOMAIN, "example.com", ScopeAction.INCLUDE)],
    )

    assert decision.status is ScopeStatus.IN_SCOPE
    assert decision.active_allowed is True


def test_explicit_exclusion_wins_over_root_include_regardless_of_order() -> None:
    rules = [
        ScopeRuleValue(ScopeRuleType.ROOT_DOMAIN, "example.com", ScopeAction.INCLUDE),
        ScopeRuleValue(ScopeRuleType.DOMAIN, "payment.example.com", ScopeAction.EXCLUDE),
    ]

    decision = evaluate_scope(AssetType.DOMAIN, "payment.example.com", rules)

    assert decision.status is ScopeStatus.EXCLUDED
    assert decision.active_allowed is False


def test_root_domain_rule_applies_to_web_urls() -> None:
    decision = evaluate_scope(
        AssetType.URL,
        "https://portal.example.com/login",
        [ScopeRuleValue(ScopeRuleType.ROOT_DOMAIN, "example.com", ScopeAction.INCLUDE)],
    )

    assert decision.status is ScopeStatus.IN_SCOPE


def test_cidr_scope_matches_ip_and_unknown_defaults_to_out_of_scope() -> None:
    rules = [ScopeRuleValue(ScopeRuleType.CIDR, "192.0.2.0/24", ScopeAction.INCLUDE)]

    assert evaluate_scope(AssetType.IP, "192.0.2.20", rules).status is ScopeStatus.IN_SCOPE
    assert evaluate_scope(AssetType.IP, "198.51.100.2", rules).status is ScopeStatus.OUT_OF_SCOPE


def test_active_task_guard_rejects_non_scope_target() -> None:
    decision = evaluate_scope(AssetType.DOMAIN, "third-party.example.net", [])

    with pytest.raises(ScopeGraphError) as raised:
        require_active_scope(decision)

    assert raised.value.code == "SCOPE_VIOLATION"
    assert raised.value.status_code == 403
