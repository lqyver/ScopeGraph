import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit
from uuid import UUID

from scopegraph.application.errors import ScopeGraphError
from scopegraph.domain.enums import AssetType, ScopeAction, ScopeRuleType, ScopeStatus
from scopegraph.normalizers.assets import normalize_asset, normalize_scope_value


@dataclass(frozen=True, slots=True)
class ScopeRuleValue:
    rule_type: ScopeRuleType
    value: str
    action: ScopeAction
    rule_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class ScopeDecision:
    status: ScopeStatus
    normalized_value: str
    reason: str
    matched_rule_id: UUID | None = None

    @property
    def active_allowed(self) -> bool:
        return self.status is ScopeStatus.IN_SCOPE


def _target_host(asset_type: AssetType, normalized_value: str) -> str | None:
    if asset_type is AssetType.DOMAIN:
        return normalized_value
    if asset_type is AssetType.URL:
        return urlsplit(normalized_value).hostname
    return None


def _matches(rule: ScopeRuleValue, asset_type: AssetType, normalized_value: str) -> bool:
    rule_value = normalize_scope_value(rule.rule_type, rule.value)
    host = _target_host(asset_type, normalized_value)
    if rule.rule_type is ScopeRuleType.URL:
        return asset_type is AssetType.URL and normalized_value == rule_value
    if rule.rule_type is ScopeRuleType.DOMAIN:
        return host == rule_value
    if rule.rule_type is ScopeRuleType.ROOT_DOMAIN:
        return host is not None and (host == rule_value or host.endswith(f".{rule_value}"))
    if rule.rule_type is ScopeRuleType.IP:
        return asset_type is AssetType.IP and normalized_value == rule_value
    if rule.rule_type is ScopeRuleType.CIDR and asset_type is AssetType.IP:
        return ipaddress.ip_address(normalized_value) in ipaddress.ip_network(rule_value)
    return False


def evaluate_scope(
    asset_type: AssetType | str,
    value: str,
    rules: list[ScopeRuleValue],
) -> ScopeDecision:
    normalized = normalize_asset(asset_type, value)
    ordered = sorted(rules, key=lambda item: item.action is ScopeAction.INCLUDE)
    for rule in ordered:
        if _matches(rule, normalized.asset_type, normalized.normalized_value):
            if rule.action is ScopeAction.EXCLUDE:
                return ScopeDecision(
                    ScopeStatus.EXCLUDED,
                    normalized.normalized_value,
                    "Matched an explicit exclusion rule",
                    rule.rule_id,
                )
            return ScopeDecision(
                ScopeStatus.IN_SCOPE,
                normalized.normalized_value,
                "Matched an explicit include rule",
                rule.rule_id,
            )
    return ScopeDecision(
        ScopeStatus.OUT_OF_SCOPE,
        normalized.normalized_value,
        "No explicit include rule matched",
    )


def require_active_scope(decision: ScopeDecision) -> None:
    if not decision.active_allowed:
        raise ScopeGraphError(
            "SCOPE_VIOLATION",
            "Target is outside authorized scope",
            status_code=403,
            details={
                "scope_status": decision.status.value,
                "normalized_value": decision.normalized_value,
                "reason": decision.reason,
            },
        )
