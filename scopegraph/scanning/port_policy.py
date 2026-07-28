import ipaddress
from dataclasses import dataclass

from scopegraph.domain.enums import IPClassification, ScopeStatus
from scopegraph.scanning.profiles import SAFE_WEB_PORTS, ScanProfileConfig
from scopegraph.scanning.third_party import classify_cname


@dataclass(frozen=True, slots=True)
class PortScanDecision:
    allowed: bool
    effective_ports: tuple[int, ...]
    reason: str
    full_port_scan: bool = False


def classify_ip(
    value: str,
    *,
    cname: str | None = None,
    explicit_classification: IPClassification | None = None,
) -> IPClassification:
    """Use conservative local signals; DNS resolution alone never proves ownership."""

    address = ipaddress.ip_address(value)
    if not address.is_global:
        return IPClassification.PRIVATE_RESERVED
    cname_classification = classify_cname(cname) if cname else None
    if cname_classification and cname_classification.category == "CDN":
        return IPClassification.CDN_WAF
    if explicit_classification is not None:
        return explicit_classification
    return IPClassification.UNKNOWN


def decide_port_scan(
    *,
    classification: IPClassification,
    scope_status: ScopeStatus,
    profile: ScanProfileConfig,
    port_scan_enabled: bool,
    full_port_scan: bool,
    full_port_confirmation: bool,
) -> PortScanDecision:
    if not port_scan_enabled or not profile.port_scan_enabled:
        return PortScanDecision(False, (), "Port scanning is disabled")
    if scope_status is not ScopeStatus.IN_SCOPE:
        return PortScanDecision(False, (), "IP is not explicitly in active Scope")
    if classification is IPClassification.PRIVATE_RESERVED:
        return PortScanDecision(False, (), "Private or reserved IP ranges are never scanned")
    if classification is IPClassification.CDN_WAF:
        return PortScanDecision(False, (), "CDN/WAF addresses are not port scanned")
    if full_port_scan:
        if classification is not IPClassification.OWNED:
            return PortScanDecision(False, (), "Full-port scanning requires an OWNED IP")
        if not full_port_confirmation:
            return PortScanDecision(False, (), "Full-port scanning requires second confirmation")
        return PortScanDecision(True, tuple(range(1, 65_536)), "Explicit full-port scan", True)
    if classification in {IPClassification.SHARED_HOSTING, IPClassification.UNKNOWN}:
        selected = tuple(port for port in profile.ports if port in SAFE_WEB_PORTS)
        if not selected:
            return PortScanDecision(
                False, (), "No approved web ports remain after policy filtering"
            )
        return PortScanDecision(True, selected, "Shared or unknown IP restricted to web ports")
    return PortScanDecision(True, profile.ports, "Profile-selected ports allowed")
