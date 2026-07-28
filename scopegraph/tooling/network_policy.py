import ipaddress
from collections.abc import Iterable

DIRECT_DOH_RESOLVERS = (
    "doh:https://1.1.1.1/dns-query",
    "doh:https://9.9.9.9/dns-query",
)
ENVIRONMENT_MAPPING_NETWORKS = (ipaddress.ip_network("198.18.0.0/15"),)


def direct_resolver_argument() -> str:
    """Return the fixed resolver set used to bypass system Fake-IP DNS."""

    return ",".join(DIRECT_DOH_RESOLVERS)


def is_environment_mapping_ip(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return any(address in network for network in ENVIRONMENT_MAPPING_NETWORKS)


def split_reported_ips(values: Iterable[object]) -> tuple[list[str], list[str]]:
    """Separate usable addresses from transparent-proxy mapping addresses."""

    usable: list[str] = []
    mapped: list[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        try:
            normalized = str(ipaddress.ip_address(value.strip()))
        except ValueError:
            continue
        destination = mapped if is_environment_mapping_ip(normalized) else usable
        if normalized not in destination:
            destination.append(normalized)
    return usable, mapped
