import ipaddress
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import idna
import tldextract

from scopegraph.domain.enums import AssetType, ScopeRuleType

_extractor = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
_company_brackets = re.compile(r"[（(][^）)]*[）)]")
_whitespace = re.compile(r"\s+")


class NormalizationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class NormalizedAsset:
    asset_type: AssetType
    normalized_value: str
    display_value: str

    @property
    def normalized_key(self) -> str:
        return f"{self.asset_type.value}:{self.normalized_value}"


def normalize_company_name(value: str) -> str:
    cleaned = _company_brackets.sub(" ", value.strip())
    cleaned = _whitespace.sub(" ", cleaned).strip().casefold()
    if not cleaned:
        raise NormalizationError("Company name cannot be empty")
    if len(cleaned) > 300:
        raise NormalizationError("Company name exceeds 300 characters")
    return cleaned


def normalize_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").casefold()
    if not candidate:
        raise NormalizationError("Domain cannot be empty")
    if "://" in candidate or "/" in candidate or "@" in candidate:
        raise NormalizationError("Domain must not contain a scheme, path, or user information")
    if candidate.startswith("*."):
        raise NormalizationError("Wildcard domains are represented by ROOT_DOMAIN scope rules")
    try:
        ascii_domain = idna.encode(candidate, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise NormalizationError("Domain is not valid IDNA") from exc
    if len(ascii_domain) > 253:
        raise NormalizationError("Domain exceeds 253 characters")
    labels = ascii_domain.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        raise NormalizationError("Domain must be a valid fully qualified public name")
    if any(label.startswith("-") or label.endswith("-") for label in labels):
        raise NormalizationError("Domain labels cannot start or end with a hyphen")
    return ascii_domain


def registrable_root_domain(value: str) -> str:
    domain = normalize_domain(value)
    extracted = _extractor(domain)
    root = extracted.top_domain_under_public_suffix
    if not root or not extracted.suffix:
        raise NormalizationError("Domain has no recognized public suffix")
    return root


def normalize_ip(value: str) -> str:
    try:
        return ipaddress.ip_address(value.strip()).compressed
    except ValueError as exc:
        raise NormalizationError("IP address is invalid") from exc


def normalize_cidr(value: str) -> str:
    try:
        return ipaddress.ip_network(value.strip(), strict=False).compressed
    except ValueError as exc:
        raise NormalizationError("CIDR is invalid") from exc


def _normalize_url_host(hostname: str) -> tuple[str, bool]:
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.compressed, ip.version == 6
    except ValueError:
        return normalize_domain(hostname), False


def _normalize_path(path: str) -> str:
    decoded = unquote(path or "/")
    trailing_slash = decoded.endswith("/")
    normalized = posixpath.normpath(decoded)
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"
    if trailing_slash and normalized != "/":
        normalized = f"{normalized}/"
    return quote(normalized, safe="/:@-._~!$&'()*+,;=")


def normalize_url(value: str) -> str:
    candidate = value.strip()
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise NormalizationError("URL contains an invalid port or host") from exc
    scheme = parsed.scheme.casefold()
    if scheme not in {"http", "https"}:
        raise NormalizationError("Only HTTP and HTTPS URLs are supported")
    if not parsed.hostname:
        raise NormalizationError("URL host is required")
    if parsed.username is not None or parsed.password is not None:
        raise NormalizationError("URL user information is not allowed")
    host, is_ipv6 = _normalize_url_host(parsed.hostname)
    if is_ipv6:
        host = f"[{host}]"
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    netloc = host if port is None or default_port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, _normalize_path(parsed.path), parsed.query, ""))


def normalize_scope_value(rule_type: ScopeRuleType, value: str) -> str:
    normalizers = {
        ScopeRuleType.DOMAIN: normalize_domain,
        ScopeRuleType.ROOT_DOMAIN: registrable_root_domain,
        ScopeRuleType.IP: normalize_ip,
        ScopeRuleType.CIDR: normalize_cidr,
        ScopeRuleType.URL: normalize_url,
    }
    return normalizers[rule_type](value)


def normalize_asset(asset_type: AssetType | str, value: str) -> NormalizedAsset:
    try:
        kind = asset_type if isinstance(asset_type, AssetType) else AssetType(asset_type.casefold())
    except ValueError as exc:
        raise NormalizationError(f"Unsupported asset type: {asset_type}") from exc
    display = value.strip()
    if not display:
        raise NormalizationError("Asset value cannot be empty")
    if len(display) > 4096:
        raise NormalizationError("Asset value is too long")
    if kind is AssetType.DOMAIN:
        normalized = normalize_domain(display)
    elif kind is AssetType.IP:
        normalized = normalize_ip(display)
    elif kind is AssetType.CIDR:
        normalized = normalize_cidr(display)
    elif kind is AssetType.URL:
        normalized = normalize_url(display)
    elif kind is AssetType.COMPANY:
        normalized = normalize_company_name(display)
    else:
        normalized = _whitespace.sub(" ", display).strip().casefold()
    return NormalizedAsset(kind, normalized, display)
