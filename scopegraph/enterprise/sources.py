import asyncio
import json
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Literal, cast
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlsplit

import httpx

from scopegraph.enterprise.names import CompanyProfile
from scopegraph.normalizers import NormalizationError, registrable_root_domain

_MAX_SEARCH_REDIRECTS = 3
_MAX_PUBLIC_SOURCE_QUERIES = 2
_MAX_CERTIFICATE_RECORDS = 500
_MAX_ENRICHMENT_DOMAINS = 8


def _is_trusted_host(host: str | None, trusted_suffixes: tuple[str, ...]) -> bool:
    normalized = (host or "").casefold().rstrip(".")
    return any(
        normalized == suffix or normalized.endswith(f".{suffix}")
        for suffix in trusted_suffixes
    )


class _ResultLinkParser(HTMLParser):
    """Extract only result links, never navigation/chrome links from a search page."""

    def __init__(self, *, result_anchor_class: str | None = None) -> None:
        super().__init__(convert_charrefs=True)
        self.result_anchor_class = result_anchor_class
        self.links: list[str] = []
        self._bing_result_stack: list[bool] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.casefold(): value or "" for key, value in attrs}
        classes = set(values.get("class", "").casefold().split())
        if tag == "li":
            self._bing_result_stack.append("b_algo" in classes)
            return
        if tag != "a":
            return
        href = values.get("href")
        if not href:
            return
        if self.result_anchor_class is not None:
            if self.result_anchor_class in classes:
                self.links.append(href)
            return
        if any(self._bing_result_stack):
            self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag == "li" and self._bing_result_stack:
            self._bing_result_stack.pop()


def _extract_duckduckgo_links(markup: str) -> tuple[str, ...]:
    parser = _ResultLinkParser(result_anchor_class="result__a")
    parser.feed(markup)
    parser.close()
    return tuple(dict.fromkeys(parser.links))


def _extract_bing_links(markup: str) -> tuple[str, ...]:
    parser = _ResultLinkParser()
    parser.feed(markup)
    parser.close()
    return tuple(dict.fromkeys(parser.links))


def _duckduckgo_destination(value: str) -> str:
    absolute = urljoin("https://duckduckgo.com/", value)
    parsed = urlsplit(absolute)
    if _is_trusted_host(parsed.hostname, ("duckduckgo.com",)) and parsed.path.startswith("/l/"):
        target = parse_qs(parsed.query).get("uddg", [""])[0]
        if target:
            return unquote(target)
    return absolute


def _identity_destination(value: str) -> str:
    return value


def _candidate_signals_from_links(
    links: tuple[str, ...],
    *,
    source: str,
    provider_suffixes: tuple[str, ...],
    destination: Callable[[str], str],
) -> tuple["CandidateSignal", ...]:
    candidates: dict[str, CandidateSignal] = {}
    for link in links:
        target = destination(link)
        host = urlsplit(target).hostname
        if not host or _is_trusted_host(host, provider_suffixes):
            continue
        try:
            root = registrable_root_domain(host)
        except NormalizationError:
            continue
        candidates[root] = CandidateSignal(
            root,
            source,
            target[:4096],
            ("SEARCH_KEYWORD_ONLY",),
        )
    return tuple(candidates.values())


async def _fetch_trusted_search_page(
    client: httpx.AsyncClient,
    *,
    endpoint: str,
    query: str,
    trusted_suffixes: tuple[str, ...],
    max_bytes: int,
) -> tuple[str | None, str | None]:
    """Fetch a search page while following only redirects within the provider."""

    target = endpoint
    params: dict[str, str] | None = {"q": query}
    try:
        for _ in range(_MAX_SEARCH_REDIRECTS + 1):
            response = await client.get(target, params=params)
            params = None
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    return None, "REDIRECT_WITHOUT_LOCATION"
                next_target = urljoin(str(response.url), location)
                if not _is_trusted_host(urlsplit(next_target).hostname, trusted_suffixes):
                    return None, "UNTRUSTED_REDIRECT"
                target = next_target
                continue
            if not _is_trusted_host(response.url.host, trusted_suffixes):
                return None, "UNTRUSTED_RESPONSE_HOST"
            # 202 is commonly a bot/challenge shell from a search provider.
            # It is not a result page.
            if response.status_code != 200:
                return None, f"HTTP_STATUS_{response.status_code}"
            if not response.content:
                return None, "EMPTY_RESPONSE"
            return response.content[:max_bytes].decode("utf-8", errors="replace"), None
    except (httpx.HTTPError, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    return None, "REDIRECT_LIMIT"


@dataclass(frozen=True, slots=True)
class CandidateSignal:
    domain: str
    source: str
    source_url: str
    signals: tuple[str, ...]
    # A provider may expose several stages.  Count these as one independent
    # source when deciding whether a candidate is corroborated.
    source_family: str | None = None


@dataclass(frozen=True, slots=True)
class SourceResult:
    source: str
    candidates: tuple[CandidateSignal, ...]
    error: str | None = None
    category: str = "passive"
    attempted_count: int = 1
    completed_count: int = 1
    skipped_reason: str | None = None

    @property
    def status(self) -> Literal["COMPLETED", "PARTIAL", "UNAVAILABLE", "SKIPPED"]:
        if self.skipped_reason is not None:
            return "SKIPPED"
        if self.error is None:
            return "COMPLETED"
        if self.completed_count > 0:
            return "PARTIAL"
        return "UNAVAILABLE"


class EnterpriseSource(ABC):
    name: str

    @abstractmethod
    async def discover(self, profile: CompanyProfile) -> SourceResult:
        raise NotImplementedError


class RecordedSource(EnterpriseSource):
    name = "recorded-public-search"

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or Path("configs/enterprise_sources/fixture.json")

    async def discover(self, profile: CompanyProfile) -> SourceResult:
        payload = cast(dict[str, Any], json.loads(self.path.read_text(encoding="utf-8")))
        rows: list[dict[str, Any]] = []
        for alias in profile.aliases:
            rows.extend(payload.get("companies", {}).get(alias, []))
        candidates = tuple(
            CandidateSignal(
                domain=str(row["domain"]),
                source=str(row["source"]),
                source_url=str(row["source_url"]),
                signals=tuple(str(item) for item in row["signals"]),
            )
            for row in rows
        )
        return SourceResult(self.name, candidates, category="fixture")


class _BoundedSearchSource(EnterpriseSource):
    """Shared bounded search flow with provider-specific result parsing."""

    endpoint: str
    trusted_suffixes: tuple[str, ...]
    user_agent: str
    extract_links: Callable[[str], tuple[str, ...]]
    destination: Callable[[str], str]
    category = "public-search"

    def __init__(self, *, timeout_seconds: float = 8, max_bytes: int = 1_000_000) -> None:
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes

    async def discover(self, profile: CompanyProfile) -> SourceResult:
        queries = [
            f'"{keyword}" 官网' for keyword in profile.search_keywords[:_MAX_PUBLIC_SOURCE_QUERIES]
        ]
        if not queries:
            return SourceResult(
                self.name,
                (),
                category=self.category,
                attempted_count=0,
                completed_count=0,
                skipped_reason="NO_SEARCH_KEYWORDS",
            )
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": self.user_agent},
        ) as client:
            pages = await asyncio.gather(
                *(
                    _fetch_trusted_search_page(
                        client,
                        endpoint=self.endpoint,
                        query=query,
                        trusted_suffixes=self.trusted_suffixes,
                        max_bytes=self.max_bytes,
                    )
                    for query in queries
                )
            )

        links: list[str] = []
        errors: list[str] = []
        completed_count = 0
        for page, error in pages:
            if error:
                errors.append(error)
            elif page:
                completed_count += 1
                links.extend(self.extract_links(page))
        candidates = _candidate_signals_from_links(
            tuple(dict.fromkeys(links)),
            source=self.name,
            provider_suffixes=self.trusted_suffixes,
            destination=self.destination,
        )
        error = _batch_error(errors, attempted_count=len(queries), completed_count=completed_count)
        return SourceResult(
            self.name,
            candidates,
            error,
            category=self.category,
            attempted_count=len(queries),
            completed_count=completed_count,
        )


class PublicSearchSource(_BoundedSearchSource):
    """Bounded passive discovery against DuckDuckGo's HTML endpoint."""

    name = "duckduckgo-html"
    endpoint = "https://html.duckduckgo.com/html/"
    trusted_suffixes = ("duckduckgo.com",)
    user_agent = "ScopeGraph/1.0 passive-enterprise-discovery"
    extract_links = staticmethod(_extract_duckduckgo_links)
    destination = staticmethod(_duckduckgo_destination)


class BingSearchSource(_BoundedSearchSource):
    """Second bounded passive source used when the primary HTML endpoint is incomplete."""

    name = "bing-html"
    endpoint = "https://www.bing.com/search"
    trusted_suffixes = ("bing.com",)
    user_agent = "Mozilla/5.0 ScopeGraph/1.0 passive-discovery"
    extract_links = staticmethod(_extract_bing_links)
    destination = staticmethod(_identity_destination)


def _batch_error(errors: list[str], *, attempted_count: int, completed_count: int) -> str | None:
    if not errors:
        return None
    unique = list(dict.fromkeys(errors))
    detail = " | ".join(unique[:3])
    unavailable_count = max(0, attempted_count - completed_count)
    if unavailable_count:
        return f"{unavailable_count}/{attempted_count} requests unavailable: {detail}"
    return f"coverage gap: {detail}"


async def _fetch_trusted_json(
    client: httpx.AsyncClient,
    *,
    endpoint: str,
    params: dict[str, str] | None,
    trusted_suffixes: tuple[str, ...],
    max_bytes: int,
) -> tuple[object | None, str | None]:
    """Fetch bounded JSON without following a provider to an unrelated host."""

    target = endpoint
    target_params = params
    try:
        for _ in range(_MAX_SEARCH_REDIRECTS + 1):
            response = await client.get(target, params=target_params)
            target_params = None
            if response.is_redirect:
                location = response.headers.get("location")
                if not location:
                    return None, "REDIRECT_WITHOUT_LOCATION"
                next_target = urljoin(str(response.url), location)
                if not _is_trusted_host(urlsplit(next_target).hostname, trusted_suffixes):
                    return None, "UNTRUSTED_REDIRECT"
                target = next_target
                continue
            if not _is_trusted_host(response.url.host, trusted_suffixes):
                return None, "UNTRUSTED_RESPONSE_HOST"
            if response.status_code != 200:
                return None, f"HTTP_STATUS_{response.status_code}"
            content = response.content[:max_bytes]
            if not content:
                return None, "EMPTY_RESPONSE"
            try:
                return json.loads(content), None
            except json.JSONDecodeError:
                return None, "INVALID_JSON"
    except (httpx.HTTPError, OSError) as exc:
        return None, f"{type(exc).__name__}: {exc}"
    return None, "REDIRECT_LIMIT"


def _certificate_roots(payload: object) -> tuple[str, ...]:
    """Return bounded registrable roots from a crt.sh-style JSON payload."""

    if not isinstance(payload, list):
        return ()
    roots: dict[str, None] = {}
    for row in payload[:_MAX_CERTIFICATE_RECORDS]:
        if not isinstance(row, dict):
            continue
        for field in ("name_value", "common_name"):
            value = row.get(field)
            if not isinstance(value, str):
                continue
            for raw_name in value.splitlines():
                candidate = raw_name.strip().casefold().lstrip("*.").rstrip(".")
                if not candidate:
                    continue
                try:
                    roots[registrable_root_domain(candidate)] = None
                except NormalizationError:
                    continue
    return tuple(roots)


class CertificateTransparencyDomainSource(EnterpriseSource):
    """Corroborate already-discovered roots with certificate SAN evidence."""

    name = "crtsh-domain-verify"
    category = "certificate-transparency"
    source_family = "certificate-transparency"
    endpoint = "https://crt.sh/"
    trusted_suffixes = ("crt.sh",)
    user_agent = "ScopeGraph/1.1 passive-enterprise-discovery"

    def __init__(
        self,
        root_domains: Iterable[str],
        *,
        timeout_seconds: float = 8,
        max_bytes: int = 1_000_000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.root_domains = tuple(dict.fromkeys(root_domains))[:_MAX_ENRICHMENT_DOMAINS]
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.transport = transport

    async def discover(self, profile: CompanyProfile) -> SourceResult:
        del profile
        if not self.root_domains:
            return SourceResult(
                self.name,
                (),
                category=self.category,
                attempted_count=0,
                completed_count=0,
                skipped_reason="NO_SEED_ROOTS",
            )
        queries = tuple(f"%.{domain}" for domain in self.root_domains)
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            headers={"User-Agent": self.user_agent, "Accept": "application/json"},
            transport=self.transport,
        ) as client:
            responses = await asyncio.gather(
                *(
                    _fetch_trusted_json(
                        client,
                        endpoint=self.endpoint,
                        params={"q": query, "output": "json"},
                        trusted_suffixes=self.trusted_suffixes,
                        max_bytes=self.max_bytes,
                    )
                    for query in queries
                )
            )

        candidates: dict[str, CandidateSignal] = {}
        errors: list[str] = []
        completed_count = 0
        for domain, query, (payload, error) in zip(
            self.root_domains, queries, responses, strict=True
        ):
            if error is not None:
                errors.append(error)
                continue
            if not isinstance(payload, list):
                errors.append("INVALID_JSON_SHAPE")
                continue
            completed_count += 1
            if domain not in _certificate_roots(payload):
                continue
            source_url = f"{self.endpoint}?{urlencode({'q': query, 'output': 'json'})}"
            candidates[domain] = CandidateSignal(
                domain,
                self.name,
                source_url,
                ("TLS_SAN_RELATED",),
                self.source_family,
            )
        return SourceResult(
            self.name,
            tuple(candidates.values()),
            _batch_error(
                errors,
                attempted_count=len(self.root_domains),
                completed_count=completed_count,
            ),
            category=self.category,
            attempted_count=len(self.root_domains),
            completed_count=completed_count,
        )


def _identity_key(value: str) -> str:
    return "".join(
        character
        for character in value.casefold()
        if character.isalnum() or "\u3400" <= character <= "\u9fff"
    )


def _rdap_registrant_values(payload: object, *, depth: int = 0) -> tuple[str, ...]:
    if depth > 3 or not isinstance(payload, dict):
        return ()
    entities = payload.get("entities")
    if not isinstance(entities, list):
        return ()
    values: dict[str, None] = {}
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        roles = entity.get("roles")
        is_registrant = isinstance(roles, list) and any(
            isinstance(role, str) and role.casefold() == "registrant" for role in roles
        )
        if is_registrant:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                for field in vcard[1]:
                    if not isinstance(field, list) or len(field) < 4:
                        continue
                    key = field[0]
                    value = field[3]
                    if not isinstance(key, str) or key.casefold() not in {"fn", "org"}:
                        continue
                    if isinstance(value, str):
                        values[value] = None
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, str):
                                values[item] = None
        values.update(
            dict.fromkeys(_rdap_registrant_values(entity, depth=depth + 1))
        )
    return tuple(values)


def _rdap_matches_company(payload: object, profile: CompanyProfile) -> bool:
    expected = {_identity_key(profile.normalized_name)}
    expected.update(_identity_key(alias) for alias in profile.aliases)
    expected.discard("")
    registrants = {_identity_key(value) for value in _rdap_registrant_values(payload)}
    return bool(expected & registrants)


def _rdap_bootstrap_endpoints(payload: object, root_domains: Iterable[str]) -> dict[str, str]:
    """Resolve TLD-specific authoritative RDAP endpoints from IANA bootstrap data."""

    if not isinstance(payload, dict):
        return {}
    services = payload.get("services")
    if not isinstance(services, list):
        return {}
    endpoint_by_tld: dict[str, str] = {}
    for service in services:
        if not isinstance(service, list) or len(service) < 2:
            continue
        tlds, endpoints = service[0], service[1]
        if not isinstance(tlds, list) or not isinstance(endpoints, list):
            continue
        endpoint = next(
            (
                value
                for value in endpoints
                if isinstance(value, str)
                and urlsplit(value).scheme == "https"
                and urlsplit(value).hostname is not None
                and urlsplit(value).username is None
                and urlsplit(value).password is None
            ),
            None,
        )
        if endpoint is None:
            continue
        for tld in tlds:
            if isinstance(tld, str):
                endpoint_by_tld[tld.casefold().rstrip(".")] = endpoint
    resolved: dict[str, str] = {}
    for domain in root_domains:
        tld = domain.rsplit(".", maxsplit=1)[-1].casefold()
        endpoint = endpoint_by_tld.get(tld)
        if endpoint is not None:
            resolved[domain] = urljoin(endpoint.rstrip("/") + "/", f"domain/{domain}")
    return resolved


class RdapRegistrantSource(EnterpriseSource):
    """Use public RDAP registrant data only to corroborate existing candidates."""

    name = "rdap-registrant"
    category = "registration"
    source_family = "rdap"
    bootstrap_endpoint = "https://data.iana.org/rdap/dns.json"
    bootstrap_suffixes = ("iana.org",)
    user_agent = "ScopeGraph/1.1 passive-enterprise-discovery"

    def __init__(
        self,
        root_domains: Iterable[str],
        *,
        timeout_seconds: float = 8,
        max_bytes: int = 512_000,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.root_domains = tuple(dict.fromkeys(root_domains))[:_MAX_ENRICHMENT_DOMAINS]
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max_bytes
        self.transport = transport

    async def discover(self, profile: CompanyProfile) -> SourceResult:
        if not self.root_domains:
            return SourceResult(
                self.name,
                (),
                category=self.category,
                attempted_count=0,
                completed_count=0,
                skipped_reason="NO_SEED_ROOTS",
            )
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            headers={
                "User-Agent": self.user_agent,
                "Accept": "application/rdap+json, application/json",
            },
            transport=self.transport,
        ) as client:
            bootstrap, bootstrap_error = await _fetch_trusted_json(
                client,
                endpoint=self.bootstrap_endpoint,
                params=None,
                trusted_suffixes=self.bootstrap_suffixes,
                max_bytes=self.max_bytes,
            )
            if bootstrap_error is not None:
                return SourceResult(
                    self.name,
                    (),
                    f"BOOTSTRAP_{bootstrap_error}",
                    category=self.category,
                    attempted_count=1,
                    completed_count=0,
                )
            endpoints = _rdap_bootstrap_endpoints(bootstrap, self.root_domains)
            lookups = list(endpoints.items())
            responses = await asyncio.gather(
                *(
                    _fetch_trusted_json(
                        client,
                        endpoint=endpoint,
                        params=None,
                        trusted_suffixes=(urlsplit(endpoint).hostname or "",),
                        max_bytes=self.max_bytes,
                    )
                    for _, endpoint in lookups
                )
            )

        candidates: dict[str, CandidateSignal] = {}
        errors = [
            "NO_BOOTSTRAP_ENDPOINT_FOR_TLD"
            for domain in self.root_domains
            if domain not in endpoints
        ]
        completed_count = 1
        for (domain, endpoint), (payload, error) in zip(lookups, responses, strict=True):
            if error is not None:
                errors.append(error)
                continue
            if not isinstance(payload, dict):
                errors.append("INVALID_JSON_SHAPE")
                continue
            completed_count += 1
            if not _rdap_matches_company(payload, profile):
                continue
            candidates[domain] = CandidateSignal(
                domain,
                self.name,
                endpoint,
                ("RDAP_REGISTRANT_MATCH",),
                self.source_family,
            )
        return SourceResult(
            self.name,
            tuple(candidates.values()),
            _batch_error(
                errors,
                attempted_count=1 + len(lookups),
                completed_count=completed_count,
            ),
            category=self.category,
            attempted_count=1 + len(lookups),
            completed_count=completed_count,
        )


def denied_source_domains(path: Path | None = None) -> set[str]:
    config_path = path or Path("configs/enterprise_sources/deny_domains.json")
    payload = json.loads(config_path.read_text(encoding="utf-8"))
    return {registrable_root_domain(str(value)) for value in payload["domains"]}
