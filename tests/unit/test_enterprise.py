import json
from pathlib import Path

import httpx
import pytest

from scopegraph.domain.enums import CandidateRootStatus, OwnershipStatus
from scopegraph.enterprise.names import build_company_profile
from scopegraph.enterprise.ownership import OwnershipRules, score_signals
from scopegraph.enterprise.sources import (
    CertificateTransparencyDomainSource,
    RdapRegistrantSource,
    RecordedSource,
    _candidate_signals_from_links,
    _duckduckgo_destination,
    _extract_bing_links,
    _extract_duckduckgo_links,
    _fetch_trusted_search_page,
)
from scopegraph.schemas.enterprise import EnterpriseDiscoveryRequest


def test_company_profile_extracts_aliases_and_suffix_free_keywords() -> None:
    profile = build_company_profile("示例科技股份有限公司（Example Tech, ET）")

    assert profile.normalized_name == "示例科技股份有限公司"
    assert "示例科技" in profile.aliases
    assert "example tech" in profile.aliases
    assert "et" in profile.aliases
    assert len(profile.search_keywords) == len(set(profile.search_keywords))


def test_ownership_score_preserves_raw_negative_and_explains_each_signal(tmp_path: Path) -> None:
    path = tmp_path / "rules.json"
    path.write_text(
        json.dumps(
            {
                "version": 9,
                "weights": {"GOOD": 20, "BAD": -50},
                "thresholds": {
                    "confirmed": 90,
                    "high_confidence": 70,
                    "pending_review": 40,
                    "weak_relation": 1,
                },
            }
        ),
        encoding="utf-8",
    )
    result = score_signals(["GOOD", "BAD", "GOOD", "UNKNOWN"], OwnershipRules.load(path))

    assert result.raw_score == -30
    assert result.score == 0
    assert result.status is CandidateRootStatus.THIRD_PARTY
    assert result.ownership_status is OwnershipStatus.THIRD_PARTY
    assert result.applied == (("GOOD", 20.0), ("BAD", -50.0))


def test_ownership_thresholds_match_product_rules() -> None:
    rules = OwnershipRules.load()
    suggested = score_signals(["CONFIRMED_ROOT", "ICP_SUBJECT_EXACT"], rules)
    pending = score_signals(["OFFICIAL_DIRECT_LINK", "BRAND_NAME_MATCH", "MULTI_SOURCE"], rules)

    assert suggested.raw_score == 90
    assert suggested.status is CandidateRootStatus.SUGGESTED_CONFIRM
    assert pending.raw_score == 35
    assert pending.status is CandidateRootStatus.PENDING_REVIEW
    assert pending.ownership_status is OwnershipStatus.WEAK_RELATION


def test_rdap_and_certificate_signals_need_manual_review() -> None:
    result = score_signals(
        ["RDAP_REGISTRANT_MATCH", "TLS_SAN_RELATED", "MULTI_SOURCE"],
        OwnershipRules.load(),
    )

    assert result.raw_score == 50
    assert result.status is CandidateRootStatus.PENDING_REVIEW
    assert result.ownership_status is OwnershipStatus.PENDING_REVIEW


def test_enterprise_request_keeps_inline_compatibility_and_allows_async_execution() -> None:
    assert EnterpriseDiscoveryRequest().async_execution is False
    assert EnterpriseDiscoveryRequest(async_execution=True).async_execution is True


@pytest.mark.asyncio
async def test_recorded_source_is_deterministic_and_company_scoped() -> None:
    source = RecordedSource()
    matched = await source.discover(build_company_profile("示例科技有限公司"))
    absent = await source.discover(build_company_profile("不存在的公司"))

    assert [item.domain for item in matched.candidates] == ["example.com"]
    assert absent.candidates == ()


def test_duckduckgo_result_parser_ignores_search_page_chrome() -> None:
    markup = """
    <a href="https://duckduckgo.com/">DuckDuckGo home</a>
    <a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fportal.example.com%2Fabout">
      Official site
    </a>
    """

    signals = _candidate_signals_from_links(
        _extract_duckduckgo_links(markup),
        source="duckduckgo-html",
        provider_suffixes=("duckduckgo.com",),
        destination=_duckduckgo_destination,
    )

    assert [(item.domain, item.source_url) for item in signals] == [
        ("example.com", "https://portal.example.com/about")
    ]


def test_bing_result_parser_only_uses_links_inside_result_rows() -> None:
    markup = """
    <a href="https://www.bing.com/">Bing home</a>
    <li class="b_algo" data-id="SERP.1"><h2><a href="https://portal.example.net/">Result</a></h2></li>
    """

    assert _extract_bing_links(markup) == ("https://portal.example.net/",)


@pytest.mark.asyncio
async def test_search_fetch_marks_202_challenge_page_as_unavailable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, request=request, content=b"<html>challenge</html>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        page, error = await _fetch_trusted_search_page(
            client,
            endpoint="https://html.duckduckgo.com/html/",
            query="example",
            trusted_suffixes=("duckduckgo.com",),
            max_bytes=1024,
        )

    assert page is None
    assert error == "HTTP_STATUS_202"


@pytest.mark.asyncio
async def test_search_fetch_follows_only_trusted_bing_redirects() -> None:
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        if request.url.host == "www.bing.com":
            return httpx.Response(
                302,
                request=request,
                headers={"location": "https://cn.bing.com/search?q=example"},
            )
        return httpx.Response(200, request=request, content=b"<html>results</html>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        page, error = await _fetch_trusted_search_page(
            client,
            endpoint="https://www.bing.com/search",
            query="example",
            trusted_suffixes=("bing.com",),
            max_bytes=1024,
        )

    assert page == "<html>results</html>"
    assert error is None
    assert requests == [
        "https://www.bing.com/search?q=example",
        "https://cn.bing.com/search?q=example",
    ]


@pytest.mark.asyncio
async def test_certificate_transparency_domain_source_only_corroborates_seed_root() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["q"] == "%.example.com"
        return httpx.Response(
            200,
            request=request,
            json=[{"name_value": "api.example.com", "common_name": "www.example.com"}],
        )

    source = CertificateTransparencyDomainSource(
        ["example.com"], transport=httpx.MockTransport(handler)
    )
    result = await source.discover(build_company_profile("Acme Security Holdings Limited"))

    assert result.status == "COMPLETED"
    assert [(item.domain, item.signals) for item in result.candidates] == [
        ("example.com", ("TLS_SAN_RELATED",))
    ]
    assert result.candidates[0].source_family == "certificate-transparency"


@pytest.mark.asyncio
async def test_rdap_source_requires_exact_registrant_match_and_reports_partial_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "data.iana.org":
            return httpx.Response(
                200,
                request=request,
                json={
                    "services": [
                        [["com", "example"], ["https://rdap.example.test/rdap/"]],
                    ]
                },
            )
        if request.url.path.endswith("/example.com"):
            return httpx.Response(
                200,
                request=request,
                json={
                    "entities": [
                        {
                            "roles": ["registrant"],
                            "vcardArray": [
                                "vcard",
                                [["fn", {}, "text", "Acme Security Holdings Limited"]],
                            ],
                        }
                    ]
                },
            )
        return httpx.Response(429, request=request, json={"errorCode": 429})

    source = RdapRegistrantSource(
        ["example.com", "unavailable.example"], transport=httpx.MockTransport(handler)
    )
    result = await source.discover(build_company_profile("Acme Security Holdings Limited"))

    assert result.status == "PARTIAL"
    assert result.completed_count == 2
    assert result.attempted_count == 3
    assert result.error is not None and "HTTP_STATUS_429" in result.error
    assert [(item.domain, item.signals) for item in result.candidates] == [
        ("example.com", ("RDAP_REGISTRANT_MATCH",))
    ]
