from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from scopegraph.application.services.scan_execution import (
    _active_domains,
    _active_websites,
    _crawler_parallelism,
    _crawler_per_site_limit,
    _crawler_target_duration_seconds,
    _job_waves,
    _naabu_output_looks_intercepted,
    _preferred_crawl_urls,
    _scan_run_lock_key,
)
from scopegraph.application.services.scans import _stage_timeout_seconds
from scopegraph.domain.enums import ScanProfile, ScopeAction, ScopeRuleType
from scopegraph.scanning.profiles import load_profile
from scopegraph.scope_engine import ScopeRuleValue


def test_naabu_saturation_guard_quarantines_large_all_open_results() -> None:
    summary: dict[str, object] = {
        "scan_targets": 171,
        "ports_tested_per_target": 4,
        "candidate_socket_checks": 684,
    }

    suspicious, ratio = _naabu_output_looks_intercepted(summary, 684)
    normal, normal_ratio = _naabu_output_looks_intercepted(summary, 12)

    assert suspicious is True
    assert ratio == 1.0
    assert normal is False
    assert normal_ratio < 0.02


def test_naabu_saturation_guard_quarantines_small_all_open_results() -> None:
    suspicious, _ = _naabu_output_looks_intercepted(
        {
            "scan_targets": 2,
            "ports_tested_per_target": 2,
            "candidate_socket_checks": 4,
        },
        4,
    )

    assert suspicious is True

    partial, ratio = _naabu_output_looks_intercepted(
        {
            "scan_targets": 2,
            "ports_tested_per_target": 2,
            "candidate_socket_checks": 4,
        },
        2,
    )
    assert partial is False
    assert ratio == 0.5


def test_scan_run_lock_key_is_stable_signed_int64() -> None:
    run_id = uuid4()

    first = _scan_run_lock_key(run_id)

    assert first == _scan_run_lock_key(run_id)
    assert -(2**63) <= first < 2**63
    assert first != _scan_run_lock_key(uuid4())


@pytest.mark.asyncio
async def test_confirmed_root_continues_when_subfinder_finds_nothing() -> None:
    session = SimpleNamespace(scalars=AsyncMock(return_value=[]))
    run = SimpleNamespace(
        id=uuid4(),
        project_id=uuid4(),
        config_snapshot={"root_domain": "Example.COM"},
    )
    rules = [
        ScopeRuleValue(
            rule_type=ScopeRuleType.ROOT_DOMAIN,
            value="example.com",
            action=ScopeAction.INCLUDE,
        )
    ]

    domains = await _active_domains(session, run, rules)  # type: ignore[arg-type]

    assert domains == ["example.com"]


@pytest.mark.asyncio
async def test_active_domains_are_isolated_to_the_run_root() -> None:
    session = SimpleNamespace(
        scalars=AsyncMock(
            return_value=["www.example.com", "example.net", "cdn.example.net"]
        )
    )
    run = SimpleNamespace(
        id=uuid4(),
        project_id=uuid4(),
        config_snapshot={"root_domain": "example.com"},
    )
    rules = [
        ScopeRuleValue(
            rule_type=ScopeRuleType.ROOT_DOMAIN,
            value="example.com",
            action=ScopeAction.INCLUDE,
        ),
        ScopeRuleValue(
            rule_type=ScopeRuleType.ROOT_DOMAIN,
            value="example.net",
            action=ScopeAction.INCLUDE,
        ),
    ]

    domains = await _active_domains(session, run, rules)  # type: ignore[arg-type]

    assert domains == ["example.com", "www.example.com"]


@pytest.mark.asyncio
async def test_active_websites_are_isolated_to_the_run_root() -> None:
    session = SimpleNamespace(
        scalars=AsyncMock(
            return_value=[
                "https://www.example.com/",
                "https://portal.example.net/",
                "https://cdn.example.net/",
            ]
        )
    )
    run = SimpleNamespace(
        id=uuid4(),
        project_id=uuid4(),
        config_snapshot={"root_domain": "example.com"},
    )
    rules = [
        ScopeRuleValue(
            rule_type=ScopeRuleType.ROOT_DOMAIN,
            value="example.com",
            action=ScopeAction.INCLUDE,
        ),
        ScopeRuleValue(
            rule_type=ScopeRuleType.ROOT_DOMAIN,
            value="example.net",
            action=ScopeAction.INCLUDE,
        ),
    ]

    websites = await _active_websites(session, run, rules)  # type: ignore[arg-type]

    assert websites == ["https://www.example.com/"]


def test_standard_crawl_budget_is_distributed_across_targets() -> None:
    standard = load_profile(ScanProfile.STANDARD)

    assert _crawler_parallelism(110) == 8
    assert _crawler_per_site_limit(standard, 110) == 27
    assert _crawler_per_site_limit(standard, 1) == 2000
    assert _crawler_target_duration_seconds(standard, 1, 1) == 120
    assert _crawler_target_duration_seconds(standard, 110, 8) == 17
    assert _stage_timeout_seconds("katana", standard) == 660
    assert _stage_timeout_seconds("puredns", standard) == 180
    assert _stage_timeout_seconds("screenshot", standard) == 600


def test_crawl_seeds_prefer_one_https_root_per_host() -> None:
    assert _preferred_crawl_urls(
        [
            "http://www.example.com/",
            "https://www.example.com/login",
            "https://www.example.com/",
            "https://api.example.com/",
        ]
    ) == ["https://api.example.com/", "https://www.example.com/"]


def test_scan_jobs_are_grouped_into_dependency_safe_parallel_waves() -> None:
    stage_types = [
        "passive_subdomain",
        "dns_bruteforce_validation",
        "domain_variants",
        "dns_permutation_validation",
        "dns_enrichment",
        "port_discovery",
        "service_detection",
        "http_probe",
        "website_screenshot",
        "web_crawl",
        "safe_security_discovery",
    ]
    jobs = [
        SimpleNamespace(id=uuid4(), sequence=index, job_type=job_type)
        for index, job_type in enumerate(stage_types)
    ]
    by_id = {job.id: job.job_type for job in jobs}

    waves = [[by_id[job_id] for job_id in wave] for wave in _job_waves(jobs)]  # type: ignore[arg-type]

    assert waves == [
        ["passive_subdomain"],
        ["dns_bruteforce_validation", "domain_variants"],
        ["dns_permutation_validation"],
        ["dns_enrichment"],
        ["port_discovery", "http_probe"],
        [
            "service_detection",
            "website_screenshot",
            "web_crawl",
            "safe_security_discovery",
        ],
    ]
