from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

EDITIONS = {
    "internal": {
        "project": "scopegraph",
        "api_image": "scopegraph-api",
        "api_port": "8000",
        "mcp_port": "8001",
        "web_port": "8080",
    },
    "community": {
        "project": "scopegraph-community",
        "api_image": "scopegraph-community-api",
        "api_port": "18000",
        "mcp_port": "18001",
        "web_port": "18080",
        "mcp_client": "scopegraph-community",
    },
}


def _example_environment() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key] = value
    return values


def test_distribution_defaults_are_isolated_and_visible() -> None:
    environment = _example_environment()
    edition = environment["SCOPEGRAPH_EDITION"]
    expected = EDITIONS[edition]
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    launcher = (ROOT / "Start-ScopeGraph.cmd").read_text(encoding="utf-8")

    assert f"name: ${{SCOPEGRAPH_COMPOSE_PROJECT:-{expected['project']}}}" in compose
    assert f"image: ${{SCOPEGRAPH_API_IMAGE:-{expected['api_image']}}}" in compose
    assert f'SCOPEGRAPH_EDITION: "{edition}"' in compose
    if edition == "community":
        assert "SCOPEGRAPH_WEB_ALLOWED_HOSTS: ${SCOPEGRAPH_WEB_ALLOWED_HOSTS:-}" in compose
        assert "SCOPEGRAPH_PROXY_MAX_BODY_BYTES: ${SCOPEGRAPH_PROXY_MAX_BODY_BYTES:-}" in compose
    assert "SCOPEGRAPH_API_URL: http://127.0.0.1:8000" in compose
    assert (
        f'"127.0.0.1:${{SCOPEGRAPH_API_HOST_PORT:-{expected["api_port"]}}}:8000"'
        in compose
    )
    assert (
        f'"127.0.0.1:${{SCOPEGRAPH_MCP_HOST_PORT:-{expected["mcp_port"]}}}:8001"'
        in compose
    )
    assert (
        f'"127.0.0.1:${{SCOPEGRAPH_WEB_HOST_PORT:-{expected["web_port"]}}}:3000"'
        in compose
    )
    assert f'set "EDITION={edition}"' in launcher
    assert f'set "DEFAULT_WEB_HOST_PORT={expected["web_port"]}"' in launcher


def test_distribution_default_identifiers_do_not_overlap() -> None:
    internal = EDITIONS["internal"]
    community = EDITIONS["community"]

    assert internal["project"] != community["project"]
    assert internal["api_image"] != community["api_image"]
    assert {
        internal["api_port"],
        internal["mcp_port"],
        internal["web_port"],
    }.isdisjoint(
        {
            community["api_port"],
            community["mcp_port"],
            community["web_port"],
        }
    )


def test_internal_checkout_excludes_nested_public_release_from_build_context() -> None:
    environment = _example_environment()
    if environment["SCOPEGRAPH_EDITION"] != "internal":
        return

    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert "public-release" in {line.strip().rstrip("/") for line in dockerignore}


def test_launcher_checks_selected_docker_context_before_desktop_fallback() -> None:
    launcher = (ROOT / "Start-ScopeGraph.cmd").read_text(encoding="utf-8")
    selected_context_check = launcher.index("call :check_docker_ready")
    desktop_fallback = launcher.index('if /i "%DOCKER_CONTEXT%"=="default"')

    assert selected_context_check < desktop_fallback
    assert launcher.count("call :check_docker_ready") >= 3


def test_launcher_check_mode_exits_before_starting_services() -> None:
    launcher = (ROOT / "Start-ScopeGraph.cmd").read_text(encoding="utf-8")
    docker_ready = launcher.index(":docker_ready")
    check_exit = launcher.index('if "%CHECK_ONLY%"=="1" (', docker_ready)
    compose_up = launcher.index("docker compose up -d --build", docker_ready)

    assert docker_ready < check_exit < compose_up
    assert "No services were started" in launcher[check_exit:compose_up]


def test_launcher_waits_work_with_redirected_input() -> None:
    launcher = (ROOT / "Start-ScopeGraph.cmd").read_text(encoding="utf-8")

    assert launcher.count("ping.exe 127.0.0.1 -n 3 >nul") == 2
    assert "timeout /t" not in launcher


def test_mcp_client_name_is_edition_specific() -> None:
    environment = _example_environment()
    expected = EDITIONS[environment["SCOPEGRAPH_EDITION"]]
    guides = [ROOT / "README.md", ROOT / "docs" / "MCP.md"]
    campus_guide = ROOT / "docs" / "CAMPUS_DEMO.md"
    if campus_guide.exists():
        guides.append(campus_guide)

    for guide in guides:
        source = guide.read_text(encoding="utf-8")
        assert f'"{expected["mcp_client"]}":' in source
        assert '"scopegraph":' not in source


def test_community_integration_smokes_use_configurable_host_ports() -> None:
    if _example_environment()["SCOPEGRAPH_EDITION"] != "community":
        return

    integration = ROOT / "tests" / "integration"
    scripts = [
        integration / name
        for name in (
            "phase2_smoke.py",
            "phase3_smoke.py",
            "phase4_smoke.py",
            "phase5_smoke.py",
            "phase5_async_smoke.py",
            "phase6_smoke.py",
            "phase7_smoke.py",
            "restart_recovery.py",
        )
    ]
    for script in scripts:
        source = script.read_text(encoding="utf-8")
        assert 'os.getenv("SCOPEGRAPH_API_HOST_PORT", "18000")' in source
        assert 'HTTPConnection("127.0.0.1", 8000' not in source

    phase7 = (integration / "phase7_smoke.py").read_text(encoding="utf-8")
    assert 'os.getenv("SCOPEGRAPH_WEB_HOST_PORT", "18080")' in phase7
    assert "port=8080" not in phase7

    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for script in scripts[:-1]:
        assert f"python tests/integration/{script.name}" in workflow
    assert "python -m apps.mcp_server.smoke" in workflow
    assert "restart_recovery.py queue" in workflow
    assert "restart_recovery.py wait" in workflow
    assert "docker compose up -d worker" in workflow
    assert "docker compose start worker" not in workflow


def test_python_container_uses_verified_constraints_and_configurable_mirrors() -> None:
    dockerfile = (ROOT / "docker" / "python.Dockerfile").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    constraints = ROOT / "constraints" / "python312.txt"

    assert constraints.is_file()
    assert "--constraint constraints/python312.txt" in dockerfile
    assert "ARG DEBIAN_MIRROR=http://deb.debian.org/debian" in dockerfile
    assert "SCOPEGRAPH_DEBIAN_MIRROR" in compose
    assert "mirrors.ustc.edu.cn" not in dockerfile


def test_web_fallback_matches_distribution() -> None:
    edition = _example_environment()["SCOPEGRAPH_EDITION"]
    health_route = (ROOT / "apps/web/app/api/health/route.ts").read_text(encoding="utf-8")
    app_header = (ROOT / "apps/web/components/projects/app-header.tsx").read_text(
        encoding="utf-8"
    )
    system_center = (ROOT / "apps/web/components/projects/system-center.tsx").read_text(
        encoding="utf-8"
    )

    assert 'settings?.edition?.toUpperCase() ?? "UNKNOWN"' in system_center
    assert '      : "无法读取运行版本";' in system_center

    if edition == "internal":
        assert '=== "community" ? "community" : "internal"' in health_route
        assert '=== "community" ? "COMMUNITY" : "INTERNAL"' in app_header
    else:
        assert '=== "internal" ? "internal" : "community"' in health_route
        assert '=== "internal" ? "INTERNAL" : "COMMUNITY"' in app_header
