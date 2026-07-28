import json
from pathlib import Path
from typing import Annotated, Any

import httpx
import typer

from apps.cli.client import ApiClient, ApiClientError
from scopegraph.infrastructure.config import get_settings

app = typer.Typer(
    name="scopegraph",
    help="ScopeGraph local administration CLI.",
    no_args_is_help=True,
)
project_app = typer.Typer(help="Create and manage projects.", no_args_is_help=True)
scope_app = typer.Typer(help="Manage authorized Scope rules.", no_args_is_help=True)
assets_app = typer.Typer(help="Query and import project assets.", no_args_is_help=True)
scan_app = typer.Typer(help="Create and control scan runs.", no_args_is_help=True)
network_app = typer.Typer(
    help="Inspect and classify IP, port, and service inventory.", no_args_is_help=True
)
enterprise_app = typer.Typer(
    help="Discover enterprise root-domain candidates.", no_args_is_help=True
)
root_domain_app = typer.Typer(help="Review candidate root domains.", no_args_is_help=True)
review_app = typer.Typer(help="Process the manual review queue.", no_args_is_help=True)
export_app = typer.Typer(help="Create structured project exports.", no_args_is_help=True)
app.add_typer(project_app, name="project")
app.add_typer(scope_app, name="scope")
app.add_typer(assets_app, name="assets")
app.add_typer(scan_app, name="scan")
app.add_typer(network_app, name="network")
app.add_typer(enterprise_app, name="enterprise")
app.add_typer(root_domain_app, name="root-domain")
app.add_typer(review_app, name="review")
app.add_typer(export_app, name="export")


@app.callback()
def main() -> None:
    """Administer the local ScopeGraph instance."""


def _fetch_health(api_url: str) -> dict[str, Any]:
    api_key = get_settings().api_key
    response = httpx.get(
        f"{api_url.rstrip('/')}/health",
        headers=(
            {"x-scopegraph-api-key": api_key.get_secret_value()} if api_key is not None else None
        ),
        timeout=5.0,
    )
    data: dict[str, Any] = response.json()
    return data


def _emit(data: Any, output_json: bool) -> None:
    if output_json:
        typer.echo(json.dumps(data, ensure_ascii=False))
        return
    if isinstance(data, list):
        for item in data:
            typer.echo(
                "  ".join(
                    str(item.get(key, ""))
                    for key in (
                        "id",
                        "sequence",
                        "name",
                        "job_type",
                        "adapter_name",
                        "ip",
                        "classification",
                        "port",
                        "protocol",
                        "rule_type",
                        "action",
                        "value",
                        "status",
                        "progress",
                    )
                    if key in item
                )
            )
        return
    typer.echo(json.dumps(data, ensure_ascii=False, indent=2))


def _client(api_url: str) -> ApiClient:
    api_key = get_settings().api_key
    return ApiClient(
        api_url,
        api_key=api_key.get_secret_value() if api_key is not None else None,
    )


def _api_call(call: Any) -> Any:
    try:
        return call()
    except ApiClientError as exc:
        typer.secho(f"{exc.code}: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def doctor(
    api_url: Annotated[
        str,
        typer.Option(help="ScopeGraph API base URL."),
    ] = get_settings().api_url,
    output_json: Annotated[
        bool,
        typer.Option("--json", help="Emit machine-readable JSON."),
    ] = False,
) -> None:
    """Check API, PostgreSQL, Redis, storage, and the local runtime."""
    try:
        result = _fetch_health(api_url)
    except (httpx.HTTPError, ValueError) as exc:
        failure = {
            "status": "unreachable",
            "api_url": api_url,
            "error": str(exc),
        }
        if output_json:
            typer.echo(json.dumps(failure, ensure_ascii=False))
        else:
            typer.secho("ScopeGraph doctor: API unreachable", fg=typer.colors.RED, bold=True)
            typer.echo(f"  API: {api_url}")
            typer.echo(f"  Error: {exc}")
        raise typer.Exit(code=1) from exc

    if output_json:
        typer.echo(json.dumps(result, ensure_ascii=False))
    else:
        healthy = result.get("status") == "healthy"
        color = typer.colors.GREEN if healthy else typer.colors.YELLOW
        typer.secho(
            f"ScopeGraph doctor: {result.get('status', 'unknown')}",
            fg=color,
            bold=True,
        )
        for name, check in result.get("checks", {}).items():
            typer.echo(f"  {name:<12} {check.get('status', 'unknown')}")

    if result.get("status") != "healthy":
        raise typer.Exit(code=1)


@project_app.command("create")
def project_create(
    name: Annotated[str, typer.Option("--name", help="Local project name.")],
    company: Annotated[str, typer.Option("--company", help="Authorized company name.")],
    authorized: Annotated[
        bool,
        typer.Option("--authorized", help="Confirm that you have authorization for this target."),
    ] = False,
    root_domains: Annotated[
        list[str] | None,
        typer.Option("--root-domain", help="Confirmed root domain; may be repeated."),
    ] = None,
    profile: Annotated[str, typer.Option(help="quick, standard, deep, or custom.")] = "standard",
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Create a project without starting a scan."""
    if not authorized:
        typer.secho(
            "--authorized is required; project creation never starts a scan.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=2)
    data = _api_call(
        lambda: _client(api_url).request(
            "POST",
            "/api/v1/projects",
            json={
                "name": name,
                "company_name": company,
                "authorization_confirmed": True,
                "known_root_domains": root_domains or [],
                "default_scan_profile": profile,
            },
        )
    )
    _emit(data, output_json)


@project_app.command("list")
def project_list(
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(lambda: _client(api_url).request("GET", "/api/v1/projects"))
    _emit(data if output_json else data.get("items", []), output_json)


@project_app.command("show")
def project_show(
    project_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(lambda: _client(api_url).request("GET", f"/api/v1/projects/{project_id}"))
    _emit(data, output_json)


@project_app.command("update")
def project_update(
    project_id: str,
    name: Annotated[str | None, typer.Option("--name")] = None,
    company: Annotated[str | None, typer.Option("--company")] = None,
    project_status: Annotated[
        str | None, typer.Option("--status", help="DRAFT, ACTIVE, or ARCHIVED.")
    ] = None,
    profile: Annotated[str | None, typer.Option("--profile")] = None,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    payload = {
        key: value
        for key, value in {
            "name": name,
            "company_name": company,
            "status": project_status,
            "default_scan_profile": profile,
        }.items()
        if value is not None
    }
    if not payload:
        typer.secho("Specify at least one field to update.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    data = _api_call(
        lambda: _client(api_url).request("PATCH", f"/api/v1/projects/{project_id}", json=payload)
    )
    _emit(data, output_json)


@project_app.command("delete")
def project_delete(
    project_id: str,
    confirmed: Annotated[
        bool, typer.Option("--yes", help="Confirm soft deletion of this project.")
    ] = False,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
) -> None:
    if not confirmed:
        typer.secho(
            "--yes is required. This operation soft-deletes the project.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=2)
    project = _api_call(lambda: _client(api_url).request("GET", f"/api/v1/projects/{project_id}"))
    project_name = project.get("name") if isinstance(project, dict) else None
    if not isinstance(project_name, str) or not project_name:
        typer.secho("Cannot read the project name required for deletion.", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    _api_call(
        lambda: _client(api_url).request(
            "DELETE",
            f"/api/v1/projects/{project_id}",
            json={"confirmation": project_name},
        )
    )
    typer.echo("Project soft-deleted.")


def _scope_target(
    domain: str | None,
    root_domain: str | None,
    ip: str | None,
    cidr: str | None,
    url: str | None,
) -> tuple[str, str]:
    candidates = [
        ("DOMAIN", domain),
        ("ROOT_DOMAIN", root_domain),
        ("IP", ip),
        ("CIDR", cidr),
        ("URL", url),
    ]
    selected = [(kind, value) for kind, value in candidates if value is not None]
    if len(selected) != 1:
        typer.secho("Specify exactly one scope target option.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    kind, value = selected[0]
    return kind, value


@scope_app.command("add")
def scope_add(
    project_id: str,
    domain: Annotated[str | None, typer.Option("--domain")] = None,
    root_domain: Annotated[str | None, typer.Option("--root-domain")] = None,
    ip: Annotated[str | None, typer.Option("--ip")] = None,
    cidr: Annotated[str | None, typer.Option("--cidr")] = None,
    url: Annotated[str | None, typer.Option("--url")] = None,
    exclude: Annotated[bool, typer.Option("--exclude", help="Create an exclusion rule.")] = False,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    rule_type, value = _scope_target(domain, root_domain, ip, cidr, url)
    data = _api_call(
        lambda: _client(api_url).request(
            "POST",
            f"/api/v1/projects/{project_id}/scope-rules",
            json={
                "rule_type": rule_type,
                "value": value,
                "action": "EXCLUDE" if exclude else "INCLUDE",
                "source": "USER",
            },
        )
    )
    _emit(data, output_json)


@scope_app.command("list")
def scope_list(
    project_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request("GET", f"/api/v1/projects/{project_id}/scope-rules")
    )
    _emit(data, output_json)


@scope_app.command("check")
def scope_check(
    project_id: str,
    value: str,
    asset_type: Annotated[str, typer.Option("--type", help="domain, ip, or url.")] = "domain",
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request(
            "POST",
            f"/api/v1/projects/{project_id}/scope/check",
            json={"asset_type": asset_type, "value": value},
        )
    )
    _emit(data, output_json)


@assets_app.command("list")
def assets_list(
    project_id: str,
    asset_type: Annotated[str | None, typer.Option("--type")] = None,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    params = {"asset_type": asset_type} if asset_type else None
    data = _api_call(
        lambda: _client(api_url).request(
            "GET", f"/api/v1/projects/{project_id}/assets", params=params
        )
    )
    _emit(data if output_json else data.get("items", []), output_json)


@assets_app.command("import")
def assets_import(
    project_id: str,
    file_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).upload(f"/api/v1/projects/{project_id}/assets/import", file_path)
    )
    _emit(data, output_json)


@scan_app.command("start")
def scan_start(
    project_id: str,
    root_domain: Annotated[str, typer.Option("--root-domain")],
    authorized: Annotated[
        bool, typer.Option("--authorized", help="Reconfirm authorization for this scan.")
    ] = False,
    mode: Annotated[
        str, typer.Option(help="fixture for offline validation, or host for installed tools.")
    ] = "fixture",
    allow_active: Annotated[
        bool,
        typer.Option(
            "--allow-active",
            help="Explicitly allow active host tool execution; required with --mode host.",
        ),
    ] = False,
    profile: Annotated[str, typer.Option(help="quick, standard, deep, or custom.")] = "standard",
    confirm_deep: Annotated[
        bool,
        typer.Option("--confirm-deep", help="Second confirmation required for the deep profile."),
    ] = False,
    custom_config_path: Annotated[
        Path | None,
        typer.Option(
            "--custom-config",
            help="UTF-8 JSON file containing only the closed custom profile fields.",
        ),
    ] = None,
    port_scan: Annotated[
        bool | None,
        typer.Option(
            "--port-scan/--no-port-scan",
            help="Override the profile only to enable or disable its port stage.",
        ),
    ] = None,
    full_port: Annotated[
        bool,
        typer.Option("--full-port", help="Request ports 1-65535; OWNED IPs only."),
    ] = False,
    confirm_full_port: Annotated[
        bool,
        typer.Option(
            "--confirm-full-port",
            help="Second confirmation required with --full-port.",
        ),
    ] = False,
    nuclei: Annotated[
        bool,
        typer.Option("--nuclei", help="Enable the approved Nuclei template allowlist."),
    ] = False,
    confirm_nuclei: Annotated[
        bool,
        typer.Option("--confirm-nuclei", help="Second confirmation required with --nuclei."),
    ] = False,
    proxy_url: Annotated[
        str | None,
        typer.Option(
            "--proxy", help="HTTP(S) proxy or Burp listener without embedded credentials."
        ),
    ] = None,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Queue the phase-2 root-domain chain after explicit authorization and Scope checks."""
    if not authorized:
        typer.secho("--authorized is required for every scan run.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    if mode == "host" and not allow_active:
        typer.secho("--mode host also requires --allow-active.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    normalized_profile = profile.casefold()
    if normalized_profile == "deep" and not confirm_deep:
        typer.secho("--profile deep also requires --confirm-deep.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    if confirm_deep and normalized_profile != "deep":
        typer.secho("--confirm-deep is only valid with --profile deep.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    if normalized_profile == "custom" and custom_config_path is None:
        typer.secho("--profile custom requires --custom-config.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    if normalized_profile != "custom" and custom_config_path is not None:
        typer.secho("--custom-config is only valid with --profile custom.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    custom_config: dict[str, Any] | None = None
    if custom_config_path is not None:
        try:
            raw = custom_config_path.read_bytes()
            if len(raw) > 65_536:
                raise ValueError("custom profile file exceeds 64 KiB")
            decoded = json.loads(raw.decode("utf-8"))
            if not isinstance(decoded, dict):
                raise ValueError("custom profile must be a JSON object")
            custom_config = decoded
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            typer.secho(f"Invalid --custom-config: {exc}", fg=typer.colors.RED)
            raise typer.Exit(code=2) from exc
    if full_port and not confirm_full_port:
        typer.secho(
            "--full-port also requires --confirm-full-port.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=2)
    if confirm_full_port and not full_port:
        typer.secho(
            "--confirm-full-port is only valid with --full-port.",
            fg=typer.colors.RED,
        )
        raise typer.Exit(code=2)
    if nuclei and not confirm_nuclei:
        typer.secho("--nuclei also requires --confirm-nuclei.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    if confirm_nuclei and not nuclei:
        typer.secho("--confirm-nuclei is only valid with --nuclei.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    payload: dict[str, Any] = {
        "root_domain": root_domain,
        "profile": profile,
        "execution_mode": mode,
        "authorization_confirmed": True,
        "allow_active_execution": allow_active,
        "deep_confirmation": normalized_profile == "deep" and confirm_deep,
        "nuclei_enabled": nuclei,
        "nuclei_confirmation": nuclei and confirm_nuclei,
        "proxy_url": proxy_url,
    }
    if custom_config is not None:
        payload["custom_config"] = custom_config
    if port_scan is not None:
        payload["port_scan_enabled"] = port_scan
    if full_port:
        payload["full_port_scan"] = True
        payload["full_port_confirmation"] = True
    data = _api_call(
        lambda: _client(api_url).request(
            "POST",
            f"/api/v1/projects/{project_id}/scan-runs",
            json=payload,
        )
    )
    _emit(data, output_json)


@scan_app.command("list")
def scan_list(
    project_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request("GET", f"/api/v1/projects/{project_id}/scan-runs")
    )
    _emit(data if output_json else data.get("items", []), output_json)


@scan_app.command("show")
def scan_show(
    scan_run_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(lambda: _client(api_url).request("GET", f"/api/v1/scan-runs/{scan_run_id}"))
    _emit(data, output_json)


@scan_app.command("jobs")
def scan_jobs(
    scan_run_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request("GET", f"/api/v1/scan-runs/{scan_run_id}/jobs")
    )
    _emit(data, output_json)


def _scan_action(action: str, scan_run_id: str, api_url: str, output_json: bool) -> None:
    data = _api_call(
        lambda: _client(api_url).request("POST", f"/api/v1/scan-runs/{scan_run_id}/{action}")
    )
    _emit(data, output_json)


@scan_app.command("pause")
def scan_pause(
    scan_run_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    _scan_action("pause", scan_run_id, api_url, output_json)


@scan_app.command("resume")
def scan_resume(
    scan_run_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    _scan_action("resume", scan_run_id, api_url, output_json)


@scan_app.command("cancel")
def scan_cancel(
    scan_run_id: str,
    confirmed: Annotated[
        bool, typer.Option("--yes", help="Confirm cancellation and process termination.")
    ] = False,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if not confirmed:
        typer.secho("--yes is required to cancel a scan run.", fg=typer.colors.RED)
        raise typer.Exit(code=2)
    _scan_action("cancel", scan_run_id, api_url, output_json)


@scan_app.command("retry")
def scan_retry(
    scan_job_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request("POST", f"/api/v1/scan-jobs/{scan_job_id}/retry")
    )
    _emit(data, output_json)


@network_app.command("ips")
def network_ips(
    project_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(lambda: _client(api_url).request("GET", f"/api/v1/projects/{project_id}/ips"))
    _emit(data, output_json)


@enterprise_app.command("discover")
def enterprise_discover(
    project_id: str,
    mode: Annotated[
        str, typer.Option(help="local, fixture, or public passive discovery.")
    ] = "local",
    alias: Annotated[list[str] | None, typer.Option("--alias")] = None,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request(
            "POST",
            f"/api/v1/projects/{project_id}/enterprise-discovery",
            json={"execution_mode": mode, "aliases": alias or []},
        )
    )
    _emit(data, output_json)


@root_domain_app.command("list")
def root_domain_list(
    project_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request(
            "GET", f"/api/v1/projects/{project_id}/candidate-root-domains"
        )
    )
    _emit(data, output_json)


@root_domain_app.command("confirm")
def root_domain_confirm(
    project_id: str,
    candidate_id: str,
    reason: Annotated[str, typer.Option(help="Auditable manual confirmation reason.")],
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request(
            "POST",
            f"/api/v1/projects/{project_id}/candidate-root-domains/{candidate_id}/review",
            json={"decision": "ADD_TO_SCOPE", "reason": reason},
        )
    )
    _emit(data, output_json)


@review_app.command("list")
def review_list(
    project_id: str,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request("GET", f"/api/v1/projects/{project_id}/review-queue")
    )
    _emit(data, output_json)


@app.command("diff")
def diff_runs(
    project_id: str,
    from_run: Annotated[str, typer.Option("--from")],
    to_run: Annotated[str, typer.Option("--to")],
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request(
            "GET",
            f"/api/v1/projects/{project_id}/diff",
            params={"from": from_run, "to": to_run},
        )
    )
    _emit(data, output_json)


@export_app.command("create")
def export_create(
    project_id: str,
    export_format: Annotated[str, typer.Option("--format")] = "xlsx",
    export_scope: Annotated[str, typer.Option("--scope")] = "confirmed-and-high",
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request(
            "POST",
            f"/api/v1/projects/{project_id}/exports",
            json={"export_format": export_format, "export_scope": export_scope},
        )
    )
    _emit(data, output_json)


@network_app.command("ports")
def network_ports(
    project_id: str,
    scan_run_id: Annotated[str | None, typer.Option("--scan-run-id")] = None,
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    params = {"scan_run_id": scan_run_id} if scan_run_id else None
    data = _api_call(
        lambda: _client(api_url).request(
            "GET", f"/api/v1/projects/{project_id}/ports", params=params
        )
    )
    _emit(data, output_json)


@network_app.command("classify")
def network_classify(
    project_id: str,
    asset_id: str,
    classification: Annotated[
        str,
        typer.Option(
            help="OWNED, CLOUD_SERVER, SHARED_HOSTING, CDN_WAF, UNKNOWN, or PRIVATE_RESERVED."
        ),
    ],
    reason: Annotated[str, typer.Option(help="Audit evidence for the classification decision.")],
    api_url: Annotated[str, typer.Option(help="ScopeGraph API base URL.")] = get_settings().api_url,
    output_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    data = _api_call(
        lambda: _client(api_url).request(
            "PATCH",
            f"/api/v1/projects/{project_id}/ips/{asset_id}",
            json={"classification": classification.upper(), "reason": reason},
        )
    )
    _emit(data, output_json)


if __name__ == "__main__":
    app()
