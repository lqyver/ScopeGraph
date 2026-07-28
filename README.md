# ScopeGraph

> A local-first, authorization-gated platform for discovering, validating, and reviewing the public attack surface of systems you are allowed to assess.

[English](./README.md) · [简体中文](./README.zh-CN.md)

ScopeGraph turns an explicitly confirmed root domain into a traceable asset graph. It is not a replacement for a one-off subdomain-enumeration command: it coordinates discovery, DNS validation, scoped network checks, web inventory, low-risk finding collection, historical comparison, and export in one local workflow.

> **Authorized use only.** Use ScopeGraph only for assets you own or for which you have explicit permission to test. Discovery results are candidates, not proof of ownership; active operations require confirmed authorization and Scope rules.

## What it provides

| Area | What ScopeGraph does |
|---|---|
| Enterprise onboarding | Starts from a company name, gathers candidate roots from bounded public search sources, corroborates discovered candidates with certificate SAN and public RDAP registrant evidence, streams durable per-source progress to the Web UI, and requires a human decision before a root enters Scope. |
| Scope and asset graph | Stores domains, IPs, ports, services, websites, technologies, endpoints, ICP evidence, findings, and provenance as structured, deduplicated records. |
| Controlled collection | Supports Quick, Standard, Deep, and validated Custom profiles. The pipeline can combine Subfinder, PureDNS/MassDNS, AlterX, dnsx, Naabu, Nmap, httpx, screenshots, Katana, and Nuclei through bounded adapters. |
| Live progress | Shows run, stage, and job status while work is running, including partial-success diagnostics, asset-funnel metrics, elapsed time, and parallelism savings. |
| Risk-aware checks | Keeps third-party/CDN/private addresses out of unsafe port checks by default; full-port, Deep, Custom, and Nuclei paths need additional explicit confirmation. Nuclei uses technology-aware, low-risk templates and marks findings as unverified. |
| Review and export | Provides review queues, scan-history diffs, raw-artifact traceability, retention/storage controls, and CSV ZIP, XLSX, JSON, HTML, and Markdown exports. |
| Web, CLI, and MCP | Includes a Next.js web UI, a Typer CLI, and a local MCP server for agent-assisted, read-only asset intelligence. |

## Why not run only `subfinder`?

`subfinder` is a useful input to the workflow, but it only answers part of the question. ScopeGraph carries an authorized root through a controlled flow:

```text
Candidate roots → human Scope confirmation → passive discovery / DNS validation
→ scoped IP and port policy → service and HTTP inventory → web and endpoint discovery
→ optional low-risk Nuclei collection → review, diff, and export
```

The independent branches run as a bounded DAG: after Subfinder, validation and variant-generation work can proceed in parallel; after DNS aggregation, the network and HTTP branches can proceed in parallel. The run keeps source outputs, stage results, and provenance so that results remain reviewable instead of becoming an unstructured command log.

## Quick start

### Requirements

- Docker Desktop (or Docker Engine) with Docker Compose v2
- At least 4 CPU cores, 8 GiB RAM, and 20 GiB free disk space recommended
- On Windows, Docker Desktop with the WSL2 backend is recommended

### Windows: one-click startup

Double-click [`Start-ScopeGraph.cmd`](./Start-ScopeGraph.cmd), or run:

```powershell
.\Start-ScopeGraph.cmd
```

The script starts Docker Desktop if necessary, builds changed images, waits for API and web health, and opens the project page in the default browser. For automation, use `--no-open`; use `--no-build` only when you know that the current images match the source tree. Fast launches preserve matching healthy containers, so they do not interrupt an active scan.

### Docker Compose

```powershell
Copy-Item .env.example .env
docker compose up -d --build
docker compose ps
docker compose exec api scopegraph doctor --json
```

When the health report is ready, open:

- Web UI: <http://127.0.0.1:8080/projects>
- API documentation: <http://127.0.0.1:8000/docs>
- MCP endpoint: <http://127.0.0.1:8001/mcp>

The default Compose configuration binds Web, API, and MCP only to `127.0.0.1`. PostgreSQL and Redis are internal-only services.

## First successful collection

1. Open the **Projects** page and create a project. Confirm that you have authorization for the target organization.
2. In **Enterprise Discovery**, run passive discovery or select the explicit offline `fixture` mode for a safe demonstration. The UI follows the persisted run while each source completes. Inspect source coverage, per-source diagnostics, and candidate evidence; a source failure is distinct from a completed source with no candidates.
3. Select a candidate root domain, or add one manually. Confirm it to add the root to Scope; do not treat a candidate as authorization by itself.
4. Open **Scans**, choose the confirmed root and an appropriate profile, then explicitly authorize an active run when using real tools.
5. Follow live stage results and review the Scope, Assets, Network, Websites, Findings, History, and Export views after the run reaches a terminal state.

The offline `fixture` mode is for demonstrations and tests only. Its outputs are labelled as fixture evidence and must not be interpreted as real-world findings.

## Profiles and execution boundaries

| Profile | Intended use | Important guardrails |
|---|---|---|
| Quick | Fast, scoped inventory of a confirmed root. | Uses a bounded web-port policy and does not imply full-port coverage. |
| Standard | Default broader inventory with DNS variants, service detection, crawling, and bounded concurrency. | Operates only on a confirmed Scope and still respects CDN/private-address restrictions. |
| Deep | Larger wordlists, broader bounded port set, and more extensive web discovery. | Requires a separate Deep confirmation; it is not a full `1-65535` scan. |
| Custom | A validated JSON policy for an explicitly controlled workflow. | Unknown fields and arbitrary command lines are rejected. |

Full-port scans require an in-scope IP explicitly classified as `OWNED` plus a second confirmation. Nuclei is disabled unless explicitly requested and confirmed; only version-pinned, technology-matched low-risk templates are available by default. ScopeGraph never silently upgrades tools or templates at runtime.

## MCP for external agents

The bundled MCP server lets a connected agent use ScopeGraph without first reading repository documentation. It is read-only by default.

```json
{
  "mcpServers": {
    "scopegraph": {
      "type": "http",
      "url": "http://127.0.0.1:8001/mcp"
    }
  }
}
```

An agent should call `scopegraph_get_started` first. It receives live health, visible projects, permissions, safety boundaries, and recommended next calls. `scopegraph_all_in_one_snapshot` then returns a bounded project-wide snapshot of Scope, assets, websites, network inventory, findings, recent runs, and the latest asset funnel in one request.

Set `SCOPEGRAPH_MCP_ALLOW_SCAN_START=true` in `.env` only when a local administrator intentionally wants an agent to start a Quick or Standard collection for an already confirmed root. MCP never exposes Scope approval, Deep, Custom, full-port, or Nuclei execution.

See the [MCP guide](./docs/MCP.md) for stdio transport, the complete tool list, and smoke-test commands.

## CLI examples

Run CLI commands inside the API container when using Docker:

```powershell
docker compose exec api scopegraph doctor
docker compose exec api scopegraph project list --json
docker compose exec api scopegraph scope list <project-id> --json
docker compose exec api scopegraph scan list <project-id> --json
docker compose exec api scopegraph network ports <project-id> --json
```

Use `docker compose exec api scopegraph --help` to see all commands. Operations that can change scope or initiate collection retain the same authorization and confirmation checks as the web UI.

## Configuration and safe deployment

Keep the default local-only binding for normal use. If you deliberately expose a non-loopback deployment, set both `SCOPEGRAPH_PUBLIC_BIND=true` and a strong `SCOPEGRAPH_API_KEY`, then place the service behind TLS, access controls, and audit logging. The API refuses public binding without the required key.

Configure an HTTP proxy or Burp forwarding address in the system settings only with a credential-free URL such as `http://host:port`. ScopeGraph validates proxy syntax and keeps its reported target IP and endpoint data separate from a local proxy listener.

Stop the stack without deleting data:

```powershell
docker compose down
```

`docker compose down -v` also deletes local Compose volumes and therefore removes stored data; use it only when that deletion is intentional.

## Development and verification

Docker is the supported runtime. For local development, install Python 3.12 and Node.js 20.9+ (or use the workspace-provided runtimes), then run:

```powershell
.\.venv\Scripts\python.exe -m ruff check apps scopegraph tests
.\.venv\Scripts\python.exe -m mypy apps scopegraph
.\.venv\Scripts\python.exe -m pytest -q
npm --prefix apps/web run lint
npm --prefix apps/web run typecheck
npm --prefix apps/web run test
```

The integration smoke suites use only repository fixtures. They do not contact real internet targets or invoke security tools against third parties.

## Documentation

- [Chinese README](./README.zh-CN.md)
- [Installation](./docs/INSTALLATION.md)
- [MCP integration](./docs/MCP.md)
- [Compatibility and tool policy](./docs/COMPATIBILITY.md)
- [Backup and restore](./docs/BACKUP_RESTORE.md)
- [Upgrade guide](./docs/UPGRADE.md)
- [Release notes](./RELEASE_NOTES_v1.0.0.md)
- [Development guide / product contract](./ScopeGraph_PRD_Development_Guide_v1.0.md)
- [Safe demonstration guide](./docs/SAFE_DEMO.md)
- [Contributing](./CONTRIBUTING.md)
- [Security policy](./SECURITY.md)
- [Support](./SUPPORT.md)
- [Third-party component inventory](./THIRD_PARTY_INVENTORY.md)

## Project layout

```text
apps/api/        FastAPI entry point
apps/worker/     Dramatiq worker entry point
apps/cli/        Typer CLI entry point
apps/web/        Next.js web application
scopegraph/      Shared core package for the API, worker, web, and CLI
migrations/      Alembic migrations
configs/         Version-controlled scan profiles and safety rules
tests/           Unit, integration-fixture, and end-to-end coverage
data/            Local structured data, logs, and retained scan artifacts
```

ScopeGraph is built against the phased requirements in the [development guide](./ScopeGraph_PRD_Development_Guide_v1.0.md). The implementation is local-first, adapter-only, and intentionally avoids automatic Scope expansion.

## License

Copyright 2026 the ScopeGraph contributors. Licensed under the
[Apache License 2.0](./LICENSE).
