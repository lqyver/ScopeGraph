# Community Edition public release readiness

Status snapshot: 2026-09-01. ScopeGraph Community Edition is a locally source- and runtime-verified
release candidate, not yet a published release. The remaining source-release gates are a clean
public commit, the strict boundary check, GitHub-hosted CI, and inspection of the archive produced
from that exact commit. Publishing prebuilt images has an additional third-party notice gate.

## Current gates

| Gate | Status | Evidence or remaining work |
|---|---|---|
| Repository identity and isolation | Passed | Internal `scopegraph` and Community `scopegraph-community` ran concurrently on 2026-08-09 with distinct repositories, Compose projects, image names, working directories, editions, and host ports. Only the Community stack was rebuilt. |
| License and community governance | Passed | Apache-2.0, English-first README, contributing, conduct, security, support, Issue, PR, CI, and Dependabot files are present. Prebuilt-image notices remain a separate gate below. |
| Local source checks | Passed | 147 Python tests, including warnings-as-errors, and 20 Web tests, Ruff, mypy, ESLint, TypeScript, and the Next.js production build passed on 2026-09-01. Coverage is 62.52%, with a CI floor of 60%. |
| Compose parsing | Passed | Default Community Compose parsing and the offline launcher check passed on 2026-08-09; regression tests cover check-only startup, container-local CLI addressing, host-port overrides, configurable Debian mirrors, dependency constraints, and edition-specific MCP client naming. |
| Public boundary/history audit | Passed | No internal marker or prohibited artifact path was found in the 14 locally available public commits; three credential-shaped strings are intentional rejection fixtures. |
| Clean public commit | Pending | The current release-candidate fixes are still uncommitted. Final validation must run without `--allow-dirty`. |
| Fresh Docker image rebuild | Passed locally | `Start-ScopeGraph.cmd --no-open` rebuilt the current Community API and Web images on 2026-09-01. Database, Redis, API, Worker, MCP, and Web were healthy; migration and data-init exited 0. The launcher reached `http://127.0.0.1:18080/projects`. |
| Fixture workflow E2E | Passed locally | Phase 2 through Phase 7, asynchronous enterprise discovery, and Worker stop/queue/start recovery passed against the final local image on 2026-09-01. All runs used loopback-only fixture execution; no real target was scanned. |
| Browser and responsive UI smoke | Pending current-tree rerun | A prior browser smoke passed on 2026-08-09. The current code has route/build checks, but the automated browser helper was unavailable in this environment on 2026-09-01; repeat the desktop and 390px visual pass before calling the candidate final. |
| MCP runtime smoke | Passed locally | The official SDK client discovered 16 tools, loaded the connection-first guide, read status/projects, and verified that scan writes are blocked by default on 2026-09-01. |
| GitHub-hosted CI | Pending | The workflow now declares constrained installs, warnings-as-errors, coverage, complete fixture E2E, MCP safety, and Worker recovery, but the current uncommitted tree has not run on GitHub Actions. |
| Prebuilt-image third-party notices | Pending for image publication | Exact bundled tool versions are inventoried, but mutable base/package tags and final license/NOTICE review still block publication of a prebuilt container image. This does not add binaries to a source-only `git archive`. |
| Release archive inspection | Pending | Generate only from the clean public commit with `git archive`, extract it, and repeat the boundary scan. |

## Offline boundary command

During development, including the current dirty release-candidate tree:

```powershell
python scripts/validate_public_release.py --allow-dirty
```

For the final release commit, omit the override:

```powershell
python scripts/validate_public_release.py
```

The validator does not contact Docker, a browser, package registry, or scan target. It checks the
Community identity, required public files, Apache-2.0 metadata, tracked and untracked candidate
paths, internal-only markers, credential shapes, nested-repository configuration, and Git
cleanliness.

## Release decision

Do not publish a v1.0 tag or source archive while the clean-commit, strict validator, GitHub-hosted
CI, or archive-inspection gates above remain pending. The local runtime revalidation is complete but
must be repeated if code changes after the release commit. Do not publish a prebuilt container image
until its separate third-party notice gate is complete. Historical phase documents record the tests
performed during implementation; this page is the authoritative status for the current public release
candidate.

## Community patch verification (2026-09-01)

The current Community-only working tree additionally passes 147 Python tests, 20 Web tests,
Ruff, mypy, ESLint, TypeScript, the Next.js production build, `validate_public_release.py --allow-dirty`,
and the offline launcher check. The patch adds migration `0010_scan_run_execution_mode`, bounded
server-side proxy Host/Origin/body checks, preserves findings during partial Nuclei timeouts, and
keeps export serialization off the async event loop. Docker fixture E2E, MCP, and Worker restart recovery were re-run on 2026-09-01; browser visual automation remained unavailable and target-network runtime evidence was not attempted. The clean-commit, GitHub CI, and archive-inspection gates remain pending.
