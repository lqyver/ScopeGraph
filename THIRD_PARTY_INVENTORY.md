# Third-party component inventory

This is an engineering inventory for release review, not a substitute for the
license notices required by the chosen project license or by each dependency.

The Docker build currently fetches, builds, or runs these externally maintained
components. Versions below are taken directly from the current Dockerfiles and
Compose file; they are not a completed legal conclusion.

| Component | Current reference | How it enters the runtime |
|---|---|---|
| Subfinder | `2.14.0` | ProjectDiscovery release archive plus upstream checksum file |
| dnsx | `1.2.3` | ProjectDiscovery release archive plus upstream checksum file |
| httpx | `1.9.0` | ProjectDiscovery release archive plus upstream checksum file |
| Naabu | `2.6.1` | ProjectDiscovery release archive plus upstream checksum file |
| Nuclei | `3.8.0` | ProjectDiscovery release archive plus upstream checksum file |
| Katana | `1.6.1` | ProjectDiscovery release archive plus upstream checksum file |
| AlterX | `0.1.0` | ProjectDiscovery release archive plus upstream checksum file |
| Nuclei templates | `10.4.4` | Versioned upstream source archive copied into the image |
| PureDNS | `2.1.1` | Built with Go from the versioned module source |
| MassDNS | commit `6bfa47197d78e68b79041d494e280174cb2d6ae1` | Built from the pinned source commit |
| Nmap | Debian Bookworm package | Installed into the Python runtime image |
| Chromium and Noto CJK fonts | Debian Bookworm packages | Installed for bounded screenshots and rendering |
| PostgreSQL | `17-alpine` image tag | Local Compose database service |
| Redis | `7-alpine` image tag | Local Compose queue service |
| Python runtime | `3.12-slim-bookworm` image tag | API, worker, CLI, and MCP base image |
| Node.js runtime | `22-alpine` image tag | Web build and runtime base image |

Python packages are declared in `pyproject.toml`; verified direct and critical
transitive versions are recorded in `constraints/python312.txt`. JavaScript
packages are locked by `apps/web/package-lock.json`.

Before publishing a release image, maintainers must verify the applicable
licenses, preserve required notices, review template and data licenses, and
record the final source/version inventory in the release notes. Do not assume
that a dependency's presence in a package manager or Docker image grants
redistribution rights without that review.

The current base-image tags and Debian package versions are not digest/snapshot
pinned. A source-only release archive does not contain those downloaded binaries.
Before publishing a prebuilt image, record immutable image digests, generate an
SBOM from the final image, review each applicable license and template/data term,
and produce any required `NOTICE` or attribution bundle.
