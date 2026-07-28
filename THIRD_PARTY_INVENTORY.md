# Third-party component inventory

This is an engineering inventory for release review, not a substitute for the
license notices required by the chosen project license or by each dependency.

The Docker runtime currently builds or bundles these externally maintained
components:

- ProjectDiscovery releases: Subfinder, dnsx, httpx, Naabu, Nuclei, Katana,
  AlterX, and the version-pinned Nuclei templates;
- PureDNS and MassDNS;
- Nmap and Chromium;
- PostgreSQL and Redis; and
- Python, Node.js, and their declared package dependencies.

Before publishing a release image, maintainers must verify the applicable
licenses, preserve required notices, review template and data licenses, and
record the final source/version inventory in the release notes. Do not assume
that a dependency's presence in a package manager or Docker image grants
redistribution rights without that review.
