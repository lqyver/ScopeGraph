# Community Edition release process

Public release archives must be produced from a clean commit in this repository. Do not copy or
zip the parent working directory: the parent is the separate proprietary Internal Edition and may
contain internal-only source, artifacts, data, or configuration.

The Community Edition and Internal Edition are separate repositories with separate histories. Do
not merge the Internal Edition branch or its commits into this repository, and do not use an
Internal Edition `dist/` artifact as a source for a public commit. Changes intended for the public
edition must be reviewed here against the public boundary validator.

## Pre-release checks

1. Confirm this checkout reports the public remote and the expected release commit:

   ```powershell
   git remote -v
   git status --short
   git rev-parse HEAD
   ```

2. Require a clean working tree and run the public boundary validator without a dirty-tree override:

   ```powershell
   python scripts/validate_public_release.py
   ```

   Then run the source, Web, Compose, fixture E2E, UI, and MCP gates listed in
   `docs/PUBLIC_RELEASE_READINESS.md`.
   Install Python checks with `constraints/python312.txt`, run `pip check`, and treat
   warnings-as-errors at least once before the release decision.
3. Confirm `LICENSE` is Apache-2.0 and that `SECURITY.md`, `CONTRIBUTING.md`, and the English-first
   `README.md` are present.
4. Search tracked files for internal-only edition names, private artifact paths, credentials, real
   targets, and generated scan output. Resolve every match before continuing.

## Build the archive

Create the archive from Git's tracked tree so ignored files such as `.env`, `node_modules`, caches,
screenshots, exports, and nested repositories cannot be included accidentally:

```powershell
git archive --format=zip --prefix=scopegraph-community-v1.0.0/ `
  --output=scopegraph-community-v1.0.0-source.zip HEAD
Get-FileHash -Algorithm SHA256 .\scopegraph-community-v1.0.0-source.zip
```

Extract the archive into a temporary directory and repeat the marker and credential checks against
the extracted files. Publish only after the checksum and the exact source commit have been recorded.

The Internal Edition archive under the parent repository's `dist/` directory is not a public
release input and must never be attached to a Community Edition release.

## Prebuilt container images

A source release and a prebuilt container release have different redistribution boundaries.
Do not publish an image merely because the source archive passed. Complete the version, digest,
SBOM, license, template/data-term, and notice review recorded in
`THIRD_PARTY_INVENTORY.md`, then repeat the runtime gates against that exact image digest.
