# Security policy

## Supported versions

Security fixes are provided for the latest published ScopeGraph release and the
default branch of the public repository. Pre-release snapshots are not a
production service and must remain local-only unless the administrator adds
their own access controls.

## Reporting a vulnerability

Do **not** open a public Issue for a suspected vulnerability, exposed secret,
or unauthorized-access concern.

When this repository is published, use GitHub private vulnerability reporting
from the repository's **Security** tab. If that channel is not available, ask
the maintainer for a private reporting channel without posting technical
details, target information, credentials, or proof-of-concept code publicly.

Please include:

- the affected ScopeGraph version or commit;
- a minimal, synthetic reproduction;
- the security impact and any prerequisites; and
- a safe contact method for follow-up.

## Research boundary

ScopeGraph is intended only for assets that the operator owns or is explicitly
authorized to assess. Do not use reports, Issues, pull requests, or examples
to publish third-party scan data, real credentials, personal data, or
unauthorized test results. Do not test hosted deployments with destructive,
high-volume, or scope-expanding activity.

## Response expectations

Maintainers should acknowledge a private report, assess reproducibility in a
controlled environment, coordinate a fix, and publish a sanitized advisory
after affected users have had a reasonable opportunity to update.
