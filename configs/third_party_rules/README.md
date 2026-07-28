# Third-party CNAME rules

`cname.json` is a versioned, local-only suffix registry. A match annotates the CNAME target as
`CDN_SHARED` or `THIRD_PARTY`; it never approves the target for active scanning. Exact user Scope
and exclusions retain higher priority than this derived classification.
