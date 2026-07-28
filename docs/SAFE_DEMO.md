# Safe demonstrations and workshops

ScopeGraph demonstrations must be reproducible without collecting data from
third-party systems.

## Recommended demonstration path

1. Start ScopeGraph locally with the default loopback-only Docker Compose
   configuration.
2. Use the explicit offline `fixture` mode in Enterprise Discovery.
3. Explain that fixture records are synthetic test evidence, not real assets or
   findings.
4. Walk through Scope confirmation, progress updates, asset views, review, and
   export using only fixture data.

## When testing active collection

Only use a domain, address range, or local lab you own or are explicitly
authorized to assess. Record the authorization separately from the public
repository. Keep test scope narrow, avoid production-impacting traffic, and do
not publish the resulting raw output, screenshots, endpoint lists, or IP data.

## What must never enter the public repository

- real target names, domains, IP addresses, or asset inventories;
- credentials, proxy authentication, API keys, or `.env` files;
- customer data, browser captures, raw response bodies, or unredacted logs;
- scan screenshots or reports from a third-party target; and
- claims that an unverified tool signal proves a vulnerability.
