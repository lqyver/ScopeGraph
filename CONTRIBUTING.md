# Contributing to ScopeGraph

Thank you for improving a responsible, local-first asset-discovery workflow.

## Before opening an Issue or pull request

- Use only synthetic fixtures or assets you own and are explicitly authorized
  to test.
- Never commit `.env` files, credentials, proxy URLs containing credentials,
  customer data, real scan outputs, screenshots of third-party targets, or
  retained runtime data.
- Report security concerns through the private process in
  [SECURITY.md](./SECURITY.md), not through public Issues.

## Development workflow

1. Start from an up-to-date branch and keep each change focused.
2. Add or update fixture-based tests for behaviour changes.
3. Run the checks described in the README: Python linting, type checking,
   tests, and the web lint/typecheck/test/build commands when relevant.
4. Explain user-visible behaviour, safety implications, and documentation
   changes in the pull request.

## ScopeGraph safety invariants

Contributions must preserve these boundaries:

- Scope changes require an explicit human confirmation.
- A discovered candidate is not proof of authorization or ownership.
- Local-only binding remains the default deployment mode.
- MCP remains read-only by default and may not silently approve Scope or expand
  active collection.
- Active collection must remain bounded, attributable, and opt-in.

## Good first contributions

Useful starter work includes improving fixture coverage, accessibility,
documentation, error messages, result presentation, translations, and
operator-safe diagnostics. Please discuss large changes to scan policy,
network behavior, or tool integration in an Issue first.
