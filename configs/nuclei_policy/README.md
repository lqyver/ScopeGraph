# Nuclei execution policy

The policy is an allowlist. ScopeGraph never invokes all templates and disables Nuclei's automatic
update check. A template hit is persisted as `UNVERIFIED`; it is not proof of a vulnerability.
