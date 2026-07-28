# Scan profiles

These version-controlled JSON files are validated by `ScanProfileConfig` before a run is
created. They contain only whitelisted policy fields; adapter command lines are never accepted
from profile input. A resolved copy is stored in every `ScanRun.config_snapshot`.

The `deep` profile is broader but still does not imply a 1-65535 scan. Full-port scanning is a
separate request and requires an explicit second confirmation plus an `OWNED`, in-scope IP.

`nuclei_strategy=automatic` is the default for versioned profiles. Nuclei fingerprints each live
host and selects only templates mapped to the detected technologies. `broad` remains available to
a validated Custom profile, but is never the default because multiplying every live site by the
whole bundled template corpus has unbounded runtime.

IPs resolved from a currently observed, authorized root-domain descendant may receive the safe
web-port policy for that run. This provenance does not mark the IP as owned: CDN/private nodes are
still blocked, unknown/shared nodes remain restricted to safe web ports, and full-port scans still
require explicit IP Scope plus an `OWNED` classification and second confirmation.
