# Integration fixtures

Phase 0 does not call external security tools. Later phases must use recorded JSON/JSONL/XML
fixtures here so CI remains independent of the public internet.

The phase smoke scripts target the Docker-published loopback API and UI. Run them in order
after `docker compose up -d --build`; every active-tool path remains in recorded fixture mode.
