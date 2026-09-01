# Python dependency constraints

`python312.txt` pins ScopeGraph's direct dependencies and the critical transitive
packages that affect its API, queue, MCP, validation, and test boundaries. CI and
the Python Docker image both consume this file.

It is deliberately not described as a complete cross-platform or hash-locked
artifact. Platform-specific wheels, build-system requirements, Debian packages,
and container base images have separate resolution boundaries.

When refreshing the constraints:

1. use a clean CPython 3.12 environment;
2. resolve from the compatible ranges in `pyproject.toml`;
3. record the selected direct and critical transitive versions here;
4. run `pip check`, warnings-as-errors tests, Ruff, mypy, and coverage;
5. rebuild the Community image and repeat fixture E2E, worker recovery, and MCP
   smoke tests; and
6. update `docs/PUBLIC_RELEASE_READINESS.md` with the exact evidence date.

Do not update this file automatically during application startup or a scan.
