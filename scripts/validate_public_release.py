from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = (
    ".gitattributes",
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/dependabot.yml",
    ".github/pull_request_template.md",
    ".github/workflows/ci.yml",
    "LICENSE",
    "README.md",
    "README.zh-CN.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "constraints/README.md",
    "constraints/python312.txt",
    "SECURITY.md",
    "SUPPORT.md",
    "THIRD_PARTY_INVENTORY.md",
    "docs/CAMPUS_DEMO.md",
    "docs/PUBLIC_RELEASE_READINESS.md",
    "docs/RELEASE_PROCESS.md",
)

INTERNAL_MARKER_PATTERNS = (
    re.compile("scopegraph-" + "internal", re.IGNORECASE),
    re.compile(re.escape("d:" + "\\1safe"), re.IGNORECASE),
    re.compile(r"\b" + "byd" + r"\b", re.IGNORECASE),
)

SECRET_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{30,}"),
    re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    re.compile(r"https?://[^\s/:@]+:[^\s/@]+@"),
)

ALLOWED_CREDENTIAL_FIXTURE_PATHS = {
    "tests/integration/phase7_smoke.py",
    "tests/unit/test_normalizers.py",
    "tests/unit/test_phase7.py",
}

BINARY_SUFFIXES = {".ico", ".jpeg", ".jpg", ".png", ".webp", ".xlsx", ".zip"}


def run_git(*args: str) -> subprocess.CompletedProcess[str]:
    git = shutil.which("git")
    if git is None:
        return subprocess.CompletedProcess(
            args=["git", *args], returncode=127, stdout="", stderr="git was not found"
        )
    return subprocess.run(  # noqa: S603 - executable is resolved locally; arguments are constants.
        [git, *args],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


def candidate_paths() -> tuple[list[str], str | None]:
    result = run_git("ls-files", "--cached", "--others", "--exclude-standard")
    if result.returncode != 0:
        return [], result.stderr.strip() or "git ls-files failed"
    return sorted({line.strip() for line in result.stdout.splitlines() if line.strip()}), None


def prohibited_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    parts = normalized.split("/")
    if normalized == "data/system/.gitkeep":
        return False
    if any(part in {"artifacts", "dist", "exports", "screenshots"} for part in parts):
        return True
    if normalized == ".env" or normalized.endswith((".db", ".sqlite", ".zip")):
        return True
    return normalized.startswith("data/system/")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the ScopeGraph Community Edition release boundary offline."
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help=(
            "Allow a dirty working tree while developing; final release validation must omit "
            "this flag."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()

    checks: list[dict[str, object]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "ok": ok, "detail": detail})

    paths, path_error = candidate_paths()
    record("git_file_inventory", path_error is None, path_error or f"{len(paths)} candidate files")

    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    missing_detail = "missing: " + ", ".join(missing) if missing else "ok"
    record("required_public_files", not missing, missing_detail)

    status = run_git("status", "--porcelain", "--untracked-files=all")
    dirty_lines = [line for line in status.stdout.splitlines() if line.strip()]
    clean_ok = status.returncode == 0 and (args.allow_dirty or not dirty_lines)
    if status.returncode != 0:
        clean_detail = status.stderr.strip() or "git status failed"
    elif dirty_lines and args.allow_dirty:
        clean_detail = f"development override: {len(dirty_lines)} changed paths"
    elif dirty_lines:
        clean_detail = f"{len(dirty_lines)} changed paths"
    else:
        clean_detail = "clean"
    record("clean_worktree", clean_ok, clean_detail)

    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    compose_expectations = (
        "name: ${SCOPEGRAPH_COMPOSE_PROJECT:-scopegraph-community}",
        "image: ${SCOPEGRAPH_API_IMAGE:-scopegraph-community-api}",
        'SCOPEGRAPH_EDITION: "community"',
        '"127.0.0.1:${SCOPEGRAPH_API_HOST_PORT:-18000}:8000"',
        '"127.0.0.1:${SCOPEGRAPH_MCP_HOST_PORT:-18001}:8001"',
        '"127.0.0.1:${SCOPEGRAPH_WEB_HOST_PORT:-18080}:3000"',
    )
    missing_compose = [value for value in compose_expectations if value not in compose]
    record(
        "community_compose_identity",
        not missing_compose,
        "missing: " + ", ".join(missing_compose) if missing_compose else "ok",
    )

    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    license_ok = (
        "Apache License" in license_text
        and 'license = { text = "Apache-2.0" }' in pyproject
    )
    record("apache_2_license", license_ok, "ok" if license_ok else "license metadata mismatch")

    unwanted_paths = [path for path in paths if prohibited_path(path)]
    record(
        "prohibited_public_paths",
        not unwanted_paths,
        ", ".join(unwanted_paths) if unwanted_paths else "ok",
    )

    marker_findings: list[str] = []
    secret_findings: list[str] = []
    for path in paths:
        file_path = ROOT / path
        if not file_path.is_file() or file_path.suffix.lower() in BINARY_SUFFIXES:
            continue
        content = file_path.read_text(encoding="utf-8", errors="replace")
        normalized_path = path.replace("\\", "/")
        if normalized_path != "scripts/validate_public_release.py":
            for pattern in INTERNAL_MARKER_PATTERNS:
                if pattern.search(content):
                    marker_findings.append(f"{path}: internal marker")
        for pattern in SECRET_PATTERNS:
            if (
                pattern.search(content)
                and normalized_path not in ALLOWED_CREDENTIAL_FIXTURE_PATHS
            ):
                secret_findings.append(f"{path}: {pattern.pattern}")

    record(
        "internal_markers",
        not marker_findings,
        ", ".join(sorted(set(marker_findings))) if marker_findings else "ok",
    )
    record(
        "credential_shapes",
        not secret_findings,
        ", ".join(sorted(set(secret_findings))) if secret_findings else "ok",
    )

    gitmodules_present = ".gitmodules" in paths
    record(
        "no_nested_repository_config",
        not gitmodules_present,
        ".gitmodules is present" if gitmodules_present else "ok",
    )

    ok = all(bool(check["ok"]) for check in checks)
    payload = {"ok": ok, "edition": "community", "offline": True, "checks": checks}
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for check in checks:
            state = "PASS" if check["ok"] else "FAIL"
            print(f"[{state}] {check['name']}: {check['detail']}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
