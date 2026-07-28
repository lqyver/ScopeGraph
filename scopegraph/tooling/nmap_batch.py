"""Internal exact-target Nmap batch runner used by the closed Nmap adapter."""

import subprocess
import sys
import xml.etree.ElementTree as ET

from pydantic import ValidationError

from scopegraph.tooling.adapters.nmap import NmapInput, nmap_command

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_XML_BYTES_PER_TARGET = 100 * 1024 * 1024


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        print("Nmap batch input exceeds safety limit", file=sys.stderr)
        return 2
    try:
        payload = NmapInput.model_validate_json(raw)
    except ValidationError as exc:
        print(f"Nmap batch input is invalid: {exc}", file=sys.stderr)
        return 2

    batch = ET.Element("scopegraph-nmap-batch")
    for target in payload.targets:
        try:
            completed = subprocess.run(  # noqa: S603
                nmap_command(target),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=600,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"Nmap execution failed for {target.ip}: {exc}", file=sys.stderr)
            return 1
        if completed.stderr:
            sys.stderr.buffer.write(completed.stderr)
        if completed.returncode != 0:
            print(
                f"Nmap exited with {completed.returncode} for {target.ip}",
                file=sys.stderr,
            )
            return completed.returncode or 1
        if len(completed.stdout) > MAX_XML_BYTES_PER_TARGET:
            print(f"Nmap XML exceeds safety limit for {target.ip}", file=sys.stderr)
            return 1
        folded = completed.stdout[:4096].upper()
        if b"<!DOCTYPE" in folded or b"<!ENTITY" in folded:
            print(f"Nmap XML declaration rejected for {target.ip}", file=sys.stderr)
            return 1
        try:
            child = ET.fromstring(completed.stdout)  # noqa: S314
        except ET.ParseError as exc:
            print(f"Nmap returned invalid XML for {target.ip}: {exc}", file=sys.stderr)
            return 1
        if child.tag != "nmaprun":
            print(f"Nmap returned an unexpected XML root for {target.ip}", file=sys.stderr)
            return 1
        batch.append(child)
    sys.stdout.buffer.write(ET.tostring(batch, encoding="utf-8", xml_declaration=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
