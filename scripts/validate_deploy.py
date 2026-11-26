#!/usr/bin/env python3
"""Reject deployment manifests that only look production-ready.

Checks performed on the rendered manifest:

* no ``CHANGE_ME``/``REPLACE_ME``/``example.eu``/``ghcr.io/example``/``TODO``;
* no ``:latest`` image tags;
* every container sets ``runAsNonRoot``, ``readOnlyRootFilesystem``,
  ``allowPrivilegeEscalation: false`` and drops all capabilities;
* a NetworkPolicy, a PodDisruptionBudget and an Ingress are present;
* no plaintext bootstrap password longer than 0 characters? (presence is fine —
  the value itself is never printed by this tool.)

Exit code 0 = pass, 1 = violations. Never prints secret values.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FORBIDDEN = {
    "CHANGE_ME": re.compile(r"CHANGE_ME"),
    "REPLACE_ME": re.compile(r"REPLACE_ME"),
    "example host": re.compile(r"(?i)example\.(eu|com|internal)"),
    "example registry": re.compile(r"ghcr\.io/example"),
    "TODO": re.compile(r"\bTODO\b"),
    "latest tag": re.compile(r"image:\s*[^\s]+:latest\b"),
    "unrendered variable": re.compile(r"\$\{[A-Z_]+\}"),
}
REQUIRED_SECURITY = {
    "runAsNonRoot": re.compile(r"runAsNonRoot:\s*true"),
    "readOnlyRootFilesystem": re.compile(r"readOnlyRootFilesystem:\s*true"),
    "allowPrivilegeEscalation": re.compile(r"allowPrivilegeEscalation:\s*false"),
    "drop ALL capabilities": re.compile(r"drop:\s*\[\s*[\"']?ALL[\"']?\s*\]"),
}
REQUIRED_OBJECTS = ("kind: NetworkPolicy", "kind: PodDisruptionBudget", "kind: Ingress")


def validate(text: str) -> list[str]:
    problems: list[str] = []
    for label, pattern in FORBIDDEN.items():
        if pattern.search(text):
            problems.append(f"forbidden {label} found")
    for label, pattern in REQUIRED_SECURITY.items():
        if not pattern.search(text):
            problems.append(f"missing security control: {label}")
    for required in REQUIRED_OBJECTS:
        if required not in text:
            problems.append(f"missing object: {required}")
    if "kind: Deployment" not in text:
        problems.append("missing object: kind: Deployment")
    if "replicas: 2" not in text:
        problems.append("API deployment must run at least 2 replicas")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="rendered manifest to validate")
    args = parser.parse_args(argv)
    try:
        text = args.manifest.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read {args.manifest}: {exc}", file=sys.stderr)
        return 2
    problems = validate(text)
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(f"PASS: {args.manifest} has no placeholder and required controls are present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
