#!/usr/bin/env python3
"""Resolve the npm version for @krypticdev/encryption.

Patch (third number) auto-increments from the latest npm release when
the incoming package.json version keeps the same major and minor.

If this commit already changed major or minor (1.1.0, 2.0.0, …), that version
is published as-is. The first publish (package not on npm yet) also
keeps the incoming version.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

PACKAGE_ID = "@krypticdev/encryption"
REGISTRY_URL = f"https://registry.npmjs.org/{PACKAGE_ID}"
PACKAGE_JSON = Path("package.json")
STABLE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def parse(version: str) -> tuple[int, int, int] | None:
    match = STABLE.match(version.strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def read_package_version() -> str:
    payload = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    version = payload.get("version")
    if not version:
        raise SystemExit(f"No version found in {PACKAGE_JSON}")
    return str(version).strip()


def latest_published() -> tuple[int, int, int] | None:
    try:
        with urllib.request.urlopen(REGISTRY_URL) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise
    latest = payload.get("dist-tags", {}).get("latest")
    return parse(latest) if latest else None


def render(version: tuple[int, int, int]) -> str:
    return f"{version[0]}.{version[1]}.{version[2]}"


def main() -> None:
    incoming_raw = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1] else read_package_version()
    incoming = parse(incoming_raw)
    if incoming is None:
        raise SystemExit(f"Incoming version must be major.minor.patch, got: {incoming_raw}")

    published = latest_published()
    if published is None:
        resolved = incoming
        reason = "first publish, keep incoming version"
    elif incoming[0] != published[0] or incoming[1] != published[1]:
        resolved = incoming
        reason = "major or minor changed, keep incoming version"
    else:
        resolved = (published[0], published[1], published[2] + 1)
        reason = "same major.minor, bump patch"

    print(f"incoming={render(incoming)}", file=sys.stderr)
    print(
        f"published={render(published) if published else '(none)'}",
        file=sys.stderr,
    )
    print(f"reason={reason}", file=sys.stderr)
    print(render(resolved))


if __name__ == "__main__":
    main()
