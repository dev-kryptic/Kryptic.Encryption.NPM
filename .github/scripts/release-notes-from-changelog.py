#!/usr/bin/env python3
"""Extract the CHANGELOG.md section for VERSION into NOTES_FILE."""

from __future__ import annotations

import os
import pathlib
import re
import sys


def main() -> None:
    version = os.environ["VERSION"]
    notes_file = pathlib.Path(os.environ["NOTES_FILE"])
    changelog = pathlib.Path("CHANGELOG.md")

    if not changelog.is_file():
        sys.exit("CHANGELOG.md not found")

    lines = changelog.read_text(encoding="utf-8").splitlines()
    pattern = re.compile(rf"^## \[?{re.escape(version)}\]?(?:\s|$|-)")
    start = next((i for i, line in enumerate(lines) if pattern.match(line)), None)
    if start is None:
        sys.exit(f"CHANGELOG.md has no ## {version} section")

    end = next(
        (j for j in range(start + 1, len(lines)) if lines[j].startswith("## ")),
        len(lines),
    )
    body = "\n".join(lines[start:end]).strip() + "\n"
    notes_file.write_text(body, encoding="utf-8")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"file={notes_file}\n")

    print(body)


if __name__ == "__main__":
    main()
