#!/usr/bin/env python3
"""
Generate docs/stdlib.md using `bpftrace doc`.
"""

import glob
import os
import pathlib
import subprocess
import sys


def generate_helpers_markdown(stdlib_files: list[str]) -> str:
    bpftrace = os.environ.get("BPFTRACE", "build/src/bpftrace")
    if not pathlib.Path(bpftrace).exists():
        print(
            f"Error: bpftrace executable '{bpftrace}' not found. "
            "Build bpftrace first or set BPFTRACE.",
            file=sys.stderr,
        )
        sys.exit(1)

    result = subprocess.run(
        [bpftrace, "doc", *stdlib_files],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        if result.stderr:
            print(result.stderr, file=sys.stderr, end="")
        if result.stdout:
            print(result.stdout, file=sys.stderr, end="")
        sys.exit(result.returncode)

    return result.stdout


def write_markdown_doc(helpers_markdown: str):
    print("Writing markdown file to docs/stdlib.md")

    with open("docs/stdlib.md", "r", encoding="utf-8") as file:
        current_lines = file.readlines()

    in_helpers_section = False
    cleaned_lines = []
    for raw_line in current_lines:
        line = raw_line.strip()
        if line == "## Helpers":
            in_helpers_section = True
        elif line == "## Map Value Functions":
            in_helpers_section = False
        elif in_helpers_section:
            continue

        cleaned_lines.append(raw_line)

    updated_lines = []
    inserted = False
    for cleaned_line in cleaned_lines:
        updated_lines.append(cleaned_line)
        if cleaned_line.strip() == "## Helpers":
            updated_lines.append("\n")
            if helpers_markdown:
                updated_lines.append(helpers_markdown)
                if not helpers_markdown.endswith("\n"):
                    updated_lines.append("\n")
            inserted = True

    if not inserted:
        print("Error: Could not find the Helpers section in docs/stdlib.md", file=sys.stderr)
        sys.exit(1)

    with open("docs/stdlib.md", "w", encoding="utf-8") as file:
        file.writelines(updated_lines)


def main():
    stdlib_files = sorted(glob.glob("src/stdlib/**/*.bt", recursive=True))
    if len(stdlib_files) == 0:
        print("Didn't find any stdlib files", file=sys.stderr)
        sys.exit(1)

    write_markdown_doc(generate_helpers_markdown(stdlib_files))


if __name__ == "__main__":
    main()
