#!/usr/bin/env python3
"""
Python script to generate documentation in stdlib.md
"""

import glob
import os
import sys
import re
from typing import Optional

class Helper:
    name: str = ""
    variants: list[str] = []
    deprecated_variants: list[str] = []
    description: str = ""

    def __init__(self):
        self.variants = []
        self.deprecated_variants = []

def parse_variant_string(line: str) -> Optional[str]:
    pattern = r':variant\s+(.+)'

    match = re.match(pattern, line.strip())
    if match:
        return match.group(1).strip()

    return None

def parse_deprecated_variant_string(line: str) -> Optional[str]:
    pattern = r':deprecated_variant\s+(.+)'

    match = re.match(pattern, line.strip())
    if match:
        return match.group(1).strip()

    return None

def variant_has_no_args(variant: str) -> bool:
    return "()" in variant

def parse_function_name_string(line: str) -> Optional[str]:
    pattern = r':function\s+(.+)'

    match = re.match(pattern, line.strip())
    if match:
        return match.group(1).strip()

    return None

def parse_macro_name(line: str) -> Optional[str]:
    # Pattern to match "macro name("
    pattern = r'macro\s+([^(]+)\('

    match = re.match(pattern, line.strip())
    if match:
        return match.group(1).strip()

    return None

def read_file_lines(file_path: str) -> Optional[list[Helper]]:
    helpers: list[Helper] = []
    try:
        if not os.path.exists(file_path):
            print(f"Error: File '{file_path}' not found.")
            return None

        current = Helper()
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                line_content = line.lstrip().rstrip()
                if line_content.startswith("//"):
                    # Don't strip, because we may have markdown with meaningful
                    # whitespace at the beginning of the line that we preserve.
                    line_content = line_content[2:]
                    if len(line_content) > 0 and line_content[:1].isspace():
                        line_content = line_content[1:]
                    if line_content.startswith(":variant"):
                        parsed_variant = parse_variant_string(line_content)
                        if parsed_variant:
                            current.variants.append(parsed_variant)
                            if variant_has_no_args(parsed_variant):
                                current.variants.append(parsed_variant.replace("()", ""))
                    elif line_content.startswith(":deprecated_variant"):
                        parsed_variant = parse_deprecated_variant_string(line_content)
                        if parsed_variant:
                            current.deprecated_variants.append(parsed_variant)

                    elif line_content.startswith(":function"):
                        parsed_function_name = parse_function_name_string(line_content)
                        if parsed_function_name:
                            current.name = parsed_function_name
                    elif line_content or current.description:
                        current.description += line_content + "\n"
                elif line_content.startswith("macro"):
                    parsed_name = parse_macro_name(line_content)
                    if parsed_name:
                        current.name = parsed_name
                        # There must at least be a description or it's an
                        # undocumented macro.
                        if current.description:
                            helpers.append(current)
                        else:
                            print(f"Warning: Helper '{current.name}' will not be added to the docs.")
                    current = Helper()
                else:
                    if current.name and current.description:
                        helpers.append(current)
                    current = Helper()

        if current.name and current.description:
            helpers.append(current)

        return helpers

    except PermissionError:
        print(f"Error: Permission denied to read '{file_path}'.")
        return None
    except UnicodeDecodeError:
        print(f"Error: Unable to decode '{file_path}' as UTF-8.")
        return None
    except Exception as e:
        print(f"Error reading file '{file_path}': {e}")
        return None

def write_markdown_doc(helpers: list[Helper]):
    print("Writing markdown file to docs/stdlib.md")

    current_lines = []
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
    for cleaned_line in cleaned_lines:
        line = cleaned_line.strip()
        if line == "## Helpers":
            updated_lines.append(cleaned_line)
            updated_lines.append("\n")

            for helper in helpers:
                updated_lines.append(f"### {helper.name}\n")
                for variant in helper.variants:
                    updated_lines.append(f"- `{variant}`\n")
                for variant in helper.deprecated_variants:
                    updated_lines.append(f"- deprecated `{variant}`\n")
                updated_lines.append("\n")
                updated_lines.append(f"{helper.description}\n")
                updated_lines.append("\n")
        else:
            updated_lines.append(cleaned_line)

    with open("docs/stdlib.md", "w", encoding="utf-8") as file:
        file.writelines(updated_lines)

def main():
    stdlib_files = glob.glob("src/stdlib/**/*.bt", recursive=True)

    if len(stdlib_files) == 0:
        print("Didn't find any stdlib files")
        sys.exit(1)
    else:
        print(f"All stdlib files: {stdlib_files}")

    all_helpers: list[Helper] = []
    for file in stdlib_files:
        helpers = read_file_lines(file)
        if helpers:
            all_helpers += helpers

    if len(all_helpers) > 0:
        sorted_by_name = sorted(all_helpers, key=lambda h: h.name)
        write_markdown_doc(sorted_by_name)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
