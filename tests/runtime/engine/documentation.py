"""Extract bpftrace documentation examples for the runtime test engine."""

from dataclasses import dataclass
from pathlib import Path
import re


@dataclass(frozen=True, order=True)
class DocumentationTest:
    path: Path
    line: int
    code: str
    name: str
    flags: frozenset[str] = frozenset()
    suite: str = "stdlib_docs"
    timeout: int = 30


def extract_examples(text, path):
    examples = []
    fence = None
    language = ""
    flags = frozenset()
    marker_line = None
    code = []
    start = 0
    section = "documentation"
    example_counts = {}

    for number, line in enumerate(text.splitlines(keepends=True), 1):
        content = line.rstrip("\r\n")
        if fence is not None:
            closing = re.fullmatch(r" {0,3}(`+|~+)[ \t]*", content)
            if (closing and closing[1][0] == fence[0]
                    and len(closing[1]) >= len(fence)):
                if language == "bpftrace":
                    example_number = example_counts.get(section, 0) + 1
                    example_counts[section] = example_number
                    examples.append(
                        DocumentationTest(path, start, "".join(code),
                                          f"{section}.example_{example_number}",
                                          flags))
                fence = None
                flags = frozenset()
                marker_line = None
            elif language == "bpftrace":
                code.append(line)
            continue

        directive = re.fullmatch(r"\s*<!--\s*doctest:\s*(.*?)\s*-->\s*", content)
        if directive:
            if marker_line is not None:
                raise ValueError(f"{path}:{number}: duplicate doctest marker")
            flags = frozenset(flag.strip() for flag in directive[1].split(','))
            for flag in sorted(flags):
                if flag not in ("expect-fail", "skip", "unsafe"):
                    raise ValueError(
                        f"{path}:{number}: unknown doctest flag: {flag!r}")
            marker_line = number
            continue

        opening = re.fullmatch(r" {0,3}(`{3,}|~{3,})([^\r\n]*)", content)
        if opening:
            fence = opening[1]
            info = opening[2].split()
            language = info[0] if info else ""
            if marker_line is not None and language != "bpftrace":
                raise ValueError(
                    f"{path}:{marker_line}: doctest marker must precede a bpftrace block")
            start = number + 1
            code = []
        elif marker_line is not None and content.strip():
            raise ValueError(
                f"{path}:{marker_line}: doctest marker must precede a bpftrace block")
        else:
            heading = re.fullmatch(
                r" {0,3}#{1,3}[ \t]+(.+?)(?:[ \t]+#+)?[ \t]*", content)
            if heading:
                section = re.sub(r"[^a-zA-Z0-9_]+", "_", heading[1])
                section = section.strip("_").lower()

    if fence is not None:
        raise ValueError(f"{path}:{start - 1}: unterminated code block")
    if marker_line is not None:
        raise ValueError(f"{path}:{marker_line}: doctest marker has no code block")
    return examples

