#!/usr/bin/env python3
"""Static checks for the workflow and action files this repository owns.

Checks applied to every file in CHECKED_FILES:
  - third-party `uses:` references are pinned to a full 40-hex commit SHA
  - no `curl ... | sh` style download-and-execute pipelines

Checks applied additionally to files in STRICT_FILES:
  - no `${{ inputs.* }}` or `${{ github.event.* }}` interpolated into `run:` blocks
    (pass them through `env:` and reference shell variables instead)
  - no `|| true` (a failing command must fail the step)

Usage: check-actions.py [repo-root]
Exit codes: 0 all checks pass, 1 violations found.
"""
import pathlib
import re
import sys

CHECKED_FILES = [
    ".github/workflows/dco.yml",
    ".github/workflows/test-framework.yml",
    "actions/osdo-sign/action.yml",
    "actions/osdo-sbom/action.yml",
    "actions/osdo-slsa-provenance/action.yml",
    "actions/osdo-llm-scan/action.yml",
]

STRICT_FILES = [
    "actions/osdo-sign/action.yml",
    "actions/osdo-llm-scan/action.yml",
]

USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)")
SHA_REF_RE = re.compile(r"@[0-9a-f]{40}$")
DOWNLOAD_EXEC_RE = re.compile(r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(sh|bash)\b")
INTERPOLATION_RE = re.compile(r"\$\{\{\s*(inputs\.|github\.event\.)")
OR_TRUE_RE = re.compile(r"\|\|\s*true\b")
RUN_KEY_RE = re.compile(r"^(\s*)(?:-\s+)?run:\s*(.*)$")


def indent_of(line):
    return len(line) - len(line.lstrip(" "))


def run_blocks(lines):
    """Yield (line_number, text) for every line that belongs to a run: block."""
    i = 0
    while i < len(lines):
        match = RUN_KEY_RE.match(lines[i])
        if not match:
            i += 1
            continue
        key_indent = len(match.group(1))
        inline = match.group(2)
        if inline and not inline.startswith("|") and not inline.startswith(">"):
            yield i + 1, inline
        j = i + 1
        while j < len(lines):
            line = lines[j]
            if line.strip() and indent_of(line) <= key_indent:
                break
            yield j + 1, line
            j += 1
        i = j


def check_file(path, rel, strict):
    problems = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        uses = USES_RE.match(line)
        if uses:
            ref = uses.group(1)
            if not ref.startswith(("./", "docker://")) and not SHA_REF_RE.search(ref):
                problems.append(f"{rel}:{number}: third-party action not pinned to a full SHA: {ref}")
    for number, text in run_blocks(lines):
        if DOWNLOAD_EXEC_RE.search(text):
            problems.append(f"{rel}:{number}: download piped straight into a shell")
        if strict:
            if INTERPOLATION_RE.search(text):
                problems.append(f"{rel}:{number}: untrusted context interpolated into run: (use env:)")
            if OR_TRUE_RE.search(text):
                problems.append(f"{rel}:{number}: '|| true' lets a failing command pass the step")
    return problems


def main(argv):
    root = pathlib.Path(argv[1] if len(argv) > 1 else ".").resolve()
    problems = []
    for rel in CHECKED_FILES:
        path = root / rel
        if not path.is_file():
            problems.append(f"{rel}: file not found")
            continue
        problems.extend(check_file(path, rel, rel in STRICT_FILES))
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        print(f"{len(problems)} static check violation(s)")
        return 1
    print(f"static checks passed for {len(CHECKED_FILES)} file(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
