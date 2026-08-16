#!/usr/bin/env python3
"""Source-shape guard for duplicate simple Rust function parameter names.

This is intentionally not a Rust parser and does not replace `cargo check`. It
exists so no-toolchain review runners still catch the high-impact class of typo
where the same named parameter is declared twice in one `fn` signature.
"""
from __future__ import annotations

import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
failures: list[str] = []
fn_re = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^{};]*?>\s*)?\(", re.S)
ident_param_re = re.compile(r"^(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*:")


def matching_paren(text: str, open_index: int) -> int | None:
    depth = 0
    in_string = False
    escape = False
    for i in range(open_index, len(text)):
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return i
    return None


def split_top_level(body: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0, "<": 0}
    closes = {")": "(", "]": "[", "}": "{", ">": "<"}
    in_string = False
    escape = False
    for i, ch in enumerate(body):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in depths:
            depths[ch] += 1
        elif ch in closes:
            opener = closes[ch]
            if depths[opener] > 0:
                depths[opener] -= 1
        elif ch == ',' and all(value == 0 for value in depths.values()):
            parts.append(body[start:i].strip())
            start = i + 1
    parts.append(body[start:].strip())
    return parts

for path in root.rglob("*.rs"):
    if "/target/" in path.as_posix() or "/_archive/" in path.as_posix():
        continue
    text = path.read_text(encoding="utf-8")
    for match in fn_re.finditer(text):
        open_index = text.find("(", match.start(), match.end() + 1)
        if open_index < 0:
            continue
        close_index = matching_paren(text, open_index)
        if close_index is None:
            continue
        names: dict[str, int] = {}
        for parameter in split_top_level(text[open_index + 1 : close_index]):
            parameter = re.sub(r"^#\[[^\]]+\]\s*", "", parameter).strip()
            m = ident_param_re.match(parameter)
            if not m:
                continue
            name = m.group(1)
            names[name] = names.get(name, 0) + 1
        duplicates = sorted(name for name, count in names.items() if count > 1)
        if duplicates:
            line = text.count("\n", 0, match.start()) + 1
            failures.append(
                f"{path.relative_to(root)}:{line}: function {match.group(1)} has duplicate parameter(s): {', '.join(duplicates)}"
            )

if failures:
    print("Rust function-parameter source check FAILED", file=sys.stderr)
    for failure in failures:
        print(f" - {failure}", file=sys.stderr)
    raise SystemExit(1)

print("Rust function-parameter source check passed")
