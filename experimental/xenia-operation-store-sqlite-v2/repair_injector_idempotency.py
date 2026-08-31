#!/usr/bin/env python3
from pathlib import Path

TARGET = Path(__file__).parent / "inject_frontier_semantics.py"
text = TARGET.read_text()
old = '''replace_once(
    "use std::fs::{self, File, OpenOptions};",
    "use std::collections::BTreeMap;\\nuse std::fs::{self, File, OpenOptions};",
    "BTreeMap import",
)
'''
new = '''if "use std::collections::BTreeMap;" not in text:
    replace_once(
        "use std::fs::{self, File, OpenOptions};",
        "use std::collections::BTreeMap;\\nuse std::fs::{self, File, OpenOptions};",
        "BTreeMap import",
    )
'''
if old in text:
    if text.count(old) != 1:
        raise SystemExit("unexpected duplicate BTreeMap import rewrite")
    text = text.replace(old, new)
elif new not in text:
    raise SystemExit("frontier injector import form not recognized")
TARGET.write_text(text)
print("sqlite-v2-injector-idempotency: OK")
