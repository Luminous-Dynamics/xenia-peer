#!/usr/bin/env python3
from pathlib import Path

TARGET = Path(__file__).parent / "src" / "lib.rs"
text = TARGET.read_text()

old_sql = '"INSERT INTO admissions VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)"'
new_sql = '"INSERT INTO admissions VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"'
old_tail = '''                sqlite_i64(persisted_at_unix_ms, "persisted_at_unix_ms")?,
                // reserved compatibility field keeps explicit column count stable in this draft
                &[0u8; 32][..],
'''
new_tail = '''                sqlite_i64(persisted_at_unix_ms, "persisted_at_unix_ms")?,
'''

if old_sql in text:
    if text.count(old_sql) != 1:
        raise SystemExit("expected exactly one 16-placeholder admission INSERT")
    text = text.replace(old_sql, new_sql)
elif new_sql not in text:
    raise SystemExit("neither expected admission INSERT form found")

if old_tail in text:
    if text.count(old_tail) != 1:
        raise SystemExit("expected exactly one obsolete compatibility tail")
    text = text.replace(old_tail, new_tail)
elif "reserved compatibility field keeps explicit column count stable in this draft" in text:
    raise SystemExit("obsolete compatibility field comment remains in unexpected form")

if "?15, ?16)" in text:
    raise SystemExit("16-placeholder admission INSERT still present")
if "reserved compatibility field keeps explicit column count stable in this draft" in text:
    raise SystemExit("obsolete compatibility field still present")

TARGET.write_text(text)
print("sqlite-v2-pre-pr-repair: OK")
