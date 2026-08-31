#!/usr/bin/env python3
from pathlib import Path

TARGET = Path(__file__).parent / "src" / "lib.rs"
text = TARGET.read_text()

# Repair the known draft admission-shape defect: the schema has exactly 15 columns.
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

# A recovery-required open must not chmod or change persistent SQLite profile before the stale
# lifecycle has been classified. Existing leaves are verified without mutation. Newly created
# leaves are tightened after creation. Exclusive ownership is acquired before marker
# classification, and the unclean marker is durably created before mutable DB configuration.
old_open = '''        if database_path.exists() {
            verify_private_regular_leaf(&database_path, expected_uid)?;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&database_path, flags)?;
        set_private_file_mode(&database_path)?;
        verify_private_regular_leaf(&database_path, expected_uid)?;
        configure_connection(&connection)?;
        acquire_exclusive_process_lock(&connection)?;
'''
new_open = '''        let database_existed = database_path.exists();
        if database_existed {
            verify_private_regular_leaf(&database_path, expected_uid)?;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&database_path, flags)?;
        if !database_existed {
            set_private_file_mode(&database_path)?;
        }
        verify_private_regular_leaf(&database_path, expected_uid)?;
        acquire_exclusive_process_lock(&connection)?;
'''

if old_open in text:
    if text.count(old_open) != 1:
        raise SystemExit("expected exactly one pre-marker sqlite configuration block")
    text = text.replace(old_open, new_open)
elif new_open not in text:
    raise SystemExit("neither expected sqlite open ordering found")

old_marker = '''        if marker_existed {
            verify_unclean_marker(&marker_path, expected_uid)?;
        } else {
            create_unclean_marker(&marker_path, expected_uid)?;
        }

        let mut store = Self {
'''
new_marker = '''        if marker_existed {
            verify_unclean_marker(&marker_path, expected_uid)?;
        } else {
            create_unclean_marker(&marker_path, expected_uid)?;
            configure_connection(&connection)?;
        }

        let mut store = Self {
'''

if old_marker in text:
    if text.count(old_marker) != 1:
        raise SystemExit("expected exactly one marker classification block")
    text = text.replace(old_marker, new_marker)
elif new_marker not in text:
    raise SystemExit("neither expected marker/configuration ordering found")

if "?15, ?16)" in text:
    raise SystemExit("16-placeholder admission INSERT still present")
if "reserved compatibility field keeps explicit column count stable in this draft" in text:
    raise SystemExit("obsolete compatibility field still present")

# Guard against regression to profile mutation before marker classification.
open_pos = text.index("let connection = Connection::open_with_flags")
marker_pos = text.index("let marker_path = marker_path")
config_pos = text.index("configure_connection(&connection)?")
if not (open_pos < marker_pos < config_pos):
    raise SystemExit("mutable sqlite configuration must occur after marker classification")

TARGET.write_text(text)
print("sqlite-v2-pre-pr-repair: OK")
