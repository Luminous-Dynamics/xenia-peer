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
old_or_else = '''        ).or_else(|error| {
            // The draft schema has exactly 15 columns. Keep a single obvious mapping error rather
            // than silently falling back to a different insert shape.
            Err(error)
        })?;
'''
new_or_else = '''        )?;
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

if old_or_else in text:
    if text.count(old_or_else) != 1:
        raise SystemExit("expected exactly one obsolete admission insert error shim")
    text = text.replace(old_or_else, new_or_else)
elif "Keep a single obvious mapping error" in text:
    raise SystemExit("obsolete admission insert error shim remains in unexpected form")

# Recovery safety: a pre-existing unclean marker means we are opening historical authority,
# never initializing replacement state. Therefore CREATE is forbidden when that marker exists,
# and marker + missing database is an explicit fail-closed condition.
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
mid_open = '''        let database_existed = database_path.exists();
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
new_open = '''        let marker_path = marker_path(&database_path);
        let marker_preexisted = match fs::symlink_metadata(&marker_path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let database_existed = database_path.exists();
        if marker_preexisted && !database_existed {
            return Err(SqliteStoreV2Error::RecoveryDatabaseMissing);
        }
        if database_existed {
            verify_private_regular_leaf(&database_path, expected_uid)?;
        }
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        if !marker_preexisted {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags(&database_path, flags)?;
        if !database_existed {
            set_private_file_mode(&database_path)?;
        }
        verify_private_regular_leaf(&database_path, expected_uid)?;
        acquire_exclusive_process_lock(&connection)?;
'''

if old_open in text:
    if text.count(old_open) != 1:
        raise SystemExit("expected exactly one original sqlite open block")
    text = text.replace(old_open, new_open)
elif mid_open in text:
    if text.count(mid_open) != 1:
        raise SystemExit("expected exactly one intermediate sqlite open block")
    text = text.replace(mid_open, new_open)
elif new_open not in text:
    raise SystemExit("no recognized sqlite open ordering found")

old_marker_original = '''        let marker_path = marker_path(&database_path);
        let marker_existed = marker_path.exists();
        if marker_existed {
            verify_unclean_marker(&marker_path, expected_uid)?;
        } else {
            create_unclean_marker(&marker_path, expected_uid)?;
        }

        let mut store = Self {
'''
old_marker_intermediate = '''        let marker_path = marker_path(&database_path);
        let marker_existed = marker_path.exists();
        if marker_existed {
            verify_unclean_marker(&marker_path, expected_uid)?;
        } else {
            create_unclean_marker(&marker_path, expected_uid)?;
            configure_connection(&connection)?;
        }

        let mut store = Self {
'''
new_marker = '''        let marker_existed = match fs::symlink_metadata(&marker_path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        if marker_existed != marker_preexisted {
            return Err(SqliteStoreV2Error::WriterMarkerChangedDuringOpen);
        }
        if marker_existed {
            verify_unclean_marker(&marker_path, expected_uid)?;
        } else {
            create_unclean_marker(&marker_path, expected_uid)?;
            configure_connection(&connection)?;
        }

        let mut store = Self {
'''

if old_marker_original in text:
    if text.count(old_marker_original) != 1:
        raise SystemExit("expected exactly one original marker block")
    text = text.replace(old_marker_original, new_marker)
elif old_marker_intermediate in text:
    if text.count(old_marker_intermediate) != 1:
        raise SystemExit("expected exactly one intermediate marker block")
    text = text.replace(old_marker_intermediate, new_marker)
elif new_marker not in text:
    raise SystemExit("no recognized marker classification block found")

# Add explicit recovery/open race failures once.
error_anchor = '''    /// Database path has no parent.
    #[error("database path has no parent directory")]
    DatabasePathHasNoParent,
'''
error_replacement = '''    /// Database path has no parent.
    #[error("database path has no parent directory")]
    DatabasePathHasNoParent,
    /// An unclean-writer marker exists but the durable database is missing.
    #[error("recovery-required SQLite V2 database is missing")]
    RecoveryDatabaseMissing,
    /// Writer marker state changed while exclusive ownership was being established.
    #[error("unclean-writer marker changed during SQLite V2 open")]
    WriterMarkerChangedDuringOpen,
'''
if "RecoveryDatabaseMissing," not in text:
    if text.count(error_anchor) != 1:
        raise SystemExit("could not locate database-path error anchor")
    text = text.replace(error_anchor, error_replacement)

if "?15, ?16)" in text:
    raise SystemExit("16-placeholder admission INSERT still present")
if "reserved compatibility field keeps explicit column count stable in this draft" in text:
    raise SystemExit("obsolete compatibility field still present")
if "Keep a single obvious mapping error" in text:
    raise SystemExit("obsolete insert error shim still present")

# Guard against regression: mutable SQLite configuration must be after marker classification,
# and CREATE must be conditional on absence of historical recovery evidence.
open_pos = text.index("let connection = Connection::open_with_flags")
marker_pos = text.index("let marker_existed = match fs::symlink_metadata")
config_pos = text.index("configure_connection(&connection)?")
if not (open_pos < marker_pos < config_pos):
    raise SystemExit("mutable sqlite configuration must occur after marker classification")
if "if !marker_preexisted {\n            flags |= OpenFlags::SQLITE_OPEN_CREATE;" not in text:
    raise SystemExit("SQLite CREATE must be disabled for pre-existing recovery marker")

TARGET.write_text(text)
print("sqlite-v2-pre-pr-repair: OK")
