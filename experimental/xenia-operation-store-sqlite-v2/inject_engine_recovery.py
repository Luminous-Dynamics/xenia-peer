#!/usr/bin/env python3
from pathlib import Path

TARGET = Path(__file__).parent / "src" / "lib.rs"
text = TARGET.read_text()


def replace_once(old: str, new: str, label: str) -> None:
    global text
    if old in text:
        if text.count(old) != 1:
            raise SystemExit(f"{label}: expected one old form, found {text.count(old)}")
        text = text.replace(old, new)
    elif new not in text:
        raise SystemExit(f"{label}: neither old nor new form found")


# Freeze the exact post-2026-06-24 SQLite source lineage qualified by ADR-021.
constant_anchor = '''pub const SQLITE_STORE_SCHEMA_VERSION_V2: i64 = 2;
/// Fail-stop writer marker suffix.'''
constant_new = '''pub const SQLITE_STORE_SCHEMA_VERSION_V2: i64 = 2;
/// Exact bundled SQLite release qualified for rollback-journal recovery.
pub const QUALIFIED_SQLITE_VERSION_V2: &str = "3.53.4";
/// Exact bundled SQLite source id qualified for rollback-journal recovery.
pub const QUALIFIED_SQLITE_SOURCE_ID_V2: &str = "2026-07-24 19:02:57 bf7c7f30031888f4e796e429ab3978879485813aaca6f641c7b33e4e09459bcc";
/// Fail-stop writer marker suffix.'''
if "pub const QUALIFIED_SQLITE_VERSION_V2" not in text:
    replace_once(constant_anchor, constant_new, "qualified SQLite constants")

# repair_pre_pr.py first creates a strict READ_ONLY recovery branch. Replace it with ADR-021's
# two-phase engine-recovery -> read-only inspection connection.
old_open = '''        let flags = if marker_preexisted {
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
        };
        let connection = Connection::open_with_flags(&database_path, flags)?;
        connection.busy_timeout(Duration::from_millis(0))?;

        if !marker_preexisted {
            if !database_existed {
                set_private_file_mode(&database_path)?;
            }
            verify_private_regular_leaf(&database_path, expected_uid)?;
            acquire_exclusive_process_lock(&connection)?;
            let marker_now_exists = match fs::symlink_metadata(&marker_path) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
            if marker_now_exists {
                return Err(SqliteStoreV2Error::WriterMarkerChangedDuringOpen);
            }
            create_unclean_marker(&marker_path, expected_uid)?;
            configure_connection(&connection)?;
        }
        let marker_existed = marker_preexisted;'''
new_open = '''        let connection = if marker_preexisted {
            run_sqlite_engine_recovery(&database_path, expected_uid)?;
            let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW;
            let connection = Connection::open_with_flags(&database_path, flags)?;
            connection.busy_timeout(Duration::from_millis(0))?;
            verify_sqlite_source_profile(&connection)?;
            connection
        } else {
            let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW;
            let connection = Connection::open_with_flags(&database_path, flags)?;
            connection.busy_timeout(Duration::from_millis(0))?;
            verify_sqlite_source_profile(&connection)?;
            if !database_existed {
                set_private_file_mode(&database_path)?;
            }
            verify_private_regular_leaf(&database_path, expected_uid)?;
            acquire_exclusive_process_lock(&connection)?;
            let marker_now_exists = match fs::symlink_metadata(&marker_path) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
            if marker_now_exists {
                return Err(SqliteStoreV2Error::WriterMarkerChangedDuringOpen);
            }
            create_unclean_marker(&marker_path, expected_uid)?;
            configure_connection(&connection)?;
            connection
        };
        let marker_existed = marker_preexisted;'''
replace_once(old_open, new_open, "ADR-021 two-phase recovery open")

# Insert journal/source/recovery helpers before marker_path().
if "fn run_sqlite_engine_recovery(" not in text:
    anchor = '''fn marker_path(database_path: &Path) -> PathBuf {'''
    helpers = '''fn verify_sqlite_source_profile(connection: &Connection) -> Result<(), SqliteStoreV2Error> {
    let version: String = connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let source_id: String = connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    if version != QUALIFIED_SQLITE_VERSION_V2 || source_id != QUALIFIED_SQLITE_SOURCE_ID_V2 {
        return Err(SqliteStoreV2Error::SQLiteSourceProfileMismatch { version, source_id });
    }
    Ok(())
}

fn rollback_journal_path(database_path: &Path) -> PathBuf {
    let mut value = database_path.as_os_str().to_os_string();
    value.push("-journal");
    PathBuf::from(value)
}

fn verify_recovery_journal_if_present(
    database_path: &Path,
    expected_uid: u32,
) -> Result<(), SqliteStoreV2Error> {
    let journal = rollback_journal_path(database_path);
    match fs::symlink_metadata(&journal) {
        Ok(_) => verify_private_regular_leaf(&journal, expected_uid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn run_sqlite_engine_recovery(
    database_path: &Path,
    expected_uid: u32,
) -> Result<(), SqliteStoreV2Error> {
    // The main database and unclean marker were already verified by open(). The journal is
    // SQLite-owned crash state, but its filesystem leaf must still satisfy the authority-root
    // trust profile before the pager is allowed to consume it.
    verify_recovery_journal_if_present(database_path, expected_uid)?;

    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(database_path, flags)
        .map_err(SqliteStoreV2Error::EngineRecoveryFailed)?;
    connection
        .busy_timeout(Duration::from_millis(0))
        .map_err(SqliteStoreV2Error::EngineRecoveryFailed)?;
    verify_sqlite_source_profile(&connection)?;

    // A schema read forces SQLite to establish a readable pager state. If the sibling rollback
    // journal is hot, the qualified SQLite pager performs its normal rollback before this read is
    // allowed to succeed. No Xenia schema/user-data mutation is issued here.
    let _: i64 = connection
        .query_row("PRAGMA schema_version", [], |row| row.get(0))
        .map_err(SqliteStoreV2Error::EngineRecoveryFailed)?;

    connection
        .close()
        .map_err(|(_connection, error)| SqliteStoreV2Error::EngineRecoveryFailed(error))?;

    // Engine recovery may legitimately rewrite DB pages and delete/neutralize the journal. What
    // it may not do is turn an unexpected filesystem object into trusted authority state.
    verify_private_regular_leaf(database_path, expected_uid)?;
    verify_recovery_journal_if_present(database_path, expected_uid)
}

fn marker_path(database_path: &Path) -> PathBuf {'''
    if anchor not in text:
        raise SystemExit("engine recovery helper insertion anchor missing")
    text = text.replace(anchor, helpers, 1)

# Add distinct recovery/source failures. Check for the actual enum declaration, not helper uses.
if "SQLiteSourceProfileMismatch { version: String, source_id: String }," not in text:
    error_anchor = '''    /// SQLite journal profile mismatch.
    #[error("SQLite journal mode mismatch: {0}")]
    JournalModeMismatch(String),'''
    error_new = '''    /// Qualified SQLite library source does not match ADR-021.
    #[error("qualified SQLite source mismatch: version={version}, source_id={source_id}")]
    SQLiteSourceProfileMismatch { version: String, source_id: String },
    /// SQLite could not canonicalize an interrupted rollback-journal transaction.
    #[error("SQLite engine crash recovery failed: {0}")]
    EngineRecoveryFailed(#[source] rusqlite::Error),
    /// SQLite journal profile mismatch.
    #[error("SQLite journal mode mismatch: {0}")]
    JournalModeMismatch(String),'''
    if error_anchor not in text:
        raise SystemExit("engine recovery error insertion anchor missing")
    text = text.replace(error_anchor, error_new, 1)

for required in (
    "pub const QUALIFIED_SQLITE_VERSION_V2",
    "pub const QUALIFIED_SQLITE_SOURCE_ID_V2",
    "fn run_sqlite_engine_recovery(",
    "fn verify_recovery_journal_if_present(",
    "PRAGMA schema_version",
    "SQLiteSourceProfileMismatch { version: String, source_id: String },",
    "EngineRecoveryFailed(#[source] rusqlite::Error),",
):
    if required not in text:
        raise SystemExit(f"missing ADR-021 hardening: {required}")

TARGET.write_text(text)
print("sqlite-v2-engine-recovery: OK")
