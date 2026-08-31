#!/usr/bin/env python3
from pathlib import Path

TARGET = Path(__file__).parent / "src" / "lib.rs"
text = TARGET.read_text()

if "fn qualified_sqlite_source_profile_is_exact" not in text:
    needle = '''    #[test]
    fn database_symlink_is_rejected() {'''
    insertion = '''    #[test]
    fn qualified_sqlite_source_profile_is_exact() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let store = SqliteOperationStoreV2::open(db(&root), f.epoch, uid).unwrap();
        let version: String = store
            .connection
            .query_row("SELECT sqlite_version()", [], |row| row.get(0))
            .unwrap();
        let source_id: String = store
            .connection
            .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, QUALIFIED_SQLITE_VERSION_V2);
        assert_eq!(source_id, QUALIFIED_SQLITE_SOURCE_ID_V2);
        store.close_clean().unwrap();
    }

    #[test]
    fn recovery_journal_symlink_is_rejected_before_engine_recovery() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let path = db(&root);
        let store = SqliteOperationStoreV2::open(&path, f.epoch.clone(), uid).unwrap();
        store.close_clean().unwrap();
        let marker = marker_path(&path);
        create_unclean_marker(&marker, uid).unwrap();
        let target = root.join("journal-target");
        File::create(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, rollback_journal_path(&path)).unwrap();
        assert!(matches!(
            SqliteOperationStoreV2::open(&path, f.epoch, uid),
            Err(SqliteStoreV2Error::PersistentLeafNotRegularFile)
        ));
    }

    #[test]
    fn recovery_journal_hard_link_is_rejected_before_engine_recovery() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let path = db(&root);
        let store = SqliteOperationStoreV2::open(&path, f.epoch.clone(), uid).unwrap();
        store.close_clean().unwrap();
        let marker = marker_path(&path);
        create_unclean_marker(&marker, uid).unwrap();
        let target = root.join("journal-target");
        File::create(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&target, rollback_journal_path(&path)).unwrap();
        assert!(matches!(
            SqliteOperationStoreV2::open(&path, f.epoch, uid),
            Err(SqliteStoreV2Error::UnexpectedHardLinkCount)
        ));
    }

    #[test]
    fn recovery_journal_wrong_mode_is_rejected_before_engine_recovery() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let path = db(&root);
        let store = SqliteOperationStoreV2::open(&path, f.epoch.clone(), uid).unwrap();
        store.close_clean().unwrap();
        let marker = marker_path(&path);
        create_unclean_marker(&marker, uid).unwrap();
        let journal = rollback_journal_path(&path);
        File::create(&journal).unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            SqliteOperationStoreV2::open(&path, f.epoch, uid),
            Err(SqliteStoreV2Error::PersistentLeafModeMismatch)
        ));
    }

    #[test]
    fn database_symlink_is_rejected() {'''
    if needle not in text:
        raise SystemExit("engine-recovery test insertion anchor not found")
    text = text.replace(needle, insertion, 1)

for required in (
    "fn qualified_sqlite_source_profile_is_exact",
    "fn recovery_journal_symlink_is_rejected_before_engine_recovery",
    "fn recovery_journal_hard_link_is_rejected_before_engine_recovery",
    "fn recovery_journal_wrong_mode_is_rejected_before_engine_recovery",
):
    if required not in text:
        raise SystemExit(f"missing engine-recovery test: {required}")

TARGET.write_text(text)
print("sqlite-v2-engine-recovery-tests: OK")
