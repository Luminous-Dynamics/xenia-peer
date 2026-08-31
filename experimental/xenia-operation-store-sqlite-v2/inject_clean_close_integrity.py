#!/usr/bin/env python3
from pathlib import Path

TARGET = Path(__file__).parent / "src" / "lib.rs"
text = TARGET.read_text()

old = '''    pub fn close_clean(self) -> Result<(), SqliteStoreV2Error> {
        if self.health != SqliteStoreHealthV2::Healthy {
            return Err(SqliteStoreV2Error::CleanCloseDenied(self.health));
        }
        let marker_path = self.marker_path;
        let expected_uid = self.expected_uid;
        match self.connection.close() {
            Ok(()) => remove_unclean_marker(&marker_path, expected_uid),
            Err((_connection, error)) => Err(SqliteStoreV2Error::Sqlite(error)),
        }
    }'''
new = '''    pub fn close_clean(self) -> Result<(), SqliteStoreV2Error> {
        if self.health != SqliteStoreHealthV2::Healthy {
            return Err(SqliteStoreV2Error::CleanCloseDenied(self.health));
        }
        self.verify_local_integrity()?;
        let marker_path = self.marker_path;
        let expected_uid = self.expected_uid;
        match self.connection.close() {
            Ok(()) => remove_unclean_marker(&marker_path, expected_uid),
            Err((_connection, error)) => Err(SqliteStoreV2Error::Sqlite(error)),
        }
    }'''
if old in text:
    if text.count(old) != 1:
        raise SystemExit("unexpected close_clean count")
    text = text.replace(old, new)
elif new not in text:
    raise SystemExit("close_clean form not recognized")

if "fn corrupted_store_cannot_claim_clean_close" not in text:
    needle = '''    #[test]
    fn database_symlink_is_rejected() {'''
    test = '''    #[test]
    fn corrupted_store_cannot_claim_clean_close() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let path = db(&root);
        let (store, _commit) = admitted_store(&f, &root, uid);
        let marker = marker_path(&path);
        store.connection
            .execute(
                "UPDATE admissions SET raw_admission_digest=?1 WHERE operation_id=?2",
                params![&[0xE3u8; 32][..], &f.admission.operation_id[..]],
            )
            .unwrap();
        assert!(matches!(
            store.close_clean(),
            Err(SqliteStoreV2Error::StoredAuthorityRowMismatch)
        ));
        assert!(marker.exists());
    }

    #[test]
    fn database_symlink_is_rejected() {'''
    if needle not in text:
        raise SystemExit("clean-close test insertion anchor missing")
    text = text.replace(needle, test, 1)

if "self.verify_local_integrity()?;" not in text:
    raise SystemExit("clean close integrity gate missing")
if "fn corrupted_store_cannot_claim_clean_close" not in text:
    raise SystemExit("clean close corruption test missing")

TARGET.write_text(text)
print("sqlite-v2-clean-close-integrity: OK")
