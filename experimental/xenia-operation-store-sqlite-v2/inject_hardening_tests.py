#!/usr/bin/env python3
from pathlib import Path

TARGET = Path(__file__).parent / "src" / "lib.rs"
text = TARGET.read_text()

if "fn corrupted_admission_auxiliary_column_fails_local_integrity" not in text:
    needle = '''    #[test]
    fn database_symlink_is_rejected() {'''
    insertion = '''    #[test]
    fn corrupted_admission_auxiliary_column_fails_local_integrity() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let (store, _commit) = admitted_store(&f, &root, uid);
        store.connection
            .execute(
                "UPDATE admissions SET raw_admission_digest=?1 WHERE operation_id=?2",
                params![&[0xE1u8; 32][..], &f.admission.operation_id[..]],
            )
            .unwrap();
        assert!(matches!(
            store.verify_local_integrity(),
            Err(SqliteStoreV2Error::StoredAuthorityRowMismatch)
        ));
    }

    #[test]
    fn corrupted_receipt_digest_column_fails_local_integrity() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let (mut store, admission_commit) = admitted_store(&f, &root, uid);
        let arm = EffectArmAuthorityV2::new(
            [0x61; 32],
            &f.admission,
            store.store_authority(),
            store.current_epoch(),
        )
        .unwrap();
        let armed = ReceiptEventV1 {
            schema: xenia_operation_receipt_finalization::RECEIPT_FINALIZATION_SCHEMA_V1.into(),
            admission_digest: f.admission.raw_admission_digest,
            operation_id: f.admission.operation_id,
            event_index: 0,
            previous_event_digest: [0; 32],
            state: ReceiptStateV1::EffectArmed,
            recorded_at_unix_ms: 1_150,
            arm_authorization_digest: Some(arm.raw_arm_authorization_digest),
            evidence_digest: None,
        };
        store
            .append_effect_armed(
                &f.admission,
                f.semantic,
                &admission_commit.proof,
                &arm,
                &armed,
                1_160,
            )
            .unwrap();
        store.connection
            .execute(
                "UPDATE receipt_events SET event_digest=?1 WHERE operation_id=?2 AND event_index=0",
                params![&[0xE2u8; 32][..], &f.admission.operation_id[..]],
            )
            .unwrap();
        assert!(matches!(
            store.verify_local_integrity(),
            Err(SqliteStoreV2Error::StoredReceiptRowMismatch)
        ));
    }

    #[test]
    fn stale_marker_with_missing_database_never_creates_replacement_store() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let path = db(&root);
        let marker = marker_path(&path);
        create_unclean_marker(&marker, uid).unwrap();
        assert!(!path.exists());
        assert!(matches!(
            SqliteOperationStoreV2::open(&path, f.epoch, uid),
            Err(SqliteStoreV2Error::RecoveryDatabaseMissing)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn recovery_required_open_does_not_change_database_bytes() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let path = db(&root);
        {
            let mut store = SqliteOperationStoreV2::open(&path, f.epoch.clone(), uid).unwrap();
            store
                .admit(
                    &f.admission,
                    &f.use_authority,
                    &f.grant,
                    f.issuance,
                    f.semantic,
                    f.slot,
                    1_100,
                )
                .unwrap();
            // Ordinary drop intentionally leaves the writer marker.
        }
        let before = fs::read(&path).unwrap();
        {
            let recovery = SqliteOperationStoreV2::open(&path, f.epoch.clone(), uid).unwrap();
            assert_eq!(recovery.health(), SqliteStoreHealthV2::RecoveryRequired);
            recovery.verify_metadata().unwrap();
        }
        let after = fs::read(&path).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn database_symlink_is_rejected() {'''
    if needle not in text:
        raise SystemExit("hardening test insertion anchor not found")
    text = text.replace(needle, insertion, 1)

for required in (
    "fn corrupted_admission_auxiliary_column_fails_local_integrity",
    "fn corrupted_receipt_digest_column_fails_local_integrity",
    "fn stale_marker_with_missing_database_never_creates_replacement_store",
    "fn recovery_required_open_does_not_change_database_bytes",
):
    if required not in text:
        raise SystemExit(f"missing hardening test: {required}")

TARGET.write_text(text)
print("sqlite-v2-hardening-tests: OK")
