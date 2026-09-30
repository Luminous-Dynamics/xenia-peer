//! Cross-crate crash-cut regressions for the durable Symthaea issuance boundary.
//!
//! These tests intentionally exercise the public issuance-journal contract from
//! the daemon package rather than duplicating its private unit-test fixtures.
//! They model the two externally visible crash cuts that the HTTP adapter must
//! preserve: durable reservation => DeliveryUnknown, and durable Issued =>
//! exact replay.

use std::fs::Permissions;

use xenia_symthaea_issuance_journal::{IssuanceJournal, ReserveOutcome};

fn private_tempdir() -> tempfile::TempDir {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        return tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
    }

    #[cfg(not(unix))]
    {
        tempfile::tempdir().unwrap()
    }
}

#[test]
fn durable_reservation_survives_restart_as_delivery_unknown() {
    let dir = private_tempdir();
    let path = dir.path().join("issuance.journal");
    let nonce = [0x31; 32];
    let binding = [0x41; 32];

    {
        let journal = IssuanceJournal::bootstrap_new(&path).unwrap();
        assert_eq!(
            journal.reserve(nonce, binding).unwrap(),
            ReserveOutcome::Reserved
        );
    }

    // Simulates a process crash/restart after the reservation fsync but before
    // any terminal issuance outcome became durable.
    let reopened = IssuanceJournal::open_existing(&path).unwrap();
    assert_eq!(
        reopened.reserve(nonce, binding).unwrap(),
        ReserveOutcome::DeliveryUnknown
    );
    assert_eq!(
        reopened.reserve_status(&nonce).unwrap(),
        Some(ReserveOutcome::DeliveryUnknown)
    );
}

#[test]
fn durable_issued_receipt_replays_exact_bytes_after_restart() {
    let dir = private_tempdir();
    let path = dir.path().join("issuance.journal");
    let nonce = [0x32; 32];
    let binding = [0x42; 32];
    let receipt = br#"{"receipt":"exact-retained-bytes","generation":7}"#;

    {
        let journal = IssuanceJournal::bootstrap_new(&path).unwrap();
        assert_eq!(
            journal.reserve(nonce, binding).unwrap(),
            ReserveOutcome::Reserved
        );
        journal.record_issued(nonce, binding, receipt).unwrap();
    }

    // The replay path returns the exact retained representation, not a
    // reconstructed semantic equivalent.
    let reopened = IssuanceJournal::open_existing(&path).unwrap();
    assert_eq!(
        reopened.reserve(nonce, binding).unwrap(),
        ReserveOutcome::AlreadyIssued {
            receipt: receipt.to_vec(),
        }
    );
}

#[test]
fn aborted_reservation_is_terminal_after_restart() {
    let dir = private_tempdir();
    let path = dir.path().join("issuance.journal");
    let nonce = [0x33; 32];
    let binding = [0x43; 32];

    {
        let journal = IssuanceJournal::bootstrap_new(&path).unwrap();
        assert_eq!(
            journal.reserve(nonce, binding).unwrap(),
            ReserveOutcome::Reserved
        );
        journal.record_aborted(nonce, binding).unwrap();
    }

    let reopened = IssuanceJournal::open_existing(&path).unwrap();
    assert_eq!(
        reopened.reserve(nonce, binding).unwrap(),
        ReserveOutcome::Aborted
    );
}
