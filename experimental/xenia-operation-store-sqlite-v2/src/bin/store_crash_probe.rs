// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Destructive, feature-gated crash qualification probe for ADR-020.
//! This binary never performs an external privileged effect.

use std::env;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use xenia_operation_authority_epoch::{
    AuthorityEpochReasonV1, OperationAuthorityEpochV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1,
};
use xenia_operation_authority_v2::{
    AdmissionAuthorityV2, AuthenticatedIssuanceContextV2, EffectArmAuthorityV2,
    GrantAuthorityV2, UseAuthorityV2,
};
use xenia_operation_receipt_finalization::{
    ReceiptEventV1, ReceiptStateV1, RECEIPT_FINALIZATION_SCHEMA_V1,
};
use xenia_operation_store_sqlite_v2::{
    AdmissionDecisionV2, AuthenticatedAdmissionContextV2, AuthenticatedUseSlotV2,
    SqliteOperationStoreV2, SqliteStoreHealthV2, SQLITE_DATABASE_FILENAME_V2,
    UNCLEAN_WRITER_MARKER_SUFFIX_V2,
};

#[derive(Clone)]
struct Fixture {
    epoch: OperationAuthorityEpochV1,
    issuance: AuthenticatedIssuanceContextV2,
    grant: GrantAuthorityV2,
    use_authority: UseAuthorityV2,
    admission: AdmissionAuthorityV2,
    semantic: AuthenticatedAdmissionContextV2,
    slot: AuthenticatedUseSlotV2,
}

fn fixture() -> Fixture {
    let epoch = OperationAuthorityEpochV1 {
        schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
        authority_domain_id: [0x01; 16],
        epoch_id: [0x02; 16],
        epoch_sequence: 0,
        previous_epoch_digest: [0; 32],
        store_id: [0x03; 16],
        store_generation: 0,
        reason: AuthorityEpochReasonV1::Genesis,
        established_at_unix_ms: 1_000,
    };
    let issuance = AuthenticatedIssuanceContextV2 {
        issuer_authority_digest: [0x11; 32],
        issuance_evidence_digest: [0x12; 32],
    };
    let grant = GrantAuthorityV2::new([0x21; 32], &epoch, issuance, 1_020)
        .expect("fixture grant");
    let use_authority = UseAuthorityV2::new(
        [0x31; 16],
        [0x32; 32],
        &grant,
        &epoch,
        issuance,
    )
    .expect("fixture use authority");
    let admission = AdmissionAuthorityV2::new(
        [0x41; 32],
        &use_authority,
        &grant,
        &epoch,
        issuance,
    )
    .expect("fixture admission authority");
    Fixture {
        epoch,
        issuance,
        grant,
        slot: AuthenticatedUseSlotV2 {
            grant_authority_digest: use_authority.grant_authority_digest,
            raw_use_digest: use_authority.raw_use_digest,
            use_index: 0,
        },
        use_authority,
        admission,
        semantic: AuthenticatedAdmissionContextV2 {
            raw_admission_digest: [0x41; 32],
            admitted_at_unix_ms: 1_050,
        },
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR={error}");
        process::exit(3);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mode = args.next().ok_or(
        "usage: store_crash_probe <init-empty|init-arm|admission|effect-armed|inspect-admission|inspect-arm> <database> [point|expectation]",
    )?;
    let database = PathBuf::from(args.next().ok_or("database path required")?);
    if database.file_name().and_then(|value| value.to_str()) != Some(SQLITE_DATABASE_FILENAME_V2) {
        return Err("database must use the fixed V2 filename".into());
    }
    let f = fixture();
    let uid = expected_uid(&database)?;

    match mode.as_str() {
        "init-empty" => {
            no_extra(args)?;
            let store = SqliteOperationStoreV2::open(&database, f.epoch, uid)?;
            if store.health() != SqliteStoreHealthV2::Healthy {
                return Err("fresh baseline did not open Healthy".into());
            }
            store.close_clean()?;
            println!("BASELINE=empty-clean");
        }
        "init-arm" => {
            no_extra(args)?;
            let mut store = SqliteOperationStoreV2::open(&database, f.epoch.clone(), uid)?;
            let commit = store.admit(
                &f.admission,
                &f.use_authority,
                &f.grant,
                f.issuance,
                f.semantic,
                f.slot,
                1_100,
            )?;
            if commit.decision != AdmissionDecisionV2::Admitted {
                return Err("arm baseline admission was not new".into());
            }
            store.close_clean()?;
            println!("BASELINE=admission-clean");
        }
        "admission" => {
            let point = one_extra(args)?;
            let mut store = SqliteOperationStoreV2::open(&database, f.epoch, uid)?;
            let commit = store.admit(
                &f.admission,
                &f.use_authority,
                &f.grant,
                f.issuance,
                f.semantic,
                f.slot,
                1_100,
            )?;
            println!("ADMISSION_RETURNED={:?}", commit.decision);
            crash_after_return_or_hold(&point);
            return Err("admission crash probe unexpectedly survived".into());
        }
        "effect-armed" => {
            let point = one_extra(args)?;
            let mut store = SqliteOperationStoreV2::open(&database, f.epoch.clone(), uid)?;
            let admission_commit = store.admit(
                &f.admission,
                &f.use_authority,
                &f.grant,
                f.issuance,
                f.semantic,
                f.slot,
                1_100,
            )?;
            if admission_commit.decision != AdmissionDecisionV2::DuplicateSame {
                return Err("EffectArmed baseline admission was not exact replay".into());
            }
            let arm = EffectArmAuthorityV2::new(
                [0x61; 32],
                &f.admission,
                store.store_authority(),
                store.current_epoch(),
            )?;
            let event = effect_armed_event(&f, &arm);
            let commit = store.append_effect_armed(
                &f.admission,
                f.semantic,
                &admission_commit.proof,
                &arm,
                &event,
                1_160,
            )?;
            println!("EFFECT_ARMED_RETURNED={:?}", commit.decision);
            crash_after_return_or_hold(&point);
            return Err("EffectArmed crash probe unexpectedly survived".into());
        }
        "inspect-admission" => {
            let expectation = one_extra(args)?;
            inspect(&database, uid, &f, InspectKind::Admission, &expectation)?;
        }
        "inspect-arm" => {
            let expectation = one_extra(args)?;
            inspect(&database, uid, &f, InspectKind::EffectArmed, &expectation)?;
        }
        _ => return Err(format!("unknown mode: {mode}").into()),
    }
    Ok(())
}

fn no_extra(mut args: impl Iterator<Item = String>) -> Result<(), Box<dyn std::error::Error>> {
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    Ok(())
}

fn one_extra(mut args: impl Iterator<Item = String>) -> Result<String, Box<dyn std::error::Error>> {
    let value = args.next().ok_or("required trailing argument missing")?;
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    Ok(value)
}

fn expected_uid(database: &Path) -> Result<u32, Box<dyn std::error::Error>> {
    let parent = database.parent().ok_or("database has no parent")?;
    Ok(std::fs::symlink_metadata(parent)?.uid())
}

fn effect_armed_event(f: &Fixture, arm: &EffectArmAuthorityV2) -> ReceiptEventV1 {
    ReceiptEventV1 {
        schema: RECEIPT_FINALIZATION_SCHEMA_V1.into(),
        admission_digest: f.admission.raw_admission_digest,
        operation_id: f.admission.operation_id,
        event_index: 0,
        previous_event_digest: [0; 32],
        state: ReceiptStateV1::EffectArmed,
        recorded_at_unix_ms: 1_150,
        arm_authorization_digest: Some(arm.raw_arm_authorization_digest),
        evidence_digest: None,
    }
}

fn crash_after_return_or_hold(point: &str) {
    match point {
        "C10" => process::abort(),
        "RACE" => loop {
            thread::sleep(Duration::from_secs(60));
        },
        _ => {
            // C0-C9 are expected to terminate inside the feature-gated library hook.
        }
    }
}

#[derive(Clone, Copy)]
enum InspectKind {
    Admission,
    EffectArmed,
}

fn inspect(
    database: &Path,
    uid: u32,
    f: &Fixture,
    kind: InspectKind,
    expectation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = SqliteOperationStoreV2::open(database, f.epoch.clone(), uid)?;
    if store.health() != SqliteStoreHealthV2::RecoveryRequired {
        return Err(format!("post-crash store health was {:?}", store.health()).into());
    }
    store.verify_local_integrity()?;
    if !marker_path(database).exists() {
        return Err("unclean writer marker did not survive crash".into());
    }

    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags(database, flags)?;
    let admissions: i64 = connection.query_row("SELECT COUNT(*) FROM admissions", [], |row| row.get(0))?;
    let receipts: i64 = connection.query_row("SELECT COUNT(*) FROM receipt_events", [], |row| row.get(0))?;
    let frontiers: i64 = connection.query_row("SELECT COUNT(*) FROM frontiers", [], |row| row.get(0))?;

    let present = match kind {
        InspectKind::Admission => {
            if receipts != 0 {
                return Err(format!("admission crash produced unexpected receipts={receipts}").into());
            }
            match admissions {
                0 if frontiers == 1 => false,
                1 if frontiers == 2 => true,
                _ => {
                    return Err(format!(
                        "partial admission state: admissions={admissions} receipts={receipts} frontiers={frontiers}"
                    )
                    .into())
                }
            }
        }
        InspectKind::EffectArmed => {
            if admissions != 1 {
                return Err(format!("EffectArmed crash lost/duplicated baseline admission: {admissions}").into());
            }
            match receipts {
                0 if frontiers == 2 => false,
                1 if frontiers == 3 => true,
                _ => {
                    return Err(format!(
                        "partial EffectArmed state: admissions={admissions} receipts={receipts} frontiers={frontiers}"
                    )
                    .into())
                }
            }
        }
    };

    match expectation {
        "absent" if present => return Err("expected absent transaction, found committed".into()),
        "present" if !present => return Err("expected committed transaction, found absent".into()),
        "absent" | "present" | "either" => {}
        _ => return Err(format!("unknown expectation: {expectation}").into()),
    }

    if present {
        let admission_digest = store.qualification_admission_proof_digest(&f.admission)?;
        println!("ADMISSION_PROOF_DIGEST={}", hex32(admission_digest));
        if matches!(kind, InspectKind::EffectArmed) {
            let arm = EffectArmAuthorityV2::new(
                [0x61; 32],
                &f.admission,
                store.store_authority(),
                store.current_epoch(),
            )?;
            let arm_digest = store.qualification_effect_armed_proof_digest(&f.admission, &arm)?;
            println!("EFFECT_ARMED_PROOF_DIGEST={}", hex32(arm_digest));
        }
        println!("OUTCOME=committed");
    } else {
        println!("OUTCOME=absent");
    }
    println!("HEALTH=RecoveryRequired");
    println!("ADMISSIONS={admissions} RECEIPTS={receipts} FRONTIERS={frontiers}");
    Ok(())
}

fn marker_path(database: &Path) -> PathBuf {
    let mut value = database.as_os_str().to_os_string();
    value.push(UNCLEAN_WRITER_MARKER_SUFFIX_V2);
    PathBuf::from(value)
}

fn hex32(value: [u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in value {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
