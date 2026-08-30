// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::env;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process;
use std::thread;
use std::time::Duration;

use xenia_operation_authority_epoch::{
    AuthorityEpochReasonV1, OperationAuthorityEpochV1, OPERATION_AUTHORITY_EPOCH_SCHEMA_V1,
};
use xenia_operation_store_sqlite_v2::{SqliteOperationStoreV2, SqliteStoreHealthV2};

fn epoch() -> OperationAuthorityEpochV1 {
    OperationAuthorityEpochV1 {
        schema: OPERATION_AUTHORITY_EPOCH_SCHEMA_V1.into(),
        authority_domain_id: [0x11; 16],
        epoch_id: [0x22; 16],
        epoch_sequence: 0,
        previous_epoch_digest: [0; 32],
        store_id: [0x33; 16],
        store_generation: 0,
        reason: AuthorityEpochReasonV1::Genesis,
        established_at_unix_ms: 1_000,
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
    let mode = args.next().ok_or("usage: store_lock_probe <hold|probe> <database>")?;
    let database = PathBuf::from(
        args.next()
            .ok_or("usage: store_lock_probe <hold|probe> <database>")?,
    );
    if args.next().is_some() {
        return Err("unexpected extra argument".into());
    }
    let parent = database.parent().ok_or("database path has no parent")?;
    let expected_uid = std::fs::symlink_metadata(parent)?.uid();

    match mode.as_str() {
        "hold" => {
            let store = SqliteOperationStoreV2::open(&database, epoch(), expected_uid)?;
            if store.health() != SqliteStoreHealthV2::Healthy {
                return Err(format!("holder opened non-healthy store: {:?}", store.health()).into());
            }
            println!("READY HEALTH={:?}", store.health());
            io::stdout().flush()?;
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }
        "probe" => match SqliteOperationStoreV2::open(&database, epoch(), expected_uid) {
            Ok(store) => {
                println!("HEALTH={:?}", store.health());
                if store.health() == SqliteStoreHealthV2::RecoveryRequired {
                    Ok(())
                } else {
                    Err(format!("unexpected probe health: {:?}", store.health()).into())
                }
            }
            Err(error) => Err(error.into()),
        },
        _ => Err("mode must be hold or probe".into()),
    }
}
