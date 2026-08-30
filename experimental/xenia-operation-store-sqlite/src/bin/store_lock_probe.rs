// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Small CI probe for cross-process writer ownership and stale-marker semantics.

use std::env;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use xenia_operation_store_sqlite::{
    SqliteOperationStoreV1, SqliteStoreConfigV1, SqliteStoreHealthV1,
};

fn main() {
    let mut args = env::args().skip(1);
    let mode = args.next().expect("mode: hold|probe|clean");
    let path = PathBuf::from(args.next().expect("database path"));
    let config = SqliteStoreConfigV1 {
        store_id: [0x41; 16],
        generation: 0,
    };

    match mode.as_str() {
        "hold" => {
            let store = SqliteOperationStoreV1::open(&path, config).expect("first writer open");
            assert_eq!(store.health(), SqliteStoreHealthV1::Healthy);
            println!("READY");
            // CI terminates this process without `close_clean` to model an unclean writer.
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }
        "probe" => match SqliteOperationStoreV1::open(&path, config) {
            Ok(store) => {
                println!("HEALTH={:?}", store.health());
                if store.health() == SqliteStoreHealthV1::Healthy {
                    // A second healthy writer while `hold` owns the DB is a test failure.
                    let _ = store.close_clean();
                    std::process::exit(2);
                }
            }
            Err(error) => {
                eprintln!("OPEN_ERROR={error}");
                std::process::exit(3);
            }
        },
        "clean" => {
            let store = SqliteOperationStoreV1::open(&path, config).expect("clean open");
            println!("HEALTH={:?}", store.health());
            if store.health() != SqliteStoreHealthV1::Healthy {
                std::process::exit(4);
            }
            store.close_clean().expect("clean close");
        }
        other => panic!("unknown mode: {other}"),
    }
}
