// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Print the exact SQLite runtime identity used by the V2 qualification lane.

use rusqlite::Connection;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    let version: String = connection.query_row("SELECT sqlite_version()", [], |row| row.get(0))?;
    let source_id: String =
        connection.query_row("SELECT sqlite_source_id()", [], |row| row.get(0))?;
    println!("SQLITE_VERSION={version}");
    println!("SQLITE_SOURCE_ID={source_id}");
    Ok(())
}
