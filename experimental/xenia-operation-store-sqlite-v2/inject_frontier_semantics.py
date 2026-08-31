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


replace_once(
    "use std::fs::{self, File, OpenOptions};",
    "use std::collections::BTreeMap;\nuse std::fs::{self, File, OpenOptions};",
    "BTreeMap import",
)

replace_once(
'''        self.verify_admission_rows()?;
        self.verify_receipt_chains()?;
        self.verify_frontier_chain()?;
        self.verify_mutation_frontier_links()''',
'''        self.verify_admission_rows()?;
        self.verify_receipt_chains()?;
        self.verify_frontier_chain()?;
        self.verify_frontier_semantics()?;
        self.verify_mutation_frontier_links()''',
"frontier semantic verification call",
)

if "fn verify_frontier_semantics(&self)" not in text:
    anchor = '''    fn verify_mutation_frontier_links(&self) -> Result<(), SqliteStoreV2Error> {'''
    method = '''    fn verify_frontier_semantics(&self) -> Result<(), SqliteStoreV2Error> {
        let mut admission_digests: Vec<[u8; 32]> = Vec::new();
        let mut receipt_heads: BTreeMap<[u8; 16], Option<(u32, [u8; 32])>> = BTreeMap::new();
        let mut statement = self.connection.prepare(
            "SELECT frontier_sequence, admissions_root_digest, receipt_heads_root_digest, \
                    frontier_digest, created_at_unix_ms \
             FROM frontiers ORDER BY frontier_sequence",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let sequence = u64::try_from(row.get::<_, i64>(0)?)
                .map_err(|_| SqliteStoreV2Error::CorruptInteger("frontier_sequence"))?;
            let stored_admissions_root = fixed_32(
                &row.get::<_, Vec<u8>>(1)?,
                "admissions_root_digest",
            )?;
            let stored_receipt_heads_root = fixed_32(
                &row.get::<_, Vec<u8>>(2)?,
                "receipt_heads_root_digest",
            )?;
            let frontier = fixed_32(&row.get::<_, Vec<u8>>(3)?, "frontier_digest")?;
            let created_at = u64::try_from(row.get::<_, i64>(4)?)
                .map_err(|_| SqliteStoreV2Error::CorruptInteger("frontier time"))?;

            if sequence == 0 {
                if created_at != self.current_epoch.established_at_unix_ms
                    || stored_admissions_root != admissions_root_from_history(&admission_digests)
                    || stored_receipt_heads_root != receipt_heads_root_from_history(&receipt_heads)
                {
                    return Err(SqliteStoreV2Error::FrontierSemanticRootMismatch);
                }
                continue;
            }

            let admission_count: i64 = self.connection.query_row(
                "SELECT COUNT(*) FROM admissions WHERE committed_frontier_digest=?1",
                params![&frontier[..]],
                |row| row.get(0),
            )?;
            let receipt_count: i64 = self.connection.query_row(
                "SELECT COUNT(*) FROM receipt_events WHERE committed_frontier_digest=?1",
                params![&frontier[..]],
                |row| row.get(0),
            )?;
            if admission_count < 0
                || receipt_count < 0
                || admission_count + receipt_count != 1
            {
                return Err(SqliteStoreV2Error::FrontierMutationCardinalityMismatch);
            }

            if admission_count == 1 {
                let (operation_id, admission_digest, admission_sequence, persisted_at):
                    (Vec<u8>, Vec<u8>, i64, i64) = self.connection.query_row(
                        "SELECT operation_id, admission_authority_digest, admission_sequence, \
                                persisted_at_unix_ms \
                         FROM admissions WHERE committed_frontier_digest=?1",
                        params![&frontier[..]],
                        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                    )?;
                let operation_id = fixed_16(&operation_id, "operation_id")?;
                let admission_digest = fixed_32(&admission_digest, "admission_authority_digest")?;
                let admission_sequence = u64::try_from(admission_sequence)
                    .map_err(|_| SqliteStoreV2Error::CorruptInteger("admission_sequence"))?;
                let persisted_at = u64::try_from(persisted_at)
                    .map_err(|_| SqliteStoreV2Error::CorruptInteger("persisted_at_unix_ms"))?;
                if admission_sequence != admission_digests.len() as u64
                    || persisted_at != created_at
                    || receipt_heads.contains_key(&operation_id)
                {
                    return Err(SqliteStoreV2Error::FrontierMutationOrderMismatch);
                }
                admission_digests.push(admission_digest);
                receipt_heads.insert(operation_id, None);
            } else {
                let (operation_id, event_index, previous_digest, event_digest, persisted_at):
                    (Vec<u8>, i64, Vec<u8>, Vec<u8>, i64) = self.connection.query_row(
                        "SELECT operation_id, event_index, previous_event_digest, event_digest, \
                                persisted_at_unix_ms \
                         FROM receipt_events WHERE committed_frontier_digest=?1",
                        params![&frontier[..]],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ))
                        },
                    )?;
                let operation_id = fixed_16(&operation_id, "operation_id")?;
                let event_index = u32::try_from(event_index)
                    .map_err(|_| SqliteStoreV2Error::CorruptInteger("event_index"))?;
                let previous_digest = fixed_32(&previous_digest, "previous_event_digest")?;
                let event_digest = fixed_32(&event_digest, "event_digest")?;
                let persisted_at = u64::try_from(persisted_at)
                    .map_err(|_| SqliteStoreV2Error::CorruptInteger("receipt persisted time"))?;
                let current = receipt_heads
                    .get(&operation_id)
                    .ok_or(SqliteStoreV2Error::FrontierMutationOrderMismatch)?;
                match current {
                    None if event_index == 0 && previous_digest == [0u8; 32] => {}
                    Some((previous_index, previous_head))
                        if event_index == previous_index.saturating_add(1)
                            && previous_digest == *previous_head => {}
                    _ => return Err(SqliteStoreV2Error::FrontierMutationOrderMismatch),
                }
                if persisted_at != created_at {
                    return Err(SqliteStoreV2Error::FrontierMutationOrderMismatch);
                }
                receipt_heads.insert(operation_id, Some((event_index, event_digest)));
            }

            if stored_admissions_root != admissions_root_from_history(&admission_digests)
                || stored_receipt_heads_root != receipt_heads_root_from_history(&receipt_heads)
            {
                return Err(SqliteStoreV2Error::FrontierSemanticRootMismatch);
            }
        }
        Ok(())
    }

    fn verify_mutation_frontier_links(&self) -> Result<(), SqliteStoreV2Error> {'''
    if anchor not in text:
        raise SystemExit("frontier semantic insertion anchor missing")
    text = text.replace(anchor, method, 1)

if "fn admissions_root_from_history(" not in text:
    anchor = '''fn empty_root(domain: &[u8]) -> [u8; 32] {'''
    helpers = '''fn admissions_root_from_history(digests: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ADMISSION_ROOT_DOMAIN_V2);
    hasher.update(&(digests.len() as u64).to_le_bytes());
    for digest in digests {
        hasher.update(digest);
    }
    *hasher.finalize().as_bytes()
}

fn receipt_heads_root_from_history(
    heads: &BTreeMap<[u8; 16], Option<(u32, [u8; 32])>>,
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPT_HEADS_ROOT_DOMAIN_V2);
    hasher.update(&(heads.len() as u64).to_le_bytes());
    for (operation_id, head) in heads {
        hasher.update(operation_id);
        hasher.update(&head.map(|(_, digest)| digest).unwrap_or([0u8; 32]));
    }
    *hasher.finalize().as_bytes()
}

fn empty_root(domain: &[u8]) -> [u8; 32] {'''
    if anchor not in text:
        raise SystemExit("history root helper anchor missing")
    text = text.replace(anchor, helpers, 1)

error_anchor = '''    /// Current semantic roots differ from frontier head.
    #[error("current frontier semantic roots mismatch")]
    FrontierRootMismatch,
'''
error_new = '''    /// Current semantic roots differ from frontier head.
    #[error("current frontier semantic roots mismatch")]
    FrontierRootMismatch,
    /// A non-genesis frontier does not correspond to exactly one durable mutation.
    #[error("frontier mutation cardinality mismatch")]
    FrontierMutationCardinalityMismatch,
    /// Mutation order or persistence time disagrees with frontier sequence.
    #[error("frontier mutation order mismatch")]
    FrontierMutationOrderMismatch,
    /// Replaying durable mutations does not reproduce a frontier's semantic roots.
    #[error("frontier semantic root mismatch")]
    FrontierSemanticRootMismatch,
'''
if "FrontierMutationCardinalityMismatch," not in text:
    replace_once(error_anchor, error_new, "frontier semantic errors")

for required in (
    "fn verify_frontier_semantics(&self)",
    "FrontierMutationCardinalityMismatch",
    "FrontierMutationOrderMismatch",
    "FrontierSemanticRootMismatch",
    "fn admissions_root_from_history(",
    "fn receipt_heads_root_from_history(",
):
    if required not in text:
        raise SystemExit(f"missing frontier semantic hardening: {required}")

TARGET.write_text(text)
print("sqlite-v2-frontier-semantics: OK")
