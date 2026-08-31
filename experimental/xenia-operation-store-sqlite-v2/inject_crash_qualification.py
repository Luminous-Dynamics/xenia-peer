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


def method_span(name: str) -> tuple[int, int]:
    marker = f"    fn {name}("
    start = text.find(marker)
    if start < 0:
        raise SystemExit(f"method not found: {name}")
    candidates = []
    next_method = text.find("\n    fn ", start + len(marker))
    if next_method >= 0:
        candidates.append(next_method)
    impl_end = text.find("\n}\n\n#[derive", start + len(marker))
    if impl_end >= 0:
        candidates.append(impl_end)
    if not candidates:
        raise SystemExit(f"method end not found: {name}")
    return start, min(candidates)


def replace_in_method(name: str, old: str, new: str, label: str) -> None:
    global text
    start, end = method_span(name)
    body = text[start:end]
    if old in body:
        if body.count(old) != 1:
            raise SystemExit(f"{label}: expected one old form in {name}, found {body.count(old)}")
        body = body.replace(old, new)
        text = text[:start] + body + text[end:]
    elif new not in body:
        raise SystemExit(f"{label}: neither old nor new form found in {name}")


# Qualification hooks are compiled out of normal builds. The commit-window hook is a small
# two-file barrier used by the parent SIGKILL race: child writes READY, waits for GO, then enters
# SQLite COMMIT immediately after returning from this function.
helper_anchor = '''const COMMIT_EVIDENCE_DOMAIN_V2: &[u8] = b"xenia-operation-store-commit-evidence-v2";\n'''
helper = '''const COMMIT_EVIDENCE_DOMAIN_V2: &[u8] = b"xenia-operation-store-commit-evidence-v2";\n\n#[cfg(feature = "crash-injection")]
fn qualification_crash_point(scope: &str, point: &str) {
    let expected = format!("{scope}:{point}");
    if std::env::var("XENIA_SQLITE_V2_CRASH_AT").ok().as_deref() == Some(expected.as_str()) {
        std::process::abort();
    }
}

#[cfg(not(feature = "crash-injection"))]
#[inline(always)]
fn qualification_crash_point(_scope: &str, _point: &str) {}

#[cfg(feature = "crash-injection")]
fn qualification_commit_window(scope: &str) {
    if std::env::var("XENIA_SQLITE_V2_COMMIT_WINDOW").ok().as_deref() != Some(scope) {
        return;
    }
    let Some(ready_path) = std::env::var_os("XENIA_SQLITE_V2_COMMIT_READY") else {
        std::process::abort();
    };
    let Some(go_path) = std::env::var_os("XENIA_SQLITE_V2_COMMIT_GO") else {
        std::process::abort();
    };
    let ready_path = PathBuf::from(ready_path);
    let go_path = PathBuf::from(go_path);
    let mut ready = match OpenOptions::new().write(true).create_new(true).open(&ready_path) {
        Ok(file) => file,
        Err(_) => std::process::abort(),
    };
    if ready.write_all(scope.as_bytes()).is_err() || ready.sync_all().is_err() {
        std::process::abort();
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !go_path.exists() {
        if std::time::Instant::now() >= deadline {
            std::process::abort();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(not(feature = "crash-injection"))]
#[inline(always)]
fn qualification_commit_window(_scope: &str) {}
'''
if "fn qualification_crash_point(" not in text:
    replace_once(helper_anchor, helper, "crash helper insertion")

# Admission C0-C4.
replace_in_method(
    "admit_inner",
    '''        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;''',
    '''        qualification_crash_point("admission", "C0");
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        qualification_crash_point("admission", "C1");''',
    "admission C0/C1",
)
replace_in_method(
    "admit_inner",
    '''        let sequence = next_admission_sequence(&transaction)?;''',
    '''        qualification_crash_point("admission", "C2");
        let sequence = next_admission_sequence(&transaction)?;''',
    "admission C2",
)
replace_in_method(
    "admit_inner",
    '''        let following = sequence''',
    '''        qualification_crash_point("admission", "C3");
        let following = sequence''',
    "admission C3",
)
replace_in_method(
    "admit_inner",
    '''        let frontier = append_frontier(&transaction, store_authority_digest, persisted_at_unix_ms)?;''',
    '''        qualification_crash_point("admission", "C4");
        let frontier = append_frontier(
            &transaction,
            store_authority_digest,
            persisted_at_unix_ms,
            "admission",
        )?;''',
    "admission C4/frontier scope",
)
replace_in_method(
    "admit_inner",
    '''        let commit_evidence = commit_evidence_digest(''',
    '''        qualification_crash_point("admission", "C7");
        let commit_evidence = commit_evidence_digest(''',
    "admission C7",
)
replace_in_method(
    "admit_inner",
    '''        transaction.commit()?;
        Ok(AdmissionCommitV2 {''',
    '''        qualification_crash_point("admission", "C8");
        qualification_commit_window("admission");
        transaction.commit()?;
        qualification_crash_point("admission", "C9");
        Ok(AdmissionCommitV2 {''',
    "admission C8/C9 commit",
)

# EffectArmed C0-C4.
replace_in_method(
    "append_effect_armed_inner",
    '''        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;''',
    '''        qualification_crash_point("effect-armed", "C0");
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        qualification_crash_point("effect-armed", "C1");''',
    "effect C0/C1",
)
replace_in_method(
    "append_effect_armed_inner",
    '''        insert_receipt_event(&transaction, event, persisted_at_unix_ms)?;''',
    '''        qualification_crash_point("effect-armed", "C2");
        insert_receipt_event(&transaction, event, persisted_at_unix_ms)?;
        qualification_crash_point("effect-armed", "C3");
        // EffectArmed has no admission-sequence metadata update. C4 is the equivalent
        // ready-to-append-frontier state after the primary receipt row is present.
        qualification_crash_point("effect-armed", "C4");''',
    "effect C2-C4",
)
replace_in_method(
    "append_effect_armed_inner",
    '''        let frontier = append_frontier(&transaction, store_authority_digest, persisted_at_unix_ms)?;''',
    '''        let frontier = append_frontier(
            &transaction,
            store_authority_digest,
            persisted_at_unix_ms,
            "effect-armed",
        )?;''',
    "effect frontier scope",
)
replace_in_method(
    "append_effect_armed_inner",
    '''        let commit_evidence = commit_evidence_digest(''',
    '''        qualification_crash_point("effect-armed", "C7");
        let commit_evidence = commit_evidence_digest(''',
    "effect C7",
)
replace_in_method(
    "append_effect_armed_inner",
    '''        transaction.commit()?;
        Ok(EffectArmedCommitV2 {''',
    '''        qualification_crash_point("effect-armed", "C8");
        qualification_commit_window("effect-armed");
        transaction.commit()?;
        qualification_crash_point("effect-armed", "C9");
        Ok(EffectArmedCommitV2 {''',
    "effect C8/C9 commit",
)

# Ordinary receipts share append_frontier but are outside ADR-020 C0-C10 qualification.
replace_in_method(
    "append_receipt_inner",
    '''        let frontier = append_frontier(&transaction, store_authority_digest, persisted_at_unix_ms)?;''',
    '''        let frontier = append_frontier(
            &transaction,
            store_authority_digest,
            persisted_at_unix_ms,
            "receipt",
        )?;''',
    "ordinary receipt frontier scope",
)

# Shared frontier C5/C6.
old_frontier_sig = '''fn append_frontier(
    transaction: &Transaction<'_>,
    store_authority_digest: [u8; 32],
    created_at_unix_ms: u64,
) -> Result<[u8; 32], SqliteStoreV2Error> {'''
new_frontier_sig = '''fn append_frontier(
    transaction: &Transaction<'_>,
    store_authority_digest: [u8; 32],
    created_at_unix_ms: u64,
    crash_scope: &'static str,
) -> Result<[u8; 32], SqliteStoreV2Error> {'''
replace_once(old_frontier_sig, new_frontier_sig, "append_frontier crash scope")

# Restrict replacements to append_frontier's top-level function body.
frontier_start = text.find("fn append_frontier(")
frontier_end = text.find("\nfn compute_admissions_root(", frontier_start)
if frontier_start < 0 or frontier_end < 0:
    raise SystemExit("append_frontier span not found")
frontier = text[frontier_start:frontier_end]
old_c5 = '''    let following = sequence
        .checked_add(1)'''
new_c5 = '''    qualification_crash_point(crash_scope, "C5");
    let following = sequence
        .checked_add(1)'''
if old_c5 in frontier:
    frontier = frontier.replace(old_c5, new_c5, 1)
elif new_c5 not in frontier:
    raise SystemExit("frontier C5 insertion point not found")
old_c6 = '''    )?;
    Ok(digest)
}'''
new_c6 = '''    )?;
    qualification_crash_point(crash_scope, "C6");
    Ok(digest)
}'''
if old_c6 in frontier:
    frontier = frontier.replace(old_c6, new_c6, 1)
elif new_c6 not in frontier:
    raise SystemExit("frontier C6 insertion point not found")
text = text[:frontier_start] + frontier + text[frontier_end:]

# Qualification-only proof reconstruction. It returns only proof digests, not reusable
# authenticated persistence contexts, and re-runs full local integrity first.
if "qualification_admission_proof_digest" not in text:
    anchor = '''    fn verify_admission_rows(&self) -> Result<(), SqliteStoreV2Error> {'''
    methods = '''    /// Qualification-only reconstruction of the exact durable admission proof digest.
    #[cfg(feature = "crash-injection")]
    pub fn qualification_admission_proof_digest(
        &self,
        admission: &AdmissionAuthorityV2,
    ) -> Result<[u8; 32], SqliteStoreV2Error> {
        self.verify_local_integrity()?;
        let row = read_admission_row(&self.connection, admission.operation_id)?
            .ok_or(SqliteStoreV2Error::MissingAdmission)?;
        let (proof, authenticated) = reconstruct_admission_proof(
            &row,
            admission,
            &self.store_authority,
            &self.current_epoch,
            self.backend_authority_digest,
            self.persistence_profile_digest,
        )?;
        proof.validate_against(
            admission,
            &self.store_authority,
            &self.current_epoch,
            authenticated,
        )?;
        Ok(proof.proof_digest()?)
    }

    /// Qualification-only reconstruction of the exact durable EffectArmed proof digest.
    #[cfg(feature = "crash-injection")]
    pub fn qualification_effect_armed_proof_digest(
        &self,
        admission: &AdmissionAuthorityV2,
        arm: &EffectArmAuthorityV2,
    ) -> Result<[u8; 32], SqliteStoreV2Error> {
        self.verify_local_integrity()?;
        let admission_row = read_admission_row(&self.connection, admission.operation_id)?
            .ok_or(SqliteStoreV2Error::MissingAdmission)?;
        let (admission_proof, admission_authenticated) = reconstruct_admission_proof(
            &admission_row,
            admission,
            &self.store_authority,
            &self.current_epoch,
            self.backend_authority_digest,
            self.persistence_profile_digest,
        )?;
        admission_proof.validate_against(
            admission,
            &self.store_authority,
            &self.current_epoch,
            admission_authenticated,
        )?;
        let receipt = read_receipt_row(&self.connection, admission.operation_id, 0)?
            .ok_or(SqliteStoreV2Error::QualificationReceiptMissing)?;
        if receipt.event.state != ReceiptStateV1::EffectArmed {
            return Err(SqliteStoreV2Error::QualificationReceiptMissing);
        }
        let (proof, authenticated) = reconstruct_effect_armed_proof(
            &receipt,
            arm,
            &admission_proof,
            &self.store_authority,
            &self.current_epoch,
            self.backend_authority_digest,
            self.persistence_profile_digest,
        )?;
        proof.validate_final_gate(
            arm,
            &admission_proof,
            &self.store_authority,
            &self.current_epoch,
            authenticated,
        )?;
        Ok(proof.proof_digest()?)
    }

    fn verify_admission_rows(&self) -> Result<(), SqliteStoreV2Error> {'''
    if anchor not in text:
        raise SystemExit("qualification proof method insertion anchor missing")
    text = text.replace(anchor, methods, 1)

if "QualificationReceiptMissing," not in text:
    error_anchor = '''    /// Receipt compare-and-append conflict.
    #[error("receipt compare-and-append conflict")]
    ReceiptCasConflict,
'''
    error_new = '''    /// Receipt compare-and-append conflict.
    #[error("receipt compare-and-append conflict")]
    ReceiptCasConflict,
    /// Qualification-only proof reconstruction expected a durable EffectArmed receipt.
    #[cfg(feature = "crash-injection")]
    #[error("qualification EffectArmed receipt is missing")]
    QualificationReceiptMissing,
'''
    if error_anchor not in text:
        raise SystemExit("qualification receipt error anchor missing")
    text = text.replace(error_anchor, error_new, 1)

for required in (
    'qualification_crash_point("admission", "C0")',
    'qualification_crash_point("admission", "C9")',
    'qualification_crash_point("effect-armed", "C0")',
    'qualification_crash_point("effect-armed", "C9")',
    'qualification_crash_point(crash_scope, "C5")',
    'qualification_crash_point(crash_scope, "C6")',
    'qualification_commit_window("admission")',
    'qualification_commit_window("effect-armed")',
    'pub fn qualification_admission_proof_digest',
    'pub fn qualification_effect_armed_proof_digest',
):
    if required not in text:
        raise SystemExit(f"missing crash qualification hardening: {required}")

TARGET.write_text(text)
print("sqlite-v2-crash-qualification-hooks: OK")
