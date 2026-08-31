#!/usr/bin/env python3
from pathlib import Path

TARGET = Path(__file__).parent / "src" / "lib.rs"
text = TARGET.read_text()


def replace_once(old: str, new: str, label: str) -> None:
    global text
    if old in text:
        if text.count(old) != 1:
            raise SystemExit(f"{label}: expected exactly one old form, found {text.count(old)}")
        text = text.replace(old, new)
    elif new not in text:
        raise SystemExit(f"{label}: neither old nor new form found")


# --- Authority imports -----------------------------------------------------
replace_once(
'''use xenia_operation_authority_v2::{
    AdmissionAuthorityV2, AuthorityV2Error, EffectArmAuthorityV2, StoreAuthorityV2,
    UseAuthorityV2,
};''',
'''use xenia_operation_authority_v2::{
    AdmissionAuthorityV2, AuthenticatedIssuanceContextV2, AuthorityV2Error,
    EffectArmAuthorityV2, GrantAuthorityV2, StoreAuthorityV2, UseAuthorityV2,
};''',
"authority-v2 imports",
)

# --- Schema: preserve the complete grant -> use -> admission authority chain.
# The previous draft had 15 semantic columns and an accidental sixteenth insert value. V2 now
# intentionally has 16 named fields by adding the exact GrantAuthorityV2 bytes after its digest.
old_schema = '''    use_authority_bytes BLOB NOT NULL,
    grant_authority_digest BLOB NOT NULL CHECK(length(grant_authority_digest) = 32),
    raw_use_digest BLOB NOT NULL CHECK(length(raw_use_digest) = 32),'''
new_schema = '''    use_authority_bytes BLOB NOT NULL,
    grant_authority_digest BLOB NOT NULL CHECK(length(grant_authority_digest) = 32),
    grant_authority_bytes BLOB NOT NULL,
    raw_use_digest BLOB NOT NULL CHECK(length(raw_use_digest) = 32),'''
replace_once(old_schema, new_schema, "grant authority bytes schema")

# --- Recovery-safe open ----------------------------------------------------
# A stale writer marker means inspection of historical authority, not initialization. Open it
# read-only, never CREATE/chmod/journal-reconfigure it, and fail if the DB is missing. Healthy
# opens acquire exclusive ownership, re-check the marker race, durably create the marker, and only
# then configure the mutable SQLite durability profile.
old_open = '''        if database_path.exists() {
            verify_private_regular_leaf(&database_path, expected_uid)?;
        }
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let connection = Connection::open_with_flags(&database_path, flags)?;
        set_private_file_mode(&database_path)?;
        verify_private_regular_leaf(&database_path, expected_uid)?;
        configure_connection(&connection)?;
        acquire_exclusive_process_lock(&connection)?;

        let marker_path = marker_path(&database_path);
        let marker_existed = marker_path.exists();
        if marker_existed {
            verify_unclean_marker(&marker_path, expected_uid)?;
        } else {
            create_unclean_marker(&marker_path, expected_uid)?;
        }
'''
new_open = '''        let marker_path = marker_path(&database_path);
        let marker_preexisted = match fs::symlink_metadata(&marker_path) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let database_existed = database_path.exists();
        if marker_preexisted && !database_existed {
            return Err(SqliteStoreV2Error::RecoveryDatabaseMissing);
        }
        if database_existed {
            verify_private_regular_leaf(&database_path, expected_uid)?;
        }
        if marker_preexisted {
            verify_unclean_marker(&marker_path, expected_uid)?;
        }

        let flags = if marker_preexisted {
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW
        };
        let connection = Connection::open_with_flags(&database_path, flags)?;
        connection.busy_timeout(Duration::from_millis(0))?;

        if !marker_preexisted {
            if !database_existed {
                set_private_file_mode(&database_path)?;
            }
            verify_private_regular_leaf(&database_path, expected_uid)?;
            acquire_exclusive_process_lock(&connection)?;
            let marker_now_exists = match fs::symlink_metadata(&marker_path) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.into()),
            };
            if marker_now_exists {
                return Err(SqliteStoreV2Error::WriterMarkerChangedDuringOpen);
            }
            create_unclean_marker(&marker_path, expected_uid)?;
            configure_connection(&connection)?;
        }
        let marker_existed = marker_preexisted;
'''
replace_once(old_open, new_open, "recovery-safe open ordering")

# Explicit recovery/open errors.
error_anchor = '''    /// Database path has no parent.
    #[error("database path has no parent directory")]
    DatabasePathHasNoParent,
'''
error_new = '''    /// Database path has no parent.
    #[error("database path has no parent directory")]
    DatabasePathHasNoParent,
    /// An unclean-writer marker exists but the durable database is missing.
    #[error("recovery-required SQLite V2 database is missing")]
    RecoveryDatabaseMissing,
    /// Writer marker state changed while healthy exclusive ownership was being established.
    #[error("unclean-writer marker changed during SQLite V2 open")]
    WriterMarkerChangedDuringOpen,
'''
if "RecoveryDatabaseMissing," not in text:
    replace_once(error_anchor, error_new, "recovery open errors")

# --- Admission must re-authenticate issuance at the persistence boundary. --
old_admit = '''    pub fn admit(
        &mut self,
        admission: &AdmissionAuthorityV2,
        use_authority: &UseAuthorityV2,
        semantic: AuthenticatedAdmissionContextV2,
        slot: AuthenticatedUseSlotV2,
        persisted_at_unix_ms: u64,
    ) -> Result<AdmissionCommitV2, SqliteStoreV2Error> {
        self.require_healthy()?;
        admission.validate()?;
        admission.authority_epoch.validate_against(&self.current_epoch)?;
        use_authority.validate()?;
        semantic.validate_against(admission)?;
        slot.validate_against(use_authority)?;
        if admission.operation_id != use_authority.operation_id {
            return Err(SqliteStoreV2Error::OperationIdMismatch);
        }
        if admission.use_authority_digest != use_authority.authority_digest()? {
            return Err(SqliteStoreV2Error::UseAuthorityMismatch);
        }
        if persisted_at_unix_ms < semantic.admitted_at_unix_ms
            || persisted_at_unix_ms < self.current_epoch.established_at_unix_ms
        {
            return Err(SqliteStoreV2Error::PersistenceTimestampRegression);
        }
        let result = self.admit_inner(admission, use_authority, semantic, slot, persisted_at_unix_ms);'''
new_admit = '''    pub fn admit(
        &mut self,
        admission: &AdmissionAuthorityV2,
        use_authority: &UseAuthorityV2,
        grant: &GrantAuthorityV2,
        authenticated_issuance: AuthenticatedIssuanceContextV2,
        semantic: AuthenticatedAdmissionContextV2,
        slot: AuthenticatedUseSlotV2,
        persisted_at_unix_ms: u64,
    ) -> Result<AdmissionCommitV2, SqliteStoreV2Error> {
        self.require_healthy()?;
        admission.validate_against(
            use_authority,
            grant,
            &self.current_epoch,
            authenticated_issuance,
        )?;
        semantic.validate_against(admission)?;
        slot.validate_against(use_authority)?;
        if persisted_at_unix_ms < semantic.admitted_at_unix_ms
            || persisted_at_unix_ms < self.current_epoch.established_at_unix_ms
        {
            return Err(SqliteStoreV2Error::PersistenceTimestampRegression);
        }
        let result = self.admit_inner(
            admission,
            use_authority,
            grant,
            semantic,
            slot,
            persisted_at_unix_ms,
        );'''
replace_once(old_admit, new_admit, "authenticated admission API")

old_admit_inner_sig = '''    fn admit_inner(
        &mut self,
        admission: &AdmissionAuthorityV2,
        use_authority: &UseAuthorityV2,
        semantic: AuthenticatedAdmissionContextV2,
        slot: AuthenticatedUseSlotV2,
        persisted_at_unix_ms: u64,
    ) -> Result<AdmissionCommitV2, SqliteStoreV2Error> {'''
new_admit_inner_sig = '''    fn admit_inner(
        &mut self,
        admission: &AdmissionAuthorityV2,
        use_authority: &UseAuthorityV2,
        grant: &GrantAuthorityV2,
        semantic: AuthenticatedAdmissionContextV2,
        slot: AuthenticatedUseSlotV2,
        persisted_at_unix_ms: u64,
    ) -> Result<AdmissionCommitV2, SqliteStoreV2Error> {'''
replace_once(old_admit_inner_sig, new_admit_inner_sig, "admit_inner grant parameter")

# Replace the positional draft insert with an explicit named mapping. The sixteenth value is now
# real GrantAuthorityV2 bytes, not a compatibility sentinel.
old_insert = '''        transaction.execute(
            "INSERT INTO admissions VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                &admission.operation_id[..],
                &admission.raw_admission_digest[..],
                &admission_digest[..],
                admission.canonical_bytes()?,
                &use_digest[..],
                use_authority.canonical_bytes()?,
                &slot.grant_authority_digest[..],
                &slot.raw_use_digest[..],
                i64::from(slot.use_index),
                &slot_digest[..],
                sqlite_i64(sequence, "admission_sequence")?,
                sqlite_i64(semantic.admitted_at_unix_ms, "admitted_at_unix_ms")?,
                &current_epoch.epoch_digest()?[..],
                &[0u8; 32][..],
                sqlite_i64(persisted_at_unix_ms, "persisted_at_unix_ms")?,
                // reserved compatibility field keeps explicit column count stable in this draft
                &[0u8; 32][..],
            ],
        ).or_else(|error| {
            // The draft schema has exactly 15 columns. Keep a single obvious mapping error rather
            // than silently falling back to a different insert shape.
            Err(error)
        })?;'''
new_insert = '''        transaction.execute(
            "INSERT INTO admissions(\
                operation_id, raw_admission_digest, admission_authority_digest, \
                admission_authority_bytes, use_authority_digest, use_authority_bytes, \
                grant_authority_digest, grant_authority_bytes, raw_use_digest, use_index, \
                use_slot_reservation_digest, admission_sequence, admitted_at_unix_ms, \
                authority_epoch_digest, committed_frontier_digest, persisted_at_unix_ms\
             ) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                &admission.operation_id[..],
                &admission.raw_admission_digest[..],
                &admission_digest[..],
                admission.canonical_bytes()?,
                &use_digest[..],
                use_authority.canonical_bytes()?,
                &slot.grant_authority_digest[..],
                grant.canonical_bytes()?,
                &slot.raw_use_digest[..],
                i64::from(slot.use_index),
                &slot_digest[..],
                sqlite_i64(sequence, "admission_sequence")?,
                sqlite_i64(semantic.admitted_at_unix_ms, "admitted_at_unix_ms")?,
                &current_epoch.epoch_digest()?[..],
                &[0u8; 32][..],
                sqlite_i64(persisted_at_unix_ms, "persisted_at_unix_ms")?,
            ],
        )?;'''
replace_once(old_insert, new_insert, "named 16-field admission insert")

# --- Ordinary receipts must bind the exact durable admission authority. -----
old_receipt_call = '''        let result = self.append_receipt_inner(receipt_binding(admission, semantic), event, persisted_at_unix_ms);'''
new_receipt_call = '''        let result = self.append_receipt_inner(
            admission,
            receipt_binding(admission, semantic),
            event,
            persisted_at_unix_ms,
        );'''
replace_once(old_receipt_call, new_receipt_call, "receipt call admission binding")

old_receipt_inner = '''    fn append_receipt_inner(
        &mut self,
        binding: ReceiptAdmissionBindingV1,
        event: &ReceiptEventV1,
        persisted_at_unix_ms: u64,
    ) -> Result<ReceiptCommitV2, SqliteStoreV2Error> {
        let digest = event.event_digest()?;
        let store_authority_digest = self.store_authority.authority_digest()?;
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_receipt_row(&transaction, event.operation_id, event.event_index)? {'''
new_receipt_inner = '''    fn append_receipt_inner(
        &mut self,
        admission: &AdmissionAuthorityV2,
        binding: ReceiptAdmissionBindingV1,
        event: &ReceiptEventV1,
        persisted_at_unix_ms: u64,
    ) -> Result<ReceiptCommitV2, SqliteStoreV2Error> {
        let digest = event.event_digest()?;
        let store_authority_digest = self.store_authority.authority_digest()?;
        let admission_authority_digest = admission.authority_digest()?;
        let transaction = self.connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored_admission = read_admission_row(&transaction, event.operation_id)?
            .ok_or(SqliteStoreV2Error::MissingAdmission)?;
        if stored_admission.admission_authority_digest != admission_authority_digest
            || stored_admission.raw_admission_digest != admission.raw_admission_digest
        {
            transaction.rollback()?;
            return Err(SqliteStoreV2Error::StoredAuthorityRowMismatch);
        }
        if let Some(existing) = read_receipt_row(&transaction, event.operation_id, event.event_index)? {'''
replace_once(old_receipt_inner, new_receipt_inner, "receipt exact stored admission binding")

# --- At-rest admission integrity -------------------------------------------
old_verify_admissions = '''    fn verify_admission_rows(&self) -> Result<(), SqliteStoreV2Error> {
        let mut statement = self.connection.prepare(
            "SELECT operation_id, admission_authority_digest, admission_authority_bytes, use_authority_digest, use_authority_bytes, grant_authority_digest, raw_use_digest FROM admissions ORDER BY admission_sequence",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let operation_id = fixed_16(&row.get::<_, Vec<u8>>(0)?, "operation_id")?;
            let admission_digest = fixed_32(&row.get::<_, Vec<u8>>(1)?, "admission_authority_digest")?;
            let admission: AdmissionAuthorityV2 = bincode::deserialize(&row.get::<_, Vec<u8>>(2)?)?;
            let use_digest = fixed_32(&row.get::<_, Vec<u8>>(3)?, "use_authority_digest")?;
            let use_authority: UseAuthorityV2 = bincode::deserialize(&row.get::<_, Vec<u8>>(4)?)?;
            let grant_digest = fixed_32(&row.get::<_, Vec<u8>>(5)?, "grant_authority_digest")?;
            let raw_use_digest = fixed_32(&row.get::<_, Vec<u8>>(6)?, "raw_use_digest")?;
            admission.validate()?;
            use_authority.validate()?;
            if admission.operation_id != operation_id
                || use_authority.operation_id != operation_id
                || admission.authority_digest()? != admission_digest
                || use_authority.authority_digest()? != use_digest
                || admission.use_authority_digest != use_digest
                || use_authority.grant_authority_digest != grant_digest
                || use_authority.raw_use_digest != raw_use_digest
            {
                return Err(SqliteStoreV2Error::StoredAuthorityRowMismatch);
            }
        }
        Ok(())
    }'''
new_verify_admissions = '''    fn verify_admission_rows(&self) -> Result<(), SqliteStoreV2Error> {
        let current_epoch_digest = self.current_epoch.epoch_digest()?;
        let mut statement = self.connection.prepare(
            "SELECT operation_id, raw_admission_digest, admission_authority_digest, \
                    admission_authority_bytes, use_authority_digest, use_authority_bytes, \
                    grant_authority_digest, grant_authority_bytes, raw_use_digest, use_index, \
                    use_slot_reservation_digest, admission_sequence, admitted_at_unix_ms, \
                    authority_epoch_digest, persisted_at_unix_ms \
             FROM admissions ORDER BY admission_sequence",
        )?;
        let mut rows = statement.query([])?;
        let mut expected_sequence = 0u64;
        while let Some(row) = rows.next()? {
            let operation_id = fixed_16(&row.get::<_, Vec<u8>>(0)?, "operation_id")?;
            let raw_admission_digest = fixed_32(&row.get::<_, Vec<u8>>(1)?, "raw_admission_digest")?;
            let admission_digest = fixed_32(&row.get::<_, Vec<u8>>(2)?, "admission_authority_digest")?;
            let admission: AdmissionAuthorityV2 = bincode::deserialize(&row.get::<_, Vec<u8>>(3)?)?;
            let use_digest = fixed_32(&row.get::<_, Vec<u8>>(4)?, "use_authority_digest")?;
            let use_authority: UseAuthorityV2 = bincode::deserialize(&row.get::<_, Vec<u8>>(5)?)?;
            let grant_digest = fixed_32(&row.get::<_, Vec<u8>>(6)?, "grant_authority_digest")?;
            let grant: GrantAuthorityV2 = bincode::deserialize(&row.get::<_, Vec<u8>>(7)?)?;
            let raw_use_digest = fixed_32(&row.get::<_, Vec<u8>>(8)?, "raw_use_digest")?;
            let use_index = u32::try_from(row.get::<_, i64>(9)?)
                .map_err(|_| SqliteStoreV2Error::CorruptInteger("use_index"))?;
            let stored_slot_digest = fixed_32(
                &row.get::<_, Vec<u8>>(10)?,
                "use_slot_reservation_digest",
            )?;
            let admission_sequence = u64::try_from(row.get::<_, i64>(11)?)
                .map_err(|_| SqliteStoreV2Error::CorruptInteger("admission_sequence"))?;
            let admitted_at = u64::try_from(row.get::<_, i64>(12)?)
                .map_err(|_| SqliteStoreV2Error::CorruptInteger("admitted_at_unix_ms"))?;
            let authority_epoch_digest = fixed_32(
                &row.get::<_, Vec<u8>>(13)?,
                "authority_epoch_digest",
            )?;
            let persisted_at = u64::try_from(row.get::<_, i64>(14)?)
                .map_err(|_| SqliteStoreV2Error::CorruptInteger("persisted_at_unix_ms"))?;

            admission.validate()?;
            use_authority.validate()?;
            grant.validate()?;
            let slot = AuthenticatedUseSlotV2 {
                grant_authority_digest: grant_digest,
                raw_use_digest,
                use_index,
            };
            if admission_sequence != expected_sequence
                || admission.operation_id != operation_id
                || use_authority.operation_id != operation_id
                || admission.raw_admission_digest != raw_admission_digest
                || admission.authority_digest()? != admission_digest
                || use_authority.authority_digest()? != use_digest
                || grant.authority_digest()? != grant_digest
                || admission.use_authority_digest != use_digest
                || use_authority.grant_authority_digest != grant_digest
                || use_authority.raw_use_digest != raw_use_digest
                || slot.reservation_digest(&use_authority)? != stored_slot_digest
                || authority_epoch_digest != current_epoch_digest
                || persisted_at < admitted_at
                || persisted_at < self.current_epoch.established_at_unix_ms
            {
                return Err(SqliteStoreV2Error::StoredAuthorityRowMismatch);
            }
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or(SqliteStoreV2Error::AdmissionSequenceOverflow)?;
        }
        let next: i64 = self.connection.query_row(
            "SELECT next_admission_sequence FROM store_meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        if u64::try_from(next)
            .map_err(|_| SqliteStoreV2Error::CorruptInteger("next_admission_sequence"))?
            != expected_sequence
        {
            return Err(SqliteStoreV2Error::AdmissionSequenceMismatch);
        }
        Ok(())
    }'''
replace_once(old_verify_admissions, new_verify_admissions, "at-rest admission integrity")

# --- At-rest receipt column integrity --------------------------------------
old_verify_receipts = '''    fn verify_receipt_chains(&self) -> Result<(), SqliteStoreV2Error> {
        let mut admissions = self.connection.prepare(
            "SELECT operation_id, raw_admission_digest, admitted_at_unix_ms FROM admissions ORDER BY operation_id",
        )?;
        let mut rows = admissions.query([])?;
        while let Some(row) = rows.next()? {
            let binding = ReceiptAdmissionBindingV1 {
                operation_id: fixed_16(&row.get::<_, Vec<u8>>(0)?, "operation_id")?,
                admission_digest: fixed_32(&row.get::<_, Vec<u8>>(1)?, "raw_admission_digest")?,
                admitted_at_unix_ms: u64::try_from(row.get::<_, i64>(2)?)
                    .map_err(|_| SqliteStoreV2Error::CorruptInteger("admitted_at_unix_ms"))?,
            };
            let mut statement = self.connection.prepare(
                "SELECT event_bytes FROM receipt_events WHERE operation_id=?1 ORDER BY event_index",
            )?;
            let mut event_rows = statement.query(params![&binding.operation_id[..]])?;
            let mut previous: Option<ReceiptEventV1> = None;
            while let Some(event_row) = event_rows.next()? {
                let event: ReceiptEventV1 = bincode::deserialize(&event_row.get::<_, Vec<u8>>(0)?)?;
                match &previous {
                    None => event.validate_first(binding)?,
                    Some(prior) => event.validate_successor(binding, prior)?,
                }
                previous = Some(event);
            }
        }
        Ok(())
    }'''
new_verify_receipts = '''    fn verify_receipt_chains(&self) -> Result<(), SqliteStoreV2Error> {
        let mut admissions = self.connection.prepare(
            "SELECT operation_id, raw_admission_digest, admitted_at_unix_ms FROM admissions ORDER BY operation_id",
        )?;
        let mut rows = admissions.query([])?;
        while let Some(row) = rows.next()? {
            let binding = ReceiptAdmissionBindingV1 {
                operation_id: fixed_16(&row.get::<_, Vec<u8>>(0)?, "operation_id")?,
                admission_digest: fixed_32(&row.get::<_, Vec<u8>>(1)?, "raw_admission_digest")?,
                admitted_at_unix_ms: u64::try_from(row.get::<_, i64>(2)?)
                    .map_err(|_| SqliteStoreV2Error::CorruptInteger("admitted_at_unix_ms"))?,
            };
            let mut statement = self.connection.prepare(
                "SELECT event_index, previous_event_digest, event_digest, event_bytes, state_code, \
                        recorded_at_unix_ms, persisted_at_unix_ms \
                 FROM receipt_events WHERE operation_id=?1 ORDER BY event_index",
            )?;
            let mut event_rows = statement.query(params![&binding.operation_id[..]])?;
            let mut previous: Option<ReceiptEventV1> = None;
            while let Some(event_row) = event_rows.next()? {
                let stored_index = u32::try_from(event_row.get::<_, i64>(0)?)
                    .map_err(|_| SqliteStoreV2Error::CorruptInteger("event_index"))?;
                let stored_previous = fixed_32(
                    &event_row.get::<_, Vec<u8>>(1)?,
                    "previous_event_digest",
                )?;
                let stored_digest = fixed_32(&event_row.get::<_, Vec<u8>>(2)?, "event_digest")?;
                let event: ReceiptEventV1 = bincode::deserialize(&event_row.get::<_, Vec<u8>>(3)?)?;
                let stored_state = event_row.get::<_, i64>(4)?;
                let stored_recorded = u64::try_from(event_row.get::<_, i64>(5)?)
                    .map_err(|_| SqliteStoreV2Error::CorruptInteger("recorded_at_unix_ms"))?;
                let stored_persisted = u64::try_from(event_row.get::<_, i64>(6)?)
                    .map_err(|_| SqliteStoreV2Error::CorruptInteger("receipt persisted time"))?;
                if event.operation_id != binding.operation_id
                    || event.event_index != stored_index
                    || event.previous_event_digest != stored_previous
                    || event.event_digest()? != stored_digest
                    || receipt_state_code(event.state) != stored_state
                    || event.recorded_at_unix_ms != stored_recorded
                    || stored_persisted < stored_recorded
                {
                    return Err(SqliteStoreV2Error::StoredReceiptRowMismatch);
                }
                match &previous {
                    None => event.validate_first(binding)?,
                    Some(prior) => event.validate_successor(binding, prior)?,
                }
                previous = Some(event);
            }
        }
        Ok(())
    }'''
replace_once(old_verify_receipts, new_verify_receipts, "at-rest receipt integrity")

# New integrity errors.
frontier_error_anchor = '''    /// Stored authority row cannot be recomputed consistently.
    #[error("stored authority row mismatch")]
    StoredAuthorityRowMismatch,
'''
frontier_error_new = '''    /// Stored authority row cannot be recomputed consistently.
    #[error("stored authority row mismatch")]
    StoredAuthorityRowMismatch,
    /// Stored receipt auxiliary columns disagree with canonical event bytes.
    #[error("stored receipt row mismatch")]
    StoredReceiptRowMismatch,
    /// Durable admission sequences are not exactly gap-free or metadata disagrees.
    #[error("durable admission sequence state mismatch")]
    AdmissionSequenceMismatch,
'''
if "StoredReceiptRowMismatch," not in text:
    replace_once(frontier_error_anchor, frontier_error_new, "integrity error variants")

# --- Tests -----------------------------------------------------------------
fixture_struct_old = '''    struct Fixture {
        epoch: OperationAuthorityEpochV1,
        grant: GrantAuthorityV2,
        use_authority: UseAuthorityV2,
        admission: AdmissionAuthorityV2,
        semantic: AuthenticatedAdmissionContextV2,
        slot: AuthenticatedUseSlotV2,
    }'''
fixture_struct_new = '''    struct Fixture {
        epoch: OperationAuthorityEpochV1,
        issuance: AuthenticatedIssuanceContextV2,
        grant: GrantAuthorityV2,
        use_authority: UseAuthorityV2,
        admission: AdmissionAuthorityV2,
        semantic: AuthenticatedAdmissionContextV2,
        slot: AuthenticatedUseSlotV2,
    }'''
replace_once(fixture_struct_old, fixture_struct_new, "fixture issuance field")

fixture_init_old = '''        Fixture {
            epoch,
            grant,
            slot: AuthenticatedUseSlotV2 {'''
fixture_init_new = '''        Fixture {
            epoch,
            issuance,
            grant,
            slot: AuthenticatedUseSlotV2 {'''
replace_once(fixture_init_old, fixture_init_new, "fixture issuance initialization")

# Common admission calls.
text = text.replace(
    'store.admit(&f.admission, &f.use_authority, f.semantic, f.slot, 1_100)',
    'store.admit(\n            &f.admission,\n            &f.use_authority,\n            &f.grant,\n            f.issuance,\n            f.semantic,\n            f.slot,\n            1_100,\n        )',
)

other_admit_old = '''            store.admit(
                &other_admission,
                &other_use,
                AuthenticatedAdmissionContextV2 { raw_admission_digest: [0x53; 32], admitted_at_unix_ms: 1_060 },
                slot,
                1_120,
            ),'''
other_admit_new = '''            store.admit(
                &other_admission,
                &other_use,
                &f.grant,
                issuance,
                AuthenticatedAdmissionContextV2 {
                    raw_admission_digest: [0x53; 32],
                    admitted_at_unix_ms: 1_060,
                },
                slot,
                1_120,
            ),'''
replace_once(other_admit_old, other_admit_new, "other operation authenticated admission")

# Negative issuance test: no mutation/frontier movement on unauthenticated grant evidence.
if "fn unauthenticated_issuance_cannot_reach_durable_admission" not in text:
    needle = '''    #[test]
    fn another_operation_cannot_reuse_same_grant_slot() {'''
    test = '''    #[test]
    fn unauthenticated_issuance_cannot_reach_durable_admission() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let mut store = SqliteOperationStoreV2::open(db(&root), f.epoch.clone(), uid).unwrap();
        let before = store.current_frontier_digest().unwrap();
        let mut wrong = f.issuance;
        wrong.issuance_evidence_digest[0] ^= 1;
        assert!(matches!(
            store.admit(
                &f.admission,
                &f.use_authority,
                &f.grant,
                wrong,
                f.semantic,
                f.slot,
                1_100,
            ),
            Err(SqliteStoreV2Error::Authority(
                AuthorityV2Error::IssuanceEvidenceMismatch
            ))
        ));
        assert_eq!(before, store.current_frontier_digest().unwrap());
        store.close_clean().unwrap();
    }

    #[test]
    fn another_operation_cannot_reuse_same_grant_slot() {'''
    replace_once(needle, test, "unauthenticated issuance test")

# Negative ordinary-receipt test: same operation id but different admission authority is refused
# before any receipt/frontier mutation.
if "fn receipt_cannot_bind_forged_same_id_admission" not in text:
    needle = '''    #[test]
    fn effect_armed_then_terminal_receipt_is_hash_chained() {'''
    test = '''    #[test]
    fn receipt_cannot_bind_forged_same_id_admission() {
        let f = fixture();
        let (_temp, root, uid) = private_root();
        let (mut store, _admission_commit) = admitted_store(&f, &root, uid);
        let before = store.current_frontier_digest().unwrap();
        let mut forged = f.admission.clone();
        forged.raw_admission_digest = [0x99; 32];
        forged.validate().unwrap();
        let semantic = AuthenticatedAdmissionContextV2 {
            raw_admission_digest: forged.raw_admission_digest,
            admitted_at_unix_ms: f.semantic.admitted_at_unix_ms,
        };
        let cancelled = ReceiptEventV1 {
            schema: xenia_operation_receipt_finalization::RECEIPT_FINALIZATION_SCHEMA_V1.into(),
            admission_digest: forged.raw_admission_digest,
            operation_id: forged.operation_id,
            event_index: 0,
            previous_event_digest: [0; 32],
            state: ReceiptStateV1::CancelledBeforeEffect,
            recorded_at_unix_ms: 1_150,
            arm_authorization_digest: None,
            evidence_digest: None,
        };
        assert!(matches!(
            store.append_receipt(&forged, semantic, &cancelled, 1_160),
            Err(SqliteStoreV2Error::StoredAuthorityRowMismatch)
        ));
        assert_eq!(before, store.current_frontier_digest().unwrap());
        store.close_clean().unwrap();
    }

    #[test]
    fn effect_armed_then_terminal_receipt_is_hash_chained() {'''
    replace_once(needle, test, "forged receipt admission test")

# Guardrails for the intended final source.
for forbidden in (
    "reserved compatibility field keeps explicit column count stable in this draft",
    "Keep a single obvious mapping error",
):
    if forbidden in text:
        raise SystemExit(f"obsolete draft text remains: {forbidden}")

required = (
    "grant_authority_bytes BLOB NOT NULL",
    "grant: &GrantAuthorityV2",
    "authenticated_issuance: AuthenticatedIssuanceContextV2",
    "admission.validate_against(",
    "GrantAuthorityV2 = bincode::deserialize",
    "StoredReceiptRowMismatch",
    "RecoveryDatabaseMissing",
    "OpenFlags::SQLITE_OPEN_READ_ONLY",
    "fn unauthenticated_issuance_cannot_reach_durable_admission",
    "fn receipt_cannot_bind_forged_same_id_admission",
)
for item in required:
    if item not in text:
        raise SystemExit(f"required hardened source fragment missing: {item}")

TARGET.write_text(text)
print("sqlite-v2-pre-pr-repair: OK")
