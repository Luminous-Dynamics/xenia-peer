#!/usr/bin/env python3
from pathlib import Path

TARGET = Path(__file__).parent / "src" / "lib.rs"
text = TARGET.read_text()

old_time = '''        if persisted_at_unix_ms < semantic.admitted_at_unix_ms
            || persisted_at_unix_ms < self.current_epoch.established_at_unix_ms
        {
            return Err(SqliteStoreV2Error::PersistenceTimestampRegression);
        }'''
new_time = '''        if semantic.admitted_at_unix_ms < grant.issued_at_unix_ms
            || persisted_at_unix_ms < semantic.admitted_at_unix_ms
            || persisted_at_unix_ms < self.current_epoch.established_at_unix_ms
        {
            return Err(SqliteStoreV2Error::PersistenceTimestampRegression);
        }'''
if old_time in text:
    if text.count(old_time) != 1:
        raise SystemExit("unexpected admission timestamp guard count")
    text = text.replace(old_time, new_time)
elif new_time not in text:
    raise SystemExit("admission timestamp guard form not recognized")

old_integrity = '''            admission.validate()?;
            use_authority.validate()?;
            grant.validate()?;
            let slot = AuthenticatedUseSlotV2 {'''
new_integrity = '''            admission.validate()?;
            use_authority.validate()?;
            grant.validate()?;
            admission.authority_epoch.validate_against(&self.current_epoch)?;
            grant.authority_epoch.validate_against(&self.current_epoch)?;
            let slot = AuthenticatedUseSlotV2 {'''
if old_integrity in text:
    if text.count(old_integrity) != 1:
        raise SystemExit("unexpected at-rest authority validation count")
    text = text.replace(old_integrity, new_integrity)
elif new_integrity not in text:
    raise SystemExit("at-rest authority validation form not recognized")

old_condition = '''                || authority_epoch_digest != current_epoch_digest
                || persisted_at < admitted_at
                || persisted_at < self.current_epoch.established_at_unix_ms'''
new_condition = '''                || authority_epoch_digest != current_epoch_digest
                || grant.issued_at_unix_ms < self.current_epoch.established_at_unix_ms
                || admitted_at < grant.issued_at_unix_ms
                || persisted_at < admitted_at
                || persisted_at < self.current_epoch.established_at_unix_ms'''
if old_condition in text:
    if text.count(old_condition) != 1:
        raise SystemExit("unexpected at-rest timestamp condition count")
    text = text.replace(old_condition, new_condition)
elif new_condition not in text:
    raise SystemExit("at-rest timestamp condition form not recognized")

if "admitted_at < grant.issued_at_unix_ms" not in text:
    raise SystemExit("grant/admission temporal ordering missing")
if text.count("grant.authority_epoch.validate_against(&self.current_epoch)?;") != 1:
    raise SystemExit("grant epoch local-integrity check missing or duplicated")

TARGET.write_text(text)
print("sqlite-v2-temporal-epoch-integrity: OK")
