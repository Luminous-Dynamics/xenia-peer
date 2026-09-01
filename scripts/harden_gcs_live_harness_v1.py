#!/usr/bin/env python3
from pathlib import Path

path = Path("experimental/xenia-operation-authority-retention-gcs-live-harness/src/lib.rs")
text = path.read_text()

old_identity = '''        if bucket.name != bucket_resource_v1(config.bucket_name())
            || bucket.project != format!("projects/{}", config.project_id())
            || bucket.location != config.location()
        {
            return Err("qualification bucket identity/project/location mismatch".into());
        }
'''
new_identity = '''        let expected_project = format!("projects/{}", config.project_number());
        let expected_name_suffix = format!("/buckets/{}", config.bucket_name());
        if bucket.bucket_id != config.bucket_name()
            || bucket.project != expected_project
            || !bucket.name.ends_with(&expected_name_suffix)
            || !bucket.location.eq_ignore_ascii_case(config.location())
        {
            return Err("qualification bucket identity/project/location mismatch".into());
        }
'''

old_retention = '''        let with_policy = control
            .update_bucket()
            .set_bucket(bucket.set_retention_policy(retention))
            .set_if_metageneration_match(bucket.metageneration)
'''
new_retention = '''        let metageneration = bucket.metageneration;
        let with_policy = control
            .update_bucket()
            .set_bucket(bucket.set_retention_policy(retention))
            .set_if_metageneration_match(metageneration)
'''

changed = False
if old_identity in text:
    text = text.replace(old_identity, new_identity, 1)
    changed = True
elif new_identity not in text:
    raise SystemExit("identity verifier is neither original nor hardened form")

if old_retention in text:
    text = text.replace(old_retention, new_retention, 1)
    changed = True
elif new_retention not in text:
    raise SystemExit("retention update is neither original nor hardened form")

if changed:
    path.write_text(text)
    print("hardened live harness source")
else:
    print("live harness source already hardened")
