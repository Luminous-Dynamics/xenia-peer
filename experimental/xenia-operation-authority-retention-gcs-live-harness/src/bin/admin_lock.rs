// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use google_cloud_storage::client::StorageControl;
use std::error::Error;
use xenia_operation_authority_retention_gcs_live_harness::{
    BoundLivePrincipalsV1, cloud::lock_retention_policy_v1,
};
use xenia_operation_authority_retention_gcs_live_qualification::GcsLiveQualificationConfigV1;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = GcsLiveQualificationConfigV1::from_current_environment()?;
    let principals = BoundLivePrincipalsV1::from_current_environment(&config)?;
    let control = StorageControl::builder().build().await?;
    let bucket = lock_retention_policy_v1(&control, &config).await?;
    println!("PHASE=admin-lock");
    println!("BUCKET={}", config.bucket_name());
    println!("EXPECTED_ADMIN_MEMBER={}", principals.admin_member());
    println!("RETENTION_SECONDS={}", config.retention_seconds());
    println!("METAGENERATION={}", bucket.metageneration);
    println!("RESULT=PASS_IRREVERSIBLE_LOCK");
    Ok(())
}
