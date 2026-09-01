// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

use google_cloud_storage::client::StorageControl;
use std::error::Error;
use xenia_operation_authority_retention_gcs_live_harness::{
    BoundLivePrincipalsV1, cloud::provision_reversible_v1,
};
use xenia_operation_authority_retention_gcs_live_qualification::GcsLiveQualificationConfigV1;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let config = GcsLiveQualificationConfigV1::from_current_environment()?;
    let principals = BoundLivePrincipalsV1::from_current_environment(&config)?;
    let control = StorageControl::builder().build().await?;
    let bucket = provision_reversible_v1(&control, &config, &principals).await?;
    println!("PHASE=admin-provision");
    println!("BUCKET={}", config.bucket_name());
    println!("BUCKET_RESOURCE={}", bucket.name);
    println!("METAGENERATION={}", bucket.metageneration);
    println!("RUNTIME_MEMBER={}", principals.runtime_member());
    println!("RESULT=PASS");
    Ok(())
}
