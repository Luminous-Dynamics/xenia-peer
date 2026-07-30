// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Load/save this profile's [`DaemonConfig`] as JSON. Not secret material
//! (no key bytes -- see `xenia_launcher_core::config`'s own doc comment),
//! but still routed through `xenia_secure_file` for its atomic,
//! no-partial-write guarantee: a launcher crash mid-save should never
//! leave a corrupt config file behind, and reusing an already-audited
//! primitive beats a second, ad-hoc "write a file safely" implementation.

use std::path::Path;
use xenia_launcher_core::config::DaemonConfig;

pub fn load_or_default(profile_dir: &Path) -> DaemonConfig {
    let path = config_path(profile_dir);
    match xenia_secure_file::read_secure_file_if_exists(&path) {
        Ok(Some(bytes)) => match serde_json::from_slice(&bytes) {
            Ok(config) => return config,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "malformed config, using defaults")
            }
        },
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "couldn't read config, using defaults")
        }
    }
    DaemonConfig::default()
}

pub fn save(profile_dir: &Path, config: &DaemonConfig) -> Result<(), Box<dyn std::error::Error>> {
    let path = config_path(profile_dir);
    let bytes = serde_json::to_vec_pretty(config)?;
    xenia_secure_file::secure_overwrite(&path, &bytes)?;
    Ok(())
}

fn config_path(profile_dir: &Path) -> std::path::PathBuf {
    profile_dir.join("launcher-config.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_default_returns_defaults_when_nothing_is_saved_yet() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-launcher-windows-test-{}",
            std::process::id()
        ));
        let config = load_or_default(&dir);
        assert_eq!(config, DaemonConfig::default());
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-launcher-windows-test-roundtrip-{}",
            std::process::id()
        ));
        let config = DaemonConfig {
            admin_port: 9191,
            listen: "127.0.0.1:9999".to_string(),
            ..DaemonConfig::default()
        };
        save(&dir, &config).unwrap();
        let loaded = load_or_default(&dir);
        assert_eq!(loaded, config);
        std::fs::remove_dir_all(&dir).ok();
    }
}
