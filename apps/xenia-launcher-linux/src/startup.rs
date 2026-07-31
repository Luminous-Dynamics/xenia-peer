// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Start-at-login integration via an XDG autostart `.desktop` file
//! (`$XDG_CONFIG_HOME/autostart/xenia-launcher.desktop`, falling back to
//! `~/.config/autostart` per the XDG Base Directory spec) -- the standard,
//! desktop-environment-agnostic mechanism (GNOME/KDE/XFCE/etc. all read
//! this same directory) for "launch this when I log in." Deliberately not
//! a systemd user unit: this project already picked the equivalent
//! non-service mechanism on Windows (the per-user Run registry key, not a
//! Windows service) for the same reason -- a login-session app, not a
//! background service that should run without a session at all.

use std::path::{Path, PathBuf};

const DESKTOP_FILE_NAME: &str = "xenia-launcher.desktop";

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("couldn't determine this launcher's own executable path: {0}")]
    CurrentExe(#[source] std::io::Error),
    #[error("couldn't determine the XDG autostart directory (no XDG_CONFIG_HOME or HOME set)")]
    NoConfigHome,
    #[error("couldn't write the autostart entry: {0}")]
    Write(#[source] Box<dyn std::error::Error>),
    #[error("couldn't remove the autostart entry: {0}")]
    Remove(#[source] std::io::Error),
}

/// Register (or, if `enabled` is `false`, unregister) launching this
/// launcher's own executable at login.
pub fn set_enabled(enabled: bool) -> Result<(), StartupError> {
    let path = autostart_dir()?.join(DESKTOP_FILE_NAME);
    if enabled {
        let exe = std::env::current_exe().map_err(StartupError::CurrentExe)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StartupError::Write(Box::new(e)))?;
        }
        let contents = desktop_entry_contents(&exe);
        // Reuses xenia-secure-file's atomic overwrite for the same reason
        // config_store.rs does: a launcher crash mid-write shouldn't leave
        // a corrupt/truncated .desktop file behind.
        xenia_secure_file::secure_overwrite(&path, contents.as_bytes())
            .map_err(StartupError::Write)?;
        Ok(())
    } else {
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            // Already absent is success from this function's point of
            // view -- the caller asked for "not registered," and it is.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StartupError::Remove(e)),
        }
    }
}

/// Whether start-at-login is currently registered, purely by checking
/// whether the `.desktop` file exists -- doesn't compare its content
/// against the current executable path (a stale entry pointing at a
/// moved/old binary is still "enabled" from the user's point of view; the
/// same convention as the Windows Run-key implementation).
pub fn is_enabled() -> Result<bool, StartupError> {
    Ok(autostart_dir()?.join(DESKTOP_FILE_NAME).exists())
}

fn desktop_entry_contents(exe: &Path) -> String {
    // Quoted: a path containing a space is otherwise ambiguous to the
    // Exec key's own field-splitting rules (freedesktop Desktop Entry
    // Specification, "Exec key").
    format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Xenia Launcher\n\
         Comment=Xenia remote-support launcher (tray icon + daemon supervisor)\n\
         Exec=\"{}\"\n\
         Terminal=false\n\
         X-GNOME-Autostart-enabled=true\n",
        exe.display()
    )
}

fn autostart_dir() -> Result<PathBuf, StartupError> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|base| base.join("autostart"))
        .ok_or(StartupError::NoConfigHome)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entry_contents_quotes_the_exec_path() {
        let contents = desktop_entry_contents(Path::new("/opt/xenia/xenia-launcher"));
        assert!(contents.contains("Exec=\"/opt/xenia/xenia-launcher\""));
        assert!(contents.starts_with("[Desktop Entry]\n"));
    }
}
