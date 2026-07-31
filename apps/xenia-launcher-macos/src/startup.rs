// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Start-at-login integration via a per-user LaunchAgent
//! (`~/Library/LaunchAgents/net.mycelix.xenia.launcher.plist`) -- the
//! standard macOS mechanism for "launch this when I log in," and the
//! macOS analog of the Windows Run-key / Linux XDG-autostart approaches
//! already used by the other two launchers. Deliberately not a
//! `launchd` *daemon* (a `LaunchDaemon` under `/Library/LaunchDaemons`,
//! which runs pre-login as root) -- same "login-session app, not a
//! background service" reasoning as the Windows/Linux launchers' own
//! non-service choices.
//!
//! Pure Rust: no AppKit/Foundation bindings needed here at all, just
//! `std::fs` and a shelled-out `launchctl` for immediate effect.

use std::path::{Path, PathBuf};

const LABEL: &str = "net.mycelix.xenia.launcher";

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("couldn't determine this launcher's own executable path: {0}")]
    CurrentExe(#[source] std::io::Error),
    #[error("couldn't determine the LaunchAgents directory (no HOME set)")]
    NoHome,
    #[error("couldn't write the LaunchAgent plist: {0}")]
    Write(#[source] Box<dyn std::error::Error>),
    #[error("couldn't remove the LaunchAgent plist: {0}")]
    Remove(#[source] std::io::Error),
}

/// Register (or, if `enabled` is `false`, unregister) launching this
/// launcher's own executable at login.
pub fn set_enabled(enabled: bool) -> Result<(), StartupError> {
    let path = launch_agents_dir()?.join(format!("{LABEL}.plist"));
    if enabled {
        let exe = std::env::current_exe().map_err(StartupError::CurrentExe)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| StartupError::Write(Box::new(e)))?;
        }
        let contents = plist_contents(&exe);
        // Reuses xenia-secure-file's atomic overwrite for the same reason
        // config_store.rs (and the Linux launcher's own .desktop write)
        // do: a launcher crash mid-write shouldn't leave a corrupt/
        // truncated plist behind.
        xenia_secure_file::secure_overwrite(&path, contents.as_bytes())
            .map_err(StartupError::Write)?;
        // Best-effort: `launchctl load` makes the change take effect
        // immediately, without needing to log out and back in. Not fatal
        // if it fails (e.g. `launchctl`'s legacy load/unload subcommands
        // behave inconsistently across macOS versions) -- the plist file
        // alone is picked up automatically at the next real login either
        // way, which is the property this function actually promises.
        run_launchctl(&["load", "-w"], &path);
        Ok(())
    } else {
        run_launchctl(&["unload", "-w"], &path);
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
/// whether the plist file exists -- doesn't compare its content against
/// the current executable path (a stale entry pointing at a moved/old
/// binary is still "enabled" from the user's point of view; the same
/// convention as the Windows/Linux implementations).
pub fn is_enabled() -> Result<bool, StartupError> {
    Ok(launch_agents_dir()?.join(format!("{LABEL}.plist")).exists())
}

fn plist_contents(exe: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"#,
        exe = xml_escape(&exe.display().to_string())
    )
}

/// Minimal XML text escaping for the one untrusted-ish value (a local
/// filesystem path) embedded in the plist -- a path containing `&`/`<`/
/// `>` would otherwise produce invalid XML.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn launch_agents_dir() -> Result<PathBuf, StartupError> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join("Library").join("LaunchAgents"))
        .ok_or(StartupError::NoHome)
}

fn run_launchctl(args: &[&str], plist_path: &Path) {
    let result = std::process::Command::new("launchctl")
        .args(args)
        .arg(plist_path)
        .output();
    match result {
        Ok(output) if !output.status.success() => {
            tracing::debug!(
                args = ?args,
                stderr = %String::from_utf8_lossy(&output.stderr),
                "launchctl reported a non-success exit -- not fatal, the plist file itself is still the source of truth"
            );
        }
        Ok(_) => {}
        Err(e) => tracing::debug!(error = %e, "couldn't run launchctl"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_contents_includes_the_exe_path_and_label() {
        let contents = plist_contents(Path::new("/opt/xenia/xenia-launcher"));
        assert!(contents.contains("<string>/opt/xenia/xenia-launcher</string>"));
        assert!(contents.contains(&format!("<string>{LABEL}</string>")));
        assert!(contents.contains("<true/>"));
    }

    #[test]
    fn xml_escape_handles_ampersand_and_angle_brackets() {
        assert_eq!(xml_escape("a & b < c > d"), "a &amp; b &lt; c &gt; d");
    }
}
