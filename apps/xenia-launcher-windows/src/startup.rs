// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Start-at-login integration via the per-user Run registry key
//! (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) -- the standard,
//! no-elevation-required mechanism for "launch this when I sign in."
//! Deliberately not a Windows *service*: a service runs before login and
//! under a different account by default, which is a materially different
//! (and more privileged) commitment than "start my own tray app when I
//! sign in" -- out of scope for this launcher unless a real need for it
//! shows up.

use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey,
    RegCreateKeyExW, RegDeleteValueW, RegSetValueExW,
};
use windows::core::HSTRING;

const RUN_KEY_PATH: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const VALUE_NAME: &str = "Xenia Launcher";

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("Windows registry operation failed: {0:?}")]
    Registry(WIN32_ERROR),
    #[error("couldn't determine this launcher's own executable path: {0}")]
    CurrentExe(#[source] std::io::Error),
}

/// Register (or, if `enabled` is `false`, unregister) launching this
/// launcher's own executable at login.
pub fn set_enabled(enabled: bool) -> Result<(), StartupError> {
    let key = open_run_key()?;
    let result = if enabled {
        let exe = std::env::current_exe().map_err(StartupError::CurrentExe)?;
        // Quoted: a path containing a space is otherwise ambiguous to the
        // Run key's own command-line parsing.
        let command = format!("\"{}\"", exe.display());
        let bytes = command_bytes(&command);
        unsafe { RegSetValueExW(key, &HSTRING::from(VALUE_NAME), None, REG_SZ, Some(&bytes)) }
    } else {
        match unsafe { RegDeleteValueW(key, &HSTRING::from(VALUE_NAME)) } {
            // Already absent is success from this function's point of
            // view -- the caller asked for "not registered," and it is.
            WIN32_ERROR(2) => WIN32_ERROR(0), // ERROR_FILE_NOT_FOUND
            other => other,
        }
    };
    unsafe {
        let _ = RegCloseKey(key);
    }
    check(result)
}

/// Whether start-at-login is currently registered, purely by checking
/// whether the value exists -- doesn't compare its content against the
/// current executable path (a stale entry pointing at a moved/old binary
/// is still "enabled" from the user's point of view; re-running
/// `set_enabled(true)` after moving the install directory is how that
/// gets corrected, not a separate repair path here).
pub fn is_enabled() -> Result<bool, StartupError> {
    use windows::Win32::System::Registry::{KEY_QUERY_VALUE, RegOpenKeyExW, RegQueryValueExW};

    let mut key = HKEY::default();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            &HSTRING::from(RUN_KEY_PATH),
            None,
            KEY_QUERY_VALUE,
            &mut key,
        )
    };
    if result == WIN32_ERROR(2) {
        // The Run key itself doesn't exist yet -- never registered.
        return Ok(false);
    }
    check(result)?;

    let query_result =
        unsafe { RegQueryValueExW(key, &HSTRING::from(VALUE_NAME), None, None, None, None) };
    unsafe {
        let _ = RegCloseKey(key);
    }
    match query_result {
        WIN32_ERROR(0) => Ok(true),
        WIN32_ERROR(2) => Ok(false), // ERROR_FILE_NOT_FOUND: value not set
        other => check(other).map(|()| false),
    }
}

fn open_run_key() -> Result<HKEY, StartupError> {
    let mut key = HKEY::default();
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            &HSTRING::from(RUN_KEY_PATH),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        )
    };
    check(result)?;
    Ok(key)
}

fn check(result: WIN32_ERROR) -> Result<(), StartupError> {
    if result == WIN32_ERROR(0) {
        Ok(())
    } else {
        Err(StartupError::Registry(result))
    }
}

/// A `REG_SZ` value's bytes: UTF-16LE, null-terminated -- `RegSetValueExW`
/// takes the raw byte length, not a character count, and does not add its
/// own terminator. Built directly from `&str` via `encode_utf16` rather
/// than through an `HSTRING` -- that type doesn't expose its raw code
/// units in this crate version, only round-trips back to a Rust `String`.
fn command_bytes(command: &str) -> Vec<u8> {
    let wide: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();
    wide.iter().flat_map(|c| c.to_le_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_bytes_are_utf16le_and_null_terminated() {
        let bytes = command_bytes("\"C:\\a.exe\"");
        // Odd length would mean a missing/extra byte in a UTF-16LE stream.
        assert_eq!(bytes.len() % 2, 0);
        // Last two bytes are the null terminator.
        assert_eq!(&bytes[bytes.len() - 2..], &[0, 0]);
    }
}
