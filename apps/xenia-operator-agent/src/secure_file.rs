// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Filesystem helpers for the sensitive files this agent owns (identity,
//! pairing token, host-trust pin store): atomic creation with owner-only
//! (`0600`) permissions set *at creation*, never chmod'd afterward, and
//! refusal to trust an existing path unless it's a regular file owned by
//! this process's user. See `main.rs`'s module doc comment for why.

use std::path::Path;

/// Load `path`'s contents if it exists and is safe to trust, or generate
/// and atomically persist a fresh file (`0600`, no chmod-after-write
/// window) if it doesn't exist yet, returning `generate()`'s output. For
/// files with fixed content decided once at creation (the identity and
/// token files) -- see [`secure_overwrite`] for files that are legitimately
/// updated later (the host-trust pin store).
pub fn load_or_create_secure_file(
    path: &Path,
    generate: impl FnOnce() -> Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    match secure_create_new(path) {
        Ok(mut file) => {
            use std::io::Write;
            let contents = generate();
            file.write_all(&contents)?;
            Ok(contents)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            check_existing_file_is_safe(path)?;
            Ok(std::fs::read(path)?)
        }
        Err(e) => Err(e.into()),
    }
}

/// Load `path`'s contents if it exists (checked safe first), or `None` if
/// it doesn't exist yet -- the read-only half of the pin-store's
/// load-then-maybe-[`secure_overwrite`] pattern.
pub fn read_secure_file_if_exists(
    path: &Path,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(None);
    }
    check_existing_file_is_safe(path)?;
    Ok(Some(std::fs::read(path)?))
}

/// Atomically replace `path`'s contents with `contents`, for a file that's
/// legitimately updated over its lifetime (unlike the identity/token
/// files, which are generated once and never rewritten). Writes to a fresh
/// sibling temp file with owner-only permissions set at creation, then
/// renames it over `path` -- `rename` is atomic within a filesystem, so
/// there is no window where `path` holds a partially-written file, and no
/// window where it's briefly world/group-readable. If `path` already
/// exists, it's checked safe (regular file, owned by this process's user)
/// before being replaced.
pub fn secure_overwrite(path: &Path, contents: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        check_existing_file_is_safe(path)?;
    }
    let parent = path
        .parent()
        .ok_or("secure_overwrite: path has no parent directory")?;
    let tmp_path = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("secure-overwrite"),
        rand::random::<u64>()
    ));
    {
        use std::io::Write;
        let mut tmp = secure_create_new(&tmp_path)?;
        tmp.write_all(contents)?;
        tmp.sync_all()?;
    }
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

#[cfg(unix)]
fn secure_create_new(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}
#[cfg(not(unix))]
fn secure_create_new(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

#[cfg(unix)]
fn check_existing_file_is_safe(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "{} is a symlink -- refusing to use it for sensitive material",
            path.display()
        )
        .into());
    }
    if !meta.is_file() {
        return Err(format!("{} is not a regular file", path.display()).into());
    }
    let owner_uid = meta.uid();
    let current_uid = rustix::process::getuid().as_raw();
    if owner_uid != current_uid {
        return Err(format!(
            "{} is owned by uid {owner_uid}, not this process's uid {current_uid} -- refusing to use it",
            path.display()
        )
        .into());
    }
    // Re-tighten permissions in case they drifted since creation (defense
    // in depth).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
#[cfg(not(unix))]
fn check_existing_file_is_safe(_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "xenia-operator-agent-secure-file-test-{label}-{}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn load_or_create_generates_once_and_reuses_thereafter() {
        let dir = temp_dir("create-reuse");
        let path = dir.join("f");
        let a = load_or_create_secure_file(&path, || b"generated".to_vec()).unwrap();
        let b =
            load_or_create_secure_file(&path, || b"different-if-called-again".to_vec()).unwrap();
        assert_eq!(a, b"generated");
        assert_eq!(b, b"generated", "second call must reuse, not regenerate");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_if_exists_distinguishes_absent_from_present() {
        let dir = temp_dir("read-if-exists");
        let path = dir.join("f");
        assert_eq!(read_secure_file_if_exists(&path).unwrap(), None);
        secure_overwrite(&path, b"hello").unwrap();
        assert_eq!(
            read_secure_file_if_exists(&path).unwrap(),
            Some(b"hello".to_vec())
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn secure_overwrite_replaces_contents_and_is_atomic_in_shape() {
        let dir = temp_dir("overwrite");
        let path = dir.join("f");
        secure_overwrite(&path, b"first").unwrap();
        secure_overwrite(&path, b"second").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
        // No leftover temp files.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "leftover temp files: {leftovers:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn overwrite_target_gets_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("overwrite-perms");
        let path = dir.join("f");
        secure_overwrite(&path, b"data").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }
}
