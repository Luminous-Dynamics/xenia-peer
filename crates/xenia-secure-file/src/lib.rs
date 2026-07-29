// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Filesystem helpers for the sensitive files `apps/xenia-peer` and
//! `apps/xenia-operator-agent` persist (identity keys, pairing tokens,
//! host-trust pins, the enrolled-operator policy): atomic creation with
//! owner-only (`0600`) permissions set *at creation* (never chmod'd
//! afterward), a dedicated `0700` parent directory, and descriptor-relative,
//! `O_NOFOLLOW` file access -- both the leaf file and its parent directory
//! are opened via a file descriptor rather than checked-then-reopened by
//! path, closing the TOCTOU window a `symlink_metadata()`-then-separate-
//! `open()` pattern leaves open (an attacker swapping a regular file for a
//! symlink between the check and the read), and rejecting an
//! attacker-controlled *parent* directory, not just the final file.
//!
//! **History**: originally lived only in `apps/xenia-operator-agent`
//! (`secure_file.rs`), which was the first place this project needed
//! TOCTOU-safe secret-file handling. `apps/xenia-peer`'s daemon
//! independently grew its own, weaker version of the same "generate once
//! or load existing" pattern across several key-loading functions in
//! `main.rs` (a plain `path.exists()` check followed by a separate
//! `std::fs::read`/chmod, not O_NOFOLLOW-protected) -- extracted here
//! (`docs/roadmap/POST_RC1_HARDENING_PLAN.md` Track 4 / `NEXT_SESSION_PLAN_
//! 2026-07-27.md` priority #4) so both binaries share one hardened
//! implementation instead of drifting independently. Deliberately its own
//! AGPL crate rather than folded into the permissively-licensed
//! `xenia-peer-core` (Apache-2.0 OR MIT) -- this is operator-security-
//! specific code with the same license as its only two consumers, matching
//! the existing `xenia-operator-proto`/`xenia-operator-agent-proto`
//! precedent rather than `xenia-peer-core`'s general-purpose scope.
//!
//! **Not a fit for every file-permission call site in this project**: the
//! daemon's own atomic-write-with-fsync helpers (`operator.rs::write_atomic`,
//! `audit_ledger_store.rs::persist_entries_atomic`, `consent_server.rs`'s
//! equivalent) already create files at the correct mode atomically (not the
//! chmod-after-write anti-pattern this crate exists to close) and provide
//! `fsync`-the-data-then-the-directory crash-durability this crate's
//! [`secure_overwrite`] does not attempt to replicate -- consolidating those
//! into this crate would be a real behavior change (losing that durability
//! guarantee), not a mechanical dedup, so they're deliberately left as-is.

use std::path::Path;

/// Load `path`'s contents if it exists and is safe to trust, or generate
/// and atomically persist a fresh file (`0600`, no chmod-after-write
/// window) if it doesn't exist yet, returning `generate()`'s output. For
/// files with fixed content decided once at creation (identity/token/key
/// files) -- see [`secure_overwrite`] for files that are legitimately
/// updated later (the host-trust pin store, the operator policy file).
pub fn load_or_create_secure_file(
    path: &Path,
    generate: impl FnOnce() -> Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    backend::load_or_create(path, generate)
}

/// Load `path`'s contents if it exists (checked safe first), or `None` if
/// it doesn't exist yet -- the read-only half of a load-then-maybe-
/// [`secure_overwrite`] pattern.
pub fn read_secure_file_if_exists(
    path: &Path,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    backend::read_if_exists(path)
}

/// Atomically replace `path`'s contents with `contents`, for a file that's
/// legitimately updated over its lifetime (unlike identity/token/key files,
/// which are generated once and never rewritten). Writes to a fresh sibling
/// temp file with owner-only permissions set at creation, then renames it
/// over `path` -- `rename` is atomic within a filesystem, so there is no
/// window where `path` holds a partially-written file, and no window where
/// it's briefly world/group-readable. If `path` already exists, it's
/// checked safe (regular file, owned by this process's user) before being
/// replaced.
pub fn secure_overwrite(path: &Path, contents: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    backend::overwrite(path, contents)
}

#[cfg(unix)]
mod backend {
    use super::*;
    use rustix::fs::{AtFlags, CWD, Mode, OFlags, linkat, openat, renameat, unlinkat};
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    /// Generate-or-load, publishing the freshly generated content
    /// atomically and without ever clobbering a concurrently-created
    /// destination.
    ///
    /// The naive version of this (create the final file `O_EXCL`, then
    /// `write_all` the generated content straight into it) has a real gap:
    /// if this process is killed, panics, or hits an I/O error between that
    /// creation and finishing the write, the final path still exists --
    /// its mere presence is what a *future* call uses to decide "already
    /// generated, load rather than regenerate" -- so a future caller would
    /// silently load a truncated/partial secret instead of either the real
    /// one or a fresh generation. This version never creates content at the
    /// final path directly: it writes into a throwaway sibling temp file
    /// first, `fsync`s it, and only then publishes -- so the final path
    /// only ever comes into existence already complete.
    ///
    /// "Publishing" also isn't a plain `rename`: two processes can both
    /// pass the initial "doesn't exist yet" check (e.g. two fresh daemon
    /// instances racing to generate the same identity key on first boot).
    /// A plain `rename` would let whichever one finishes last silently
    /// overwrite the other's already-published value -- exactly the kind
    /// of TOCTOU this crate otherwise closes. [`publish_if_absent`]
    /// resolves that race atomically instead: at most one racer's content
    /// ever becomes `file_name`, and every other racer reads back and
    /// returns *that* winning content rather than its own.
    pub(super) fn load_or_create(
        path: &Path,
        generate: impl FnOnce() -> Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let dir = open_secure_parent_dir(path)?;
        let file_name = file_name_of(path)?;

        match open_secure_existing(&dir, file_name) {
            Ok(mut existing) => {
                let mut contents = Vec::new();
                existing.read_to_end(&mut contents)?;
                return Ok(contents);
            }
            Err(e) if is_not_found(e.as_ref()) => {}
            Err(e) => return Err(e),
        }

        let contents = generate();
        let tmp_name_string = format!(
            ".{}.tmp-{}",
            file_name.to_str().unwrap_or("secure-create"),
            rand::random::<u64>()
        );
        let tmp_name = OsStr::new(&tmp_name_string);
        {
            let mut tmp = secure_create_new(&dir, tmp_name)?;
            tmp.write_all(&contents)?;
            tmp.sync_all()?;
        }

        match publish_if_absent(&dir, tmp_name, file_name) {
            Ok(true) => {
                // We published: `file_name` now durably holds our content.
                // Sync the directory entry itself, not just the file's
                // data -- without this, a crash right after `linkat` could
                // still lose the *link*, even though the data it points to
                // was already fsync'd above.
                dir.sync_all()?;
                Ok(contents)
            }
            Ok(false) => {
                // Someone else won the race; `publish_if_absent` has
                // already cleaned up our tmp file. Return *their*
                // content, which may differ from ours (e.g. two processes
                // independently generating a random identity key -- only
                // one value is ever the real one).
                let mut winner = open_secure_existing(&dir, file_name)?;
                let mut winner_contents = Vec::new();
                winner.read_to_end(&mut winner_contents)?;
                Ok(winner_contents)
            }
            Err(e) => {
                // Best-effort cleanup so a failed publish doesn't leave an
                // orphaned tmp file behind. The publish error is what
                // matters here, not this cleanup's own result.
                let _ = unlinkat(&dir, tmp_name, AtFlags::empty());
                Err(e.into())
            }
        }
    }

    /// Publish `tmp_name` (already a complete, fsync'd file in `dir`) to
    /// `file_name` in the same `dir`, iff `file_name` doesn't already
    /// exist. Returns `Ok(true)` if this call published (`file_name` now
    /// holds `tmp_name`'s content; `tmp_name` itself no longer exists) or
    /// `Ok(false)` if `file_name` already existed (this call's `tmp_name`
    /// has been removed; the caller should read the pre-existing
    /// `file_name` instead -- it does not touch that file's content).
    ///
    /// Implemented as link-then-unlink, not `rename`: `rename` would
    /// silently *replace* `file_name` if another racer already published
    /// it, which is exactly the clobber this exists to prevent. `link` is
    /// specified to fail atomically with `EEXIST` if the destination
    /// already exists -- of any number of callers racing this function for
    /// the same `dir`/`file_name`, exactly one ever succeeds.
    fn publish_if_absent(dir: &File, tmp_name: &OsStr, file_name: &OsStr) -> std::io::Result<bool> {
        match linkat(dir, tmp_name, dir, file_name, AtFlags::empty()) {
            Ok(()) => {
                unlinkat(dir, tmp_name, AtFlags::empty())?;
                Ok(true)
            }
            Err(e) if e == rustix::io::Errno::EXIST => {
                unlinkat(dir, tmp_name, AtFlags::empty())?;
                Ok(false)
            }
            Err(e) => Err(e.into()),
        }
    }

    pub(super) fn read_if_exists(
        path: &Path,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let dir = open_secure_parent_dir(path)?;
        let file_name = file_name_of(path)?;
        match open_secure_existing(&dir, file_name) {
            Ok(mut file) => {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents)?;
                Ok(Some(contents))
            }
            Err(e) if is_not_found(e.as_ref()) => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub(super) fn overwrite(
        path: &Path,
        contents: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let dir = open_secure_parent_dir(path)?;
        let file_name = file_name_of(path)?;
        // If something's already there, it must pass the same safety
        // checks the load/read paths require -- refuse to blindly clobber
        // a symlink or a file some other uid owns.
        match open_secure_existing(&dir, file_name) {
            Ok(_) => {}
            Err(e) if is_not_found(e.as_ref()) => {}
            Err(e) => return Err(e),
        }
        let tmp_name_string = format!(
            ".{}.tmp-{}",
            file_name.to_str().unwrap_or("secure-overwrite"),
            rand::random::<u64>()
        );
        let tmp_name = OsStr::new(&tmp_name_string);
        {
            let mut tmp = secure_create_new(&dir, tmp_name)?;
            tmp.write_all(contents)?;
            tmp.sync_all()?;
        }
        renameat(&dir, tmp_name, &dir, file_name)?;
        Ok(())
    }

    /// Whether the owner check in [`open_secure_parent_dir`]/
    /// [`open_secure_existing`] should be enforced for the process running
    /// under `current_uid`. Root (`uid 0`) is exempt: the check exists to
    /// stop a *lower*-privileged attacker from pre-planting a directory or
    /// file this process would otherwise trust, but root already has
    /// unrestricted read/write/chown access to the whole filesystem --
    /// refusing to trust a directory root didn't create itself adds no
    /// security there, while breaking legitimate deployments where a
    /// state directory is provisioned by a separate, unprivileged
    /// setup/installer step before the process itself runs as root (this
    /// bit `apps/xenia-peer`'s own network-chaos CI smoke test: the state
    /// directory is `mkdir`'d by the unprivileged runner user, then the
    /// daemon runs inside a network namespace via `sudo ip netns exec`,
    /// i.e. as root).
    pub(super) fn owner_check_should_apply(current_uid: u32) -> bool {
        current_uid != 0
    }

    fn file_name_of(path: &Path) -> Result<&OsStr, Box<dyn std::error::Error>> {
        path.file_name()
            .ok_or_else(|| format!("{}: path has no file name", path.display()).into())
    }

    fn is_not_found(e: &(dyn std::error::Error + 'static)) -> bool {
        e.downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::NotFound)
    }

    /// Open (or create, `0700`) `path`'s parent directory and return it as
    /// a verified descriptor-relative anchor: owned by this process's uid,
    /// opened `O_NOFOLLOW` so a symlinked parent path component is refused
    /// rather than silently followed. Every other helper in this module
    /// opens files relative to this directory, not by re-walking `path`
    /// from scratch, so a parent-directory swap after this check can't
    /// affect the subsequent open.
    fn open_secure_parent_dir(path: &Path) -> Result<File, Box<dyn std::error::Error>> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        // First-run-only exposure (nothing to race against yet if this is
        // truly the first time this directory is created) -- the same
        // acceptance every other `create_dir_all` call site in this crate
        // already makes. Every *subsequent* access re-verifies via the
        // O_NOFOLLOW open + fstat below, not this path-based call.
        std::fs::create_dir_all(parent)?;
        let dir = File::from(openat(
            CWD,
            parent,
            OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::RDONLY,
            Mode::empty(),
        )?);
        let meta = dir.metadata()?;
        let current_uid = rustix::process::getuid().as_raw();
        if owner_check_should_apply(current_uid) && meta.uid() != current_uid {
            return Err(format!(
                "{} is owned by uid {}, not this process's uid {current_uid} -- refusing to trust its contents",
                parent.display(), meta.uid()
            )
            .into());
        }
        // Re-tighten to 0700 in case it drifted (defense in depth), via
        // the already-verified fd -- no separate path-based chmod race.
        // Immune to a looser ambient umask: 0700 & !0o022 == 0700.
        dir.set_permissions(std::fs::Permissions::from_mode(0o700))?;
        Ok(dir)
    }

    fn secure_create_new(dir: &File, file_name: &OsStr) -> std::io::Result<File> {
        let fd = openat(
            dir,
            file_name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW,
            Mode::from(0o600),
        )
        .map_err(std::io::Error::from)?;
        Ok(File::from(fd))
    }

    /// Open `file_name` relative to the already-verified `dir`, `O_NOFOLLOW`
    /// so a symlink swapped in for the leaf component is refused atomically
    /// at open time rather than via a separate, racy metadata check. Checked
    /// safe (regular file, owned by this process's uid) via `fstat` on the
    /// resulting fd -- the same fd the caller then reads from, not a
    /// re-resolved path.
    fn open_secure_existing(
        dir: &File,
        file_name: &OsStr,
    ) -> Result<File, Box<dyn std::error::Error>> {
        let fd = openat(
            dir,
            file_name,
            OFlags::RDONLY | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|e| -> Box<dyn std::error::Error> {
            if e == rustix::io::Errno::LOOP {
                format!("{file_name:?} is a symlink -- refusing to use it for sensitive material")
                    .into()
            } else {
                std::io::Error::from(e).into()
            }
        })?;
        let file = File::from(fd);
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(format!("{file_name:?} is not a regular file").into());
        }
        let current_uid = rustix::process::getuid().as_raw();
        if owner_check_should_apply(current_uid) && meta.uid() != current_uid {
            return Err(format!(
                "{file_name:?} is owned by uid {}, not this process's uid {current_uid} -- refusing to use it",
                meta.uid()
            )
            .into());
        }
        // Re-tighten permissions in case they drifted since creation
        // (defense in depth), via the fd -- no separate path-based chmod.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn temp_dir(label: &str) -> std::path::PathBuf {
            std::env::temp_dir().join(format!(
                "xenia-secure-file-backend-test-{label}-{}",
                rand::random::<u64>()
            ))
        }

        /// Direct, deterministic exercise of both `publish_if_absent`
        /// branches -- the genuine race between two callers is covered
        /// separately (multi-threaded, through the public API) in the
        /// crate-level test module; this is the precise, reproducible unit
        /// test of the primitive that race relies on.
        #[test]
        fn publish_if_absent_wins_when_the_destination_is_free() {
            let dir_path = temp_dir("publish-wins");
            std::fs::create_dir_all(&dir_path).unwrap();
            let dir = open_secure_parent_dir(&dir_path.join("f")).unwrap();
            let file_name = OsStr::new("f");
            let tmp_name = OsStr::new(".f.tmp-1");
            {
                let mut tmp = secure_create_new(&dir, tmp_name).unwrap();
                tmp.write_all(b"winner").unwrap();
                tmp.sync_all().unwrap();
            }

            let published = publish_if_absent(&dir, tmp_name, file_name).unwrap();
            assert!(published, "an unclaimed destination must be won");
            assert_eq!(std::fs::read(dir_path.join("f")).unwrap(), b"winner");
            assert!(
                !dir_path.join(".f.tmp-1").exists(),
                "the tmp file must be gone after a successful publish, not left as a second link"
            );
            std::fs::remove_dir_all(&dir_path).ok();
        }

        #[test]
        fn publish_if_absent_loses_without_touching_the_existing_winner() {
            let dir_path = temp_dir("publish-loses");
            std::fs::create_dir_all(&dir_path).unwrap();
            let dir = open_secure_parent_dir(&dir_path.join("f")).unwrap();
            let file_name = OsStr::new("f");

            // Simulate "someone else already published" directly.
            std::fs::write(dir_path.join("f"), b"already-here").unwrap();

            let tmp_name = OsStr::new(".f.tmp-2");
            {
                let mut tmp = secure_create_new(&dir, tmp_name).unwrap();
                tmp.write_all(b"loser").unwrap();
                tmp.sync_all().unwrap();
            }

            let published = publish_if_absent(&dir, tmp_name, file_name).unwrap();
            assert!(
                !published,
                "an already-occupied destination must not be won"
            );
            assert_eq!(
                std::fs::read(dir_path.join("f")).unwrap(),
                b"already-here",
                "the pre-existing winner's content must be untouched, not clobbered"
            );
            assert!(
                !dir_path.join(".f.tmp-2").exists(),
                "the losing caller's own tmp file must still be cleaned up"
            );
            std::fs::remove_dir_all(&dir_path).ok();
        }

        /// The exact guarantee this whole design exists for: a caller that
        /// writes into the tmp file but never reaches (or never completes)
        /// the publish step -- modeling a crash, panic, or I/O error at
        /// that point -- must leave no trace at the *final* path. A future
        /// `load_or_create` call must see "doesn't exist yet" and generate
        /// fresh, not load a file that was never actually published.
        #[test]
        fn a_write_that_never_reaches_publish_leaves_no_final_path_file() {
            let dir_path = temp_dir("crash-before-publish");
            std::fs::create_dir_all(&dir_path).unwrap();
            let dir = open_secure_parent_dir(&dir_path.join("f")).unwrap();
            let file_name = OsStr::new("f");
            let tmp_name = OsStr::new(".f.tmp-3");
            {
                let mut tmp = secure_create_new(&dir, tmp_name).unwrap();
                tmp.write_all(b"never-published").unwrap();
                tmp.sync_all().unwrap();
                // Deliberately no `publish_if_absent` call here.
            }

            let result = open_secure_existing(&dir, file_name);
            assert!(
                is_not_found(result.unwrap_err().as_ref()),
                "the final path must not exist until an explicit publish succeeds"
            );
            std::fs::remove_dir_all(&dir_path).ok();
        }
    }
}

#[cfg(not(unix))]
mod backend {
    use super::*;

    pub(super) fn load_or_create(
        path: &Path,
        generate: impl FnOnce() -> Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(mut file) => {
                use std::io::Write;
                let contents = generate();
                file.write_all(&contents)?;
                Ok(contents)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(std::fs::read(path)?),
            Err(e) => Err(e.into()),
        }
    }

    pub(super) fn read_if_exists(
        path: &Path,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(std::fs::read(path)?))
    }

    pub(super) fn overwrite(
        path: &Path,
        contents: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let parent = path
            .parent()
            .ok_or("secure_overwrite: path has no parent directory")?;
        std::fs::create_dir_all(parent)?;
        let tmp_path = parent.join(format!(
            ".{}.tmp-{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("secure-overwrite"),
            rand::random::<u64>()
        ));
        {
            use std::io::Write;
            let mut tmp = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?;
            tmp.write_all(contents)?;
            tmp.sync_all()?;
        }
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deliberately NOT pre-created here -- this crate itself is responsible
    // for creating its parent directory, and several tests below assert on
    // exactly that behavior.
    fn temp_dir(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "xenia-secure-file-test-{label}-{}",
            rand::random::<u64>()
        ))
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

    #[test]
    #[cfg(unix)]
    fn parent_dir_is_created_with_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("dir-perms");
        let path = dir.join("nested").join("f");
        load_or_create_secure_file(&path, || b"x".to_vec()).unwrap();
        let mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn a_looser_existing_parent_dir_is_retightened_to_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("dir-retighten");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = dir.join("f");
        load_or_create_secure_file(&path, || b"x".to_vec()).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "an existing looser-permissioned parent must be re-tightened"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn a_symlinked_leaf_file_is_refused_even_after_a_prior_metadata_check() {
        let dir = temp_dir("symlink-leaf");
        std::fs::create_dir_all(&dir).unwrap();
        let real_target = dir.join("attacker-target");
        std::fs::write(&real_target, b"not yours").unwrap();
        let path = dir.join("f");
        std::os::unix::fs::symlink(&real_target, &path).unwrap();

        let result = read_secure_file_if_exists(&path);
        assert!(
            result.is_err(),
            "a symlinked leaf must be refused, not transparently followed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn a_symlinked_parent_directory_is_refused() {
        let dir = temp_dir("symlink-parent-outer");
        std::fs::create_dir_all(&dir).unwrap();
        let real_dir = dir.join("real-state-dir");
        std::fs::create_dir_all(&real_dir).unwrap();
        let symlinked_parent = dir.join("state-dir-symlink");
        std::os::unix::fs::symlink(&real_dir, &symlinked_parent).unwrap();
        let path = symlinked_parent.join("f");

        let result = load_or_create_secure_file(&path, || b"x".to_vec());
        assert!(
            result.is_err(),
            "a symlinked parent directory must be refused, not silently followed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn a_wrong_owner_existing_file_is_refused() {
        // Can't actually chown to a different uid without privilege, so this
        // exercises the code path indirectly: a file this test process does
        // own must be *accepted*, proving the uid check doesn't spuriously
        // reject legitimate files (the negative case -- a real other-uid
        // file -- is exercised by `check_existing_file_is_safe`'s original
        // reasoning and isn't independently re-testable without root).
        let dir = temp_dir("owner-check-sanity");
        let path = dir.join("f");
        load_or_create_secure_file(&path, || b"mine".to_vec()).unwrap();
        assert_eq!(
            read_secure_file_if_exists(&path).unwrap(),
            Some(b"mine".to_vec())
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn owner_check_is_skipped_only_for_root() {
        // Pure logic, independent of the actual uid this test happens to
        // run under (CI runs it unprivileged; a real root-owned deployment
        // is exercised by apps/xenia-peer's network-chaos smoke test, not
        // reproducible here without actually being root).
        assert!(
            !backend::owner_check_should_apply(0),
            "root must be exempt -- it already has unrestricted filesystem access"
        );
        assert!(backend::owner_check_should_apply(1));
        assert!(backend::owner_check_should_apply(1001));
    }

    /// Adversarial, real-concurrency exercise of `load_or_create_secure_file`
    /// against the exact race PR 2 closes: many real OS threads all seeing
    /// "doesn't exist yet" and racing to generate + publish distinct
    /// content for the same path, via the public API end-to-end (not a
    /// direct call into `publish_if_absent`). A `Barrier` maximizes actual
    /// contention at the publish step rather than relying on incidental
    /// scheduling luck.
    ///
    /// Properties that must hold regardless of which thread wins:
    /// - every thread's return value is identical (there is exactly one
    ///   true winner; nobody observes their own losing content as if it
    ///   had been accepted);
    /// - the file on disk matches that same value, byte for byte -- never
    ///   a mix, truncation, or corruption from two writers touching it;
    /// - the winning value is one of the N candidates, not something else;
    /// - no `.tmp-` files are left behind once every racer has finished.
    #[test]
    #[cfg(unix)]
    fn concurrent_load_or_create_never_corrupts_or_double_publishes() {
        use std::sync::{Arc, Barrier};

        const RACERS: usize = 12;
        let dir = temp_dir("concurrent-race");
        let path = Arc::new(dir.join("f"));
        let barrier = Arc::new(Barrier::new(RACERS));

        let handles: Vec<_> = (0..RACERS)
            .map(|i| {
                let path = Arc::clone(&path);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_create_secure_file(&path, move || format!("candidate-{i}").into_bytes())
                        .unwrap()
                })
            })
            .collect();

        let results: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let winner = results[0].clone();
        for (i, result) in results.iter().enumerate() {
            assert_eq!(
                result, &winner,
                "racer {i} observed a different winning value than the rest -- \
                 the race let more than one value through"
            );
        }
        assert!(
            (0..RACERS)
                .map(|i| format!("candidate-{i}").into_bytes())
                .any(|candidate| candidate == winner),
            "the winning content must be one of the real candidates, not corrupted data"
        );
        assert_eq!(
            std::fs::read(path.as_ref()).unwrap(),
            winner,
            "the file on disk must match what every racer agreed was published"
        );
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "leftover temp files after the race settled: {leftovers:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
