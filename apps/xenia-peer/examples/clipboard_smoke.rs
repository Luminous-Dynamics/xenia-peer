// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Manual real-desktop smoke test for the `arboard`-backed clipboard I/O
//! added for `--clipboard`. Not run in CI (no display/compositor there).
//!
//! Verifies `arboard::Clipboard::new()/get_text()/set_text()` actually work
//! against a real Wayland or X11 session on this host, since that's the one
//! part of clipboard sync the unit tests (which only cover the wire
//! protocol) can't reach.
//!
//! Deliberately does NOT test `Clipboard::clear()`: verified live on a real
//! KDE-Wayland session that `clear()` fails to override a selection still
//! served by an earlier `set_text()` call from a different connection (it
//! returns `Ok` but a stale value keeps reading back). `set_text("")`
//! reliably overrides it instead -- see `apply_clipboard_content` in
//! `xenia-peer`/`xenia-viewer`'s `main.rs`, which uses that for
//! `ClipboardContent::Cleared` rather than `clear()`.
//!
//! Backs up the real clipboard first and restores it on exit (even on
//! panic, via a guard), and never prints the backed-up content anywhere --
//! only its byte length -- since the user's real clipboard may hold
//! something sensitive.
//!
//! Run with: `cargo run --example clipboard_smoke -p xenia-peer`

struct RestoreGuard(Option<String>);

impl Drop for RestoreGuard {
    fn drop(&mut self) {
        let Some(original) = self.0.take() else {
            return;
        };
        match arboard::Clipboard::new().and_then(|mut c| c.set_text(original)) {
            Ok(()) => println!("restored original clipboard content"),
            Err(err) => eprintln!("WARNING: failed to restore original clipboard: {err}"),
        }
    }
}

fn main() {
    let mut clipboard = arboard::Clipboard::new().expect("open clipboard");

    let original = match clipboard.get_text() {
        Ok(text) => Some(text),
        Err(arboard::Error::ContentNotAvailable) => None,
        Err(err) => panic!("failed to read original clipboard: {err}"),
    };
    println!(
        "backed up original clipboard ({} bytes, not printed)",
        original.as_ref().map_or(0, |t| t.len())
    );
    let _guard = RestoreGuard(original);

    const MARKER: &str = "xenia-clipboard-smoke-test-3f8a1c";
    clipboard.set_text(MARKER).expect("set test text");
    println!("set clipboard to test marker");

    // Re-open a fresh handle, mirroring how the daemon/viewer poll loops
    // never hold a `Clipboard` across an await point.
    let mut reopened = arboard::Clipboard::new().expect("reopen clipboard");
    let readback = reopened.get_text().expect("read back test text");
    assert_eq!(
        readback, MARKER,
        "round-tripped clipboard text did not match what was set"
    );
    println!("PASS: round-tripped test marker matches");

    // Mirrors `ClipboardContent::Cleared`'s real handling: set_text(""),
    // not clear() -- see the module doc comment for why.
    reopened.set_text(String::new()).expect("set empty text");
    let mut reopened2 = arboard::Clipboard::new().expect("reopen clipboard again");
    match reopened2.get_text() {
        Ok(text) => {
            assert!(
                text.is_empty(),
                "expected empty text after set_text(\"\"), got {} bytes",
                text.len()
            );
            println!("PASS: set_text(\"\") emptied the clipboard");
        }
        Err(arboard::Error::ContentNotAvailable) => {
            println!("PASS: set_text(\"\") left clipboard with no text content");
        }
        Err(err) => panic!("unexpected error reading cleared clipboard: {err}"),
    }

    println!("VERDICT: PASS");
    // `_guard` drops here, restoring the original content.
}
