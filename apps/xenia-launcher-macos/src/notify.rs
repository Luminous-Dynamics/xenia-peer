// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Desktop notifications via the UserNotifications framework
//! (`objc2-user-notifications`) directly, rather than the `notify-rust`
//! crate used elsewhere in this session -- its macOS backend
//! (`mac-notification-sys`) has a build script that compiles real
//! Objective-C source with macOS-specific compiler flags, which cannot
//! even be type-checked on a Linux host with no Apple SDK/osxcross. The
//! `objc2-*` crates used here are pure, pre-generated Rust FFI bindings
//! with no C-compilation step, so they at least `cargo check --target
//! x86_64-apple-darwin` cleanly, confirmed before committing to this
//! design -- see this app's `Cargo.toml` doc comment.
//!
//! Every method used here was verified against the real cached
//! `objc2-user-notifications` 0.3.2 source before use, the same
//! discipline as the rest of this session's platform-specific code.
//! **What that verification cannot cover**: whether this actually shows
//! a notification on a real macOS session (authorization prompts,
//! Notification Center behavior, and Do Not Disturb interaction are all
//! unverifiable without a real Mac) -- this is compile-checked, not
//! behavior-tested.

use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
    UNUserNotificationCenter,
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Show a desktop notification. Best-effort: authorization is requested
/// on first use (fire-and-forget -- if the user denies it, later calls
/// silently produce no visible notification, which is the correct
/// behavior, not an error) and a failure to enqueue the request is
/// logged, not propagated -- a missed notification should never take
/// down the launcher.
pub fn show(title: &str, message: &str) {
    let center = UNUserNotificationCenter::currentNotificationCenter();

    request_authorization_once(&center);

    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str(title));
    content.setBody(&NSString::from_str(message));

    let identifier = format!(
        "net.mycelix.xenia.launcher.{}",
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    // `trigger: None` fires the notification immediately, matching the
    // Windows/Linux launchers' "show it now" balloon/toast semantics.
    let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
        &NSString::from_str(&identifier),
        &content,
        None,
    );

    let completion = block2::RcBlock::new(move |error: *mut objc2_foundation::NSError| {
        if !error.is_null() {
            tracing::warn!(
                "couldn't show a desktop notification (UNUserNotificationCenter declined the request)"
            );
        }
    });
    center.addNotificationRequest_withCompletionHandler(&request, Some(&completion));
}

fn request_authorization_once(center: &Retained<UNUserNotificationCenter>) {
    static REQUESTED: std::sync::Once = std::sync::Once::new();
    REQUESTED.call_once(|| {
        let options = UNAuthorizationOptions::Alert
            | UNAuthorizationOptions::Sound
            | UNAuthorizationOptions::Badge;
        let completion = block2::RcBlock::new(
            |_granted: objc2::runtime::Bool, error: *mut objc2_foundation::NSError| {
                if !error.is_null() {
                    tracing::warn!("notification authorization request failed");
                }
            },
        );
        center.requestAuthorizationWithOptions_completionHandler(options, &completion);
    });
}
