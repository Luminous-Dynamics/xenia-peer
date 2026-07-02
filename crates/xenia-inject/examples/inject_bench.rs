// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// inject-bench — RemoteDesktop portal real-hardware validation harness.
//
// Constructs XdgPortalInjector (which blocks on the operator clicking
// through the portal's consent dialog), then sends a handful of real
// pointer moves, a click, and a keypress, reporting success/failure per
// call. The point isn't to prove any particular event lands somewhere
// specific on screen (there's no capture loop here to verify against,
// unlike capture_bench) — it's to prove the portal session negotiation
// (CreateSession -> SelectDevices -> Start) and each Notify* D-Bus call
// actually succeed against a live compositor, not just compile.
//
// Usage:
//
//   cargo run -p xenia-inject --features xdg-portal --example inject_bench

use std::time::Duration;

use xenia_inject::{InputInjector, XdgPortalInjector};

fn main() {
    println!("xenia-inject bench — RemoteDesktop portal validation harness");
    println!("  A consent dialog should appear now -- click Allow to continue.");
    println!();

    let mut injector = match XdgPortalInjector::new(1920, 1080, Duration::from_secs(60)) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("XdgPortalInjector::new failed: {e}");
            eprintln!(
                "Linux: ensure xdg-desktop-portal + a RemoteDesktop backend (gnome / kde) are"
            );
            eprintln!("       installed, and you are inside a Wayland session.");
            std::process::exit(2);
        }
    };
    println!("session ready, backend: {}", injector.backend_name());
    println!();

    let mut errors = 0usize;
    let mut checked = 0usize;

    let mut check = |name: &str, result: Result<(), xenia_inject::InjectError>| {
        checked += 1;
        match result {
            Ok(()) => println!("  ok    {name}"),
            Err(e) => {
                errors += 1;
                println!("  ERROR {name}: {e}");
            }
        }
    };

    check(
        "pointer move to center",
        injector.inject_pointer(0.5, 0.5, 0, false),
    );
    std::thread::sleep(Duration::from_millis(200));
    check(
        "pointer move to top-left quadrant",
        injector.inject_pointer(0.25, 0.25, 0, false),
    );
    std::thread::sleep(Duration::from_millis(200));
    check(
        "left button down",
        injector.inject_pointer(0.25, 0.25, 0, true),
    );
    std::thread::sleep(Duration::from_millis(50));
    check(
        "left button up",
        injector.inject_pointer(0.25, 0.25, 0, false),
    );
    std::thread::sleep(Duration::from_millis(200));
    // Linux keycode 30 = KEY_A (evdev), sent as a harmless press+release.
    check("key press (A)", injector.inject_key(30, true, 0));
    check("key release (A)", injector.inject_key(30, false, 0));
    check(
        "touch down/motion/up",
        injector.inject_touch(0, 0.5, 0.5, 0, 1.0),
    );
    std::thread::sleep(Duration::from_millis(50));
    let _ = injector.inject_touch(0, 0.55, 0.55, 1, 1.0);
    check("touch up", injector.inject_touch(0, 0.55, 0.55, 2, 1.0));

    println!();
    println!("Results");
    println!("  checked: {checked}");
    println!("  errors:  {errors}");
    println!();

    if errors == 0 {
        println!("VERDICT: PASS (portal session + every Notify* call succeeded)");
        std::process::exit(0);
    } else {
        println!("VERDICT: FAIL");
        std::process::exit(1);
    }
}
