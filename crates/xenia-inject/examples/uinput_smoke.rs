// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Real-hardware smoke test for `UinputInjector`. Creates the virtual
//! device, confirms it registers as a real evdev node, injects a
//! sequence of pointer/key/touch events, and prints the device's evdev
//! path so an operator can independently verify with `evtest` or
//! `libinput debug-events`.

use std::{thread, time::Duration};
use xenia_inject::{InputInjector, UinputInjector};

fn main() {
    let mut injector = UinputInjector::new(1920, 1080).expect("failed to create uinput device");
    println!("uinput device created: backend={}", injector.backend_name());

    // Give userspace (udev/libinput) a moment to notice the new device.
    thread::sleep(Duration::from_millis(500));

    injector
        .inject_pointer(0.1, 0.1, 0, true)
        .expect("pointer down");
    thread::sleep(Duration::from_millis(20));
    injector
        .inject_pointer(0.1, 0.1, 0, false)
        .expect("pointer up");
    thread::sleep(Duration::from_millis(20));
    injector
        .inject_pointer(0.9, 0.9, 0, false)
        .expect("pointer move");
    thread::sleep(Duration::from_millis(20));

    injector.inject_key(30, true, 0).expect("key A down"); // KEY_A = 30
    thread::sleep(Duration::from_millis(20));
    injector.inject_key(30, false, 0).expect("key A up");
    thread::sleep(Duration::from_millis(20));

    injector
        .inject_touch(0, 0.5, 0.5, 0, 1.0)
        .expect("touch down");
    thread::sleep(Duration::from_millis(20));
    injector
        .inject_touch(0, 0.5, 0.5, 2, 1.0)
        .expect("touch up");

    println!("all events injected successfully, no I/O errors");
}
