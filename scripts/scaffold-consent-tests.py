#!/usr/bin/env python3
"""Emit or write a Rust test skeleton for Xenia consent-state invariants."""
from __future__ import annotations

import argparse
from pathlib import Path

SKELETON = r'''//! Consent-state invariant tests for Xenia privileged sessions.
//!
//! This file is intentionally a skeleton. Wire it to the concrete session type
//! once the consent state machine lands in xenia-handshake or xenia-peer-core.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsentState {
    Idle,
    Requested,
    Presented,
    Granted,
    Active,
    Revoking,
    Revoked,
    Denied,
    Expired,
    FaultClosed,
}

fn can_transition(from: ConsentState, to: ConsentState) -> bool {
    use ConsentState::*;
    matches!(
        (from, to),
        (Idle, Requested)
            | (Requested, Presented)
            | (Presented, Granted)
            | (Presented, Denied)
            | (Granted, Active)
            | (Active, Revoking)
            | (Revoking, Revoked)
            | (Active, Expired)
            | (Requested, FaultClosed)
            | (Presented, FaultClosed)
            | (Granted, FaultClosed)
            | (Active, FaultClosed)
    )
}

#[test]
fn active_cannot_skip_presentation_and_grant() {
    use ConsentState::*;
    assert!(!can_transition(Idle, Active));
    assert!(!can_transition(Requested, Active));
    assert!(!can_transition(Presented, Active));
    assert!(can_transition(Presented, Granted));
    assert!(can_transition(Granted, Active));
}

#[test]
fn terminal_or_fault_states_stop_privilege() {
    use ConsentState::*;
    for state in [Revoked, Denied, Expired, FaultClosed] {
        assert!(!can_transition(state, Active), "{state:?} must not resume Active");
    }
}

#[test]
fn revoke_path_is_explicit_and_fail_closed() {
    use ConsentState::*;
    assert!(can_transition(Active, Revoking));
    assert!(can_transition(Revoking, Revoked));
    assert!(can_transition(Active, FaultClosed));
    assert!(!can_transition(Revoking, Active));
}
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".", help="Xenia repository root")
    parser.add_argument("--stdout", action="store_true", help="print skeleton instead of writing")
    parser.add_argument(
        "--path",
        default="xenia-peer/crates/xenia-peer-core/tests/consent_state_invariants.rs",
        help="relative output path when writing",
    )
    args = parser.parse_args()

    if args.stdout:
        print(SKELETON)
        return 0

    root = Path(args.root).resolve()
    out = root / args.path
    if out.exists():
        raise SystemExit(f"refusing to overwrite existing file: {out}")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(SKELETON, encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
