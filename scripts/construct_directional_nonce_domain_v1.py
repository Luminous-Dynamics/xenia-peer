#!/usr/bin/env python3
"""Construct the bounded DND-001 directional sender nonce-domain repair.

This script is exact-source and fail-closed. It accepts only the reviewed main
blobs for xenia-peer-core/session.rs, xenia-peer/main.rs, and xenia-viewer/main.rs,
then applies the minimal role-bound sender-domain transformation. It does not
commit or push anything.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

BASE_SHA = "af4fcefc6d4cc7c3f74a3ca48f26abcd97d1e930"
FILES = {
    Path("crates/xenia-peer-core/src/session.rs"): "c5af3fb533652a7125b9831a0defa9e9df20320e",
    Path("apps/xenia-peer/src/main.rs"): "8212d35f148dd8eb16248e7c7a10bdb4dce0492c",
    Path("apps/xenia-viewer/src/main.rs"): "84f959252eaa40f9438ed485ebea494db519d8d7",
}


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def read_exact(path: Path) -> str:
    raw = path.read_bytes()
    actual = git_blob_sha1(raw)
    expected = FILES[path]
    if actual != expected:
        raise SystemExit(f"{path}: unexpected blob {actual}; expected {expected}")
    return raw.decode()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    session_path = Path("crates/xenia-peer-core/src/session.rs")
    daemon_path = Path("apps/xenia-peer/src/main.rs")
    viewer_path = Path("apps/xenia-viewer/src/main.rs")

    session = read_exact(session_path)
    daemon = read_exact(daemon_path)
    viewer = read_exact(viewer_path)

    role_anchor = """pub enum SessionRole {\n    /// Captures frames, accepts input. The side running on the\n    /// machine being controlled.\n    Host,\n    /// Renders frames, sends input. The side running on the\n    /// technician's device.\n    Viewer,\n}\n\n"""
    role_replacement = role_anchor + """/// Version-1 sender-role tags carried in nonce byte 0.\n///\n/// `xenia-wire` authenticates a 12-byte nonce whose first six bytes are the\n/// sender source prefix. Host and viewer currently share symmetric lane keys\n/// and independent sender counters, so their sealing domains MUST be disjoint.\n/// Reserving the first carried source byte for the role makes cross-direction\n/// prefix equality impossible without changing envelope bytes or the KDF.\nconst HOST_SENDER_DOMAIN_TAG_V1: u8 = 0x48;\nconst VIEWER_SENDER_DOMAIN_TAG_V1: u8 = 0x56;\n\nimpl SessionRole {\n    /// Derive this sealing role's literal wire `source_id` from a shared\n    /// connection source-domain root.\n    ///\n    /// Only `source_id[0..6]` is carried in the AEAD nonce. Byte 0 is therefore\n    /// overwritten with a role-exclusive tag while bytes 1..7 retain the\n    /// configured root metadata. The host/viewer nonce prefixes are disjoint\n    /// even if the two configured roots accidentally differ.\n    pub fn sender_source_id(self, mut source_domain_root: [u8; 8]) -> [u8; 8] {\n        source_domain_root[0] = match self {\n            Self::Host => HOST_SENDER_DOMAIN_TAG_V1,\n            Self::Viewer => VIEWER_SENDER_DOMAIN_TAG_V1,\n        };\n        source_domain_root\n    }\n}\n\n"""
    session = replace_once(session, role_anchor, role_replacement, "role-bound sender domain")

    fixture_anchor = """impl LaneSession {\n    /// Construct a lane-separated session with deterministic source metadata.\n    pub fn with_fixture(source_id: [u8; 8], epoch: u8) -> Self {\n"""
    fixture_replacement = """impl LaneSession {\n    /// Construct a production lane-separated session from a shared connection\n    /// source-domain root and the local sealing role.\n    ///\n    /// The literal `source_id` installed into every lane is role-bound before\n    /// any AEAD key is installed, satisfying xenia-wire E-03-001 directional\n    /// nonce-domain separation while keeping the existing envelope format.\n    pub fn with_source_domain_root(\n        source_domain_root: [u8; 8],\n        epoch: u8,\n        role: SessionRole,\n    ) -> Self {\n        Self::with_fixture(role.sender_source_id(source_domain_root), epoch)\n    }\n\n    /// Construct a lane-separated session with an exact literal `source_id`.\n    ///\n    /// This raw compatibility/test constructor does not provide directional\n    /// sender-domain separation by itself. Production bidirectional peers must\n    /// use [`Self::with_source_domain_root`] instead.\n    pub fn with_fixture(source_id: [u8; 8], epoch: u8) -> Self {\n"""
    session = replace_once(session, fixture_anchor, fixture_replacement, "production role-bound constructor")

    tests_anchor = """#[cfg(test)]\nmod tests {\n    use super::*;\n\n    fn fixture_key() -> [u8; 32] {\n"""
    tests_replacement = """#[cfg(test)]\nmod tests {\n    use super::*;\n\n    #[test]\n    fn role_bound_sender_prefixes_are_unconditionally_cross_direction_disjoint() {\n        let host = SessionRole::Host.sender_source_id([0x11; 8]);\n        let viewer = SessionRole::Viewer.sender_source_id([0xEE; 8]);\n\n        assert_eq!(host[0], HOST_SENDER_DOMAIN_TAG_V1);\n        assert_eq!(viewer[0], VIEWER_SENDER_DOMAIN_TAG_V1);\n        assert_ne!(&host[..6], &viewer[..6]);\n    }\n\n    #[test]\n    fn role_bound_rekey_seq_zero_control_nonces_do_not_collide() {\n        let root = [0x78, 0x65, 0x6e, 0x69, 0x61, 0x70, 0x68, 0x01];\n        let mut host = LaneSession::with_source_domain_root(root, 0x01, SessionRole::Host);\n        let mut viewer =\n            LaneSession::with_source_domain_root(root, 0x01, SessionRole::Viewer);\n\n        let old_key = [0x31; 32];\n        let new_key = [0x42; 32];\n        host.control.install_key(old_key);\n        viewer.control.install_key(old_key);\n\n        // Model the host Proposal under K_n before both sides install K_{n+1}.\n        let _old_proposal = host\n            .control\n            .seal(b\"proposal-under-old-key\", xenia_wire::PAYLOAD_TYPE_FRAME)\n            .unwrap();\n        host.control.install_key(new_key);\n        viewer.control.install_key(new_key);\n\n        // Both independent sender counters are now zero under the same key.\n        // This is the exact dangerous shape from DND-001: viewer Ack seq0 and\n        // the host's first subsequent control RawFrame seq0.\n        let viewer_ack = viewer\n            .control\n            .seal(b\"viewer-ack\", xenia_wire::PAYLOAD_TYPE_FRAME)\n            .unwrap();\n        let host_next_control = host\n            .control\n            .seal(b\"host-next-proposal\", xenia_wire::PAYLOAD_TYPE_FRAME)\n            .unwrap();\n\n        assert_eq!(&viewer_ack[6..12], &host_next_control[6..12]);\n        assert_eq!(&viewer_ack[8..12], &[0, 0, 0, 0]);\n        assert_ne!(&viewer_ack[..6], &host_next_control[..6]);\n        assert_ne!(&viewer_ack[..12], &host_next_control[..12]);\n    }\n\n    fn fixture_key() -> [u8; 32] {\n"""
    session = replace_once(session, tests_anchor, tests_replacement, "directional nonce regressions")

    daemon_arg_anchor = """    #[arg(long, default_value = \"7878656e69617068\")]\n    source_id_hex: String,\n"""
    daemon_arg_replacement = """    /// Shared connection source-domain root (hex, 16 chars). The daemon does\n    /// not install this literal value as its AEAD sender source ID: byte 0 is\n    /// replaced by the Host role tag before sealing. Use the same root on the\n    /// viewer so future strict expected-domain checks can derive each role.\n    #[arg(long, default_value = \"7878656e69617068\")]\n    source_id_hex: String,\n"""
    daemon = replace_once(daemon, daemon_arg_anchor, daemon_arg_replacement, "daemon source-domain CLI docs")
    daemon_session_anchor = """        let mut session = LaneSession::with_fixture(source_id, args.epoch);\n"""
    daemon_session_replacement = """        let mut session = LaneSession::with_source_domain_root(\n            source_id,\n            args.epoch,\n            xenia_peer_core::SessionRole::Host,\n        );\n"""
    daemon = replace_once(daemon, daemon_session_anchor, daemon_session_replacement, "daemon role-bound LaneSession")

    viewer_arg_anchor = """    /// Fixed source_id (hex, 16 chars). MUST match daemon.\n    #[arg(long, default_value = \"7878656e69617068\")]\n    source_id_hex: String,\n"""
    viewer_arg_replacement = """    /// Shared connection source-domain root (hex, 16 chars). Keep this root in\n    /// sync with the daemon, but it is NOT installed literally as the viewer's\n    /// AEAD sender source ID: byte 0 is replaced by the Viewer role tag so the\n    /// two sealing directions have disjoint nonce prefixes.\n    #[arg(long, default_value = \"7878656e69617068\")]\n    source_id_hex: String,\n"""
    viewer = replace_once(viewer, viewer_arg_anchor, viewer_arg_replacement, "viewer source-domain CLI docs")

    viewer_session_anchor = """    let mut session = LaneSession::with_fixture(source_id, args.epoch);\n"""
    viewer_count = viewer.count(viewer_session_anchor)
    if viewer_count != 2:
        raise SystemExit(f"viewer role-bound LaneSession: expected 2 source anchors, found {viewer_count}")
    viewer = viewer.replace(
        viewer_session_anchor,
        """    let mut session = LaneSession::with_source_domain_root(\n        source_id,\n        args.epoch,\n        xenia_peer_core::SessionRole::Viewer,\n    );\n""",
        2,
    )

    session_path.write_text(session)
    daemon_path.write_text(daemon)
    viewer_path.write_text(viewer)


if __name__ == "__main__":
    main()
