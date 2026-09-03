#!/usr/bin/env python3
"""Construct the bounded GUI viewer rekey Ack-delivery barrier candidate.

This script is intentionally exact-source and fail-closed.  It accepts only the
qualified xenia-peer #229 viewer source blob and applies a small set of reviewed
text transformations.  It does not commit or push anything.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

PATH = Path("apps/xenia-viewer/src/main.rs")
EXPECTED_SHA1 = "84f959252eaa40f9438ed485ebea494db519d8d7"


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def replace_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{label}: expected exactly one source anchor, found {count}")
    return text.replace(old, new, 1)


def main() -> None:
    raw = PATH.read_bytes()
    actual = git_blob_sha1(raw)
    if actual != EXPECTED_SHA1:
        raise SystemExit(
            f"refusing to transform unexpected viewer source blob: {actual} != {EXPECTED_SHA1}"
        )
    text = raw.decode()

    anchor = """impl AnySendHalf {\n    /// Mirrors `AnyTransport::close` for the post-split send half.\n    async fn close(&mut self) -> Result<(), TransportError> {\n        if let AnySendHalf::Quic { _endpoint, send } = self {\n            let finish_result = send.finish();\n            _endpoint.close().await;\n            finish_result?;\n        }\n        Ok(())\n    }\n}\n\n/// Receive-only half of a split [`AnyTransport`].\n"""
    replacement = """impl AnySendHalf {\n    /// Mirrors `AnyTransport::close` for the post-split send half.\n    async fn close(&mut self) -> Result<(), TransportError> {\n        if let AnySendHalf::Quic { _endpoint, send } = self {\n            let finish_result = send.finish();\n            _endpoint.close().await;\n            finish_result?;\n        }\n        Ok(())\n    }\n}\n\n#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]\nenum ViewerOutboundPhase {\n    #[default]\n    Stable,\n    AckDeliveryPending,\n    Dead,\n}\n\n#[derive(Debug, Default)]\nstruct ViewerOutboundAuthority {\n    phase: ViewerOutboundPhase,\n}\n\nimpl ViewerOutboundAuthority {\n    fn application_allowed(&self) -> bool {\n        self.phase == ViewerOutboundPhase::Stable\n    }\n\n    fn begin_ack_delivery(&mut self) -> Result<(), &'static str> {\n        if self.phase != ViewerOutboundPhase::Stable {\n            return Err(\"viewer outbound authority is not stable\");\n        }\n        self.phase = ViewerOutboundPhase::AckDeliveryPending;\n        Ok(())\n    }\n\n    fn ack_delivered(&mut self) -> Result<(), &'static str> {\n        if self.phase != ViewerOutboundPhase::AckDeliveryPending {\n            return Err(\"viewer Ack delivery is not pending\");\n        }\n        self.phase = ViewerOutboundPhase::Stable;\n        Ok(())\n    }\n\n    fn fail_closed(&mut self) {\n        self.phase = ViewerOutboundPhase::Dead;\n    }\n}\n\nstruct ViewerOutbound {\n    send_half: AnySendHalf,\n    authority: ViewerOutboundAuthority,\n}\n\nimpl ViewerOutbound {\n    fn new(send_half: AnySendHalf) -> Self {\n        Self {\n            send_half,\n            authority: ViewerOutboundAuthority::default(),\n        }\n    }\n}\n\nasync fn send_viewer_application_envelope<F, E>(\n    outbound: &Arc<tokio::sync::Mutex<ViewerOutbound>>,\n    session: &Arc<tokio::sync::Mutex<LaneSession>>,\n    seal: F,\n) -> Result<(), Box<dyn std::error::Error + Send + Sync>>\nwhere\n    F: FnOnce(&mut LaneSession) -> Result<Vec<u8>, E>,\n    E: std::fmt::Display,\n{\n    // This mutex is the local outbound linearization point.  Every GUI\n    // application seal+send transaction and the receiver rekey Ack transaction\n    // hold it across both nonce allocation and carrier handoff, so send order\n    // cannot diverge from the order in which new-key nonces are allocated.\n    let mut outbound = outbound.lock().await;\n    if !outbound.authority.application_allowed() {\n        return Err(\"viewer application authority unavailable during rekey Ack delivery\".into());\n    }\n    let envelope = {\n        let mut session = session.lock().await;\n        match seal(&mut session) {\n            Ok(envelope) => envelope,\n            Err(err) => {\n                outbound.authority.fail_closed();\n                return Err(format!(\"failed to seal viewer application envelope: {err}\").into());\n            }\n        }\n    };\n    if let Err(err) = outbound.send_half.send_envelope(&envelope).await {\n        outbound.authority.fail_closed();\n        return Err(Box::new(err));\n    }\n    Ok(())\n}\n\n/// Receive-only half of a split [`AnyTransport`].\n"""
    text = replace_once(text, anchor, replacement, "insert outbound authority")

    text = replace_once(
        text,
        """    send_half: &Arc<tokio::sync::Mutex<AnySendHalf>>,\n    session: &Arc<tokio::sync::Mutex<LaneSession>>,\n""",
        """    outbound: &Arc<tokio::sync::Mutex<ViewerOutbound>>,\n    session: &Arc<tokio::sync::Mutex<LaneSession>>,\n""",
        "file-transfer outbound parameter",
    )

    replacements = [
        (
            """            let envelope = session\n                .lock()\n                .await\n                .seal_file_transfer_message(reply, false)?;\n            send_half.lock().await.send_envelope(&envelope).await?;\n""",
            """            send_viewer_application_envelope(outbound, session, |session| {\n                session.seal_file_transfer_message(reply, false)\n            })\n            .await?;\n""",
            "file-transfer accept/reject reply",
        ),
        (
            """                let envelope = session\n                    .lock()\n                    .await\n                    .seal_file_transfer_message(msg, false)?;\n                send_half.lock().await.send_envelope(&envelope).await?;\n""",
            """                send_viewer_application_envelope(outbound, session, |session| {\n                    session.seal_file_transfer_message(msg, false)\n                })\n                .await?;\n""",
            "file-transfer chunk",
        ),
        (
            """            let envelope = session\n                .lock()\n                .await\n                .seal_file_transfer_message(complete, false)?;\n            send_half.lock().await.send_envelope(&envelope).await?;\n""",
            """            send_viewer_application_envelope(outbound, session, |session| {\n                session.seal_file_transfer_message(complete, false)\n            })\n            .await?;\n""",
            "file-transfer complete",
        ),
        (
            """            let envelope = session\n                .lock()\n                .await\n                .seal_file_transfer_message(verified, false)?;\n            send_half.lock().await.send_envelope(&envelope).await?;\n""",
            """            send_viewer_application_envelope(outbound, session, |session| {\n                session.seal_file_transfer_message(verified, false)\n            })\n            .await?;\n""",
            "file-transfer verified",
        ),
    ]
    for old, new, label in replacements:
        text = replace_once(text, old, new, label)

    text = replace_once(
        text,
        """    let (send_half, mut recv_half) = transport.split();\n    let session = Arc::new(tokio::sync::Mutex::new(session));\n    let send_half = Arc::new(tokio::sync::Mutex::new(send_half));\n""",
        """    let (send_half, mut recv_half) = transport.split();\n    let session = Arc::new(tokio::sync::Mutex::new(session));\n    let outbound = Arc::new(tokio::sync::Mutex::new(ViewerOutbound::new(send_half)));\n""",
        "create unified outbound owner",
    )

    old_clone = """        let session = Arc::clone(&session);\n        let send_half = Arc::clone(&send_half);\n        let mut surface_ready = surface_ready_rx.clone();\n"""
    if text.count(old_clone) != 2:
        raise SystemExit(f"application producer clone anchor: expected 2, found {text.count(old_clone)}")
    text = text.replace(
        old_clone,
        """        let session = Arc::clone(&session);\n        let outbound = Arc::clone(&outbound);\n        let mut surface_ready = surface_ready_rx.clone();\n""",
        2,
    )

    text = replace_once(
        text,
        """                let envelope = {\n                    let mut session = session.lock().await;\n                    match session.seal_input_event(payload) {\n                        Ok(envelope) => envelope,\n                        Err(err) => {\n                            warn!(error = %err, \"failed to seal captured input event\");\n                            continue;\n                        }\n                    }\n                };\n                if let Err(err) = send_half.lock().await.send_envelope(&envelope).await {\n                    info!(error = %err, \"input send loop ending (daemon disconnected)\");\n                    break;\n                }\n""",
        """                if let Err(err) = send_viewer_application_envelope(\n                    &outbound,\n                    &session,\n                    |session| session.seal_input_event(payload),\n                )\n                .await\n                {\n                    info!(error = %err, \"input send loop ending (outbound authority unavailable or daemon disconnected)\");\n                    break;\n                }\n""",
        "input producer transaction",
    )

    text = replace_once(
        text,
        """                let envelope = {\n                    let mut session = session.lock().await;\n                    match session.seal_clipboard_event(ClipboardContent::Text(text.clone())) {\n                        Ok(envelope) => envelope,\n                        Err(err) => {\n                            warn!(error = %err, \"failed to seal captured clipboard update\");\n                            continue;\n                        }\n                    }\n                };\n                if let Err(err) = send_half.lock().await.send_envelope(&envelope).await {\n                    info!(error = %err, \"clipboard send loop ending (daemon disconnected)\");\n                    break;\n                }\n""",
        """                if let Err(err) = send_viewer_application_envelope(\n                    &outbound,\n                    &session,\n                    |session| session.seal_clipboard_event(ClipboardContent::Text(text.clone())),\n                )\n                .await\n                {\n                    info!(error = %err, \"clipboard send loop ending (outbound authority unavailable or daemon disconnected)\");\n                    break;\n                }\n""",
        "clipboard producer transaction",
    )

    text = replace_once(
        text,
        """                message,\n                &send_half,\n                &session,\n""",
        """                message,\n                &outbound,\n                &session,\n""",
        "file-transfer handler call",
    )

    gui_rekey_old = """            let keys = epoch_state\n                .derive_and_install(&handshake.key_schedule, &context)\n                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {\n                    e.to_string().into()\n                })?;\n            session.lock().await.install_rekey_keys(&keys);\n            let ack = RawRekey::Ack {\n                key_epoch: epoch_state.current_epoch(),\n                epoch_hash,\n            }\n            .into_frame(0, 0)\n            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;\n            let envelope = session.lock().await.seal_control_frame(&ack).map_err(\n                |e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() },\n            )?;\n            send_half\n                .lock()\n                .await\n                .send_envelope(&envelope)\n                .await\n                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {\n                    e.to_string().into()\n                })?;\n            info!(key_epoch = epoch_state.current_epoch(), epoch_hash = ?epoch_hash, \"session rekey installed\");\n"""
    gui_rekey_new = """            // Linearize the receiver transition against every GUI application\n            // seal+send transaction.  Once this lock is acquired no input,\n            // clipboard, or file-transfer envelope can allocate a new-key nonce\n            // or reach the carrier until the exact Ack send outcome is known.\n            let mut outbound_tx = outbound.lock().await;\n            if let Err(err) = outbound_tx.authority.begin_ack_delivery() {\n                outbound_tx.authority.fail_closed();\n                return Err(err.into());\n            }\n            let keys = match epoch_state.derive_and_install(&handshake.key_schedule, &context) {\n                Ok(keys) => keys,\n                Err(err) => {\n                    outbound_tx.authority.fail_closed();\n                    return Err(err.to_string().into());\n                }\n            };\n            let ack = match (RawRekey::Ack {\n                key_epoch: epoch_state.current_epoch(),\n                epoch_hash,\n            })\n            .into_frame(0, 0)\n            {\n                Ok(ack) => ack,\n                Err(err) => {\n                    outbound_tx.authority.fail_closed();\n                    return Err(err.to_string().into());\n                }\n            };\n            let ack_envelope = {\n                let mut session = session.lock().await;\n                session.install_rekey_keys(&keys);\n                match session.seal_control_frame(&ack) {\n                    Ok(envelope) => envelope,\n                    Err(err) => {\n                        outbound_tx.authority.fail_closed();\n                        return Err(err.to_string().into());\n                    }\n                }\n            };\n            if let Err(err) = outbound_tx.send_half.send_envelope(&ack_envelope).await {\n                outbound_tx.authority.fail_closed();\n                return Err(format!(\n                    \"operator rekey Ack delivery failed after local key commit; fresh handshake required: {err}\"\n                )\n                .into());\n            }\n            outbound_tx\n                .authority\n                .ack_delivered()\n                .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { err.into() })?;\n            info!(key_epoch = epoch_state.current_epoch(), epoch_hash = ?epoch_hash, \"session rekey installed and Ack delivered before application authority resumed\");\n"""
    text = replace_once(text, gui_rekey_old, gui_rekey_new, "GUI rekey Ack transaction")

    pending_old = """                let envelope = session\n                    .lock()\n                    .await\n                    .seal_file_transfer_message(offer, false)\n                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {\n                        e.to_string().into()\n                    })?;\n                send_half\n                    .lock()\n                    .await\n                    .send_envelope(&envelope)\n                    .await\n                    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {\n                        e.to_string().into()\n                    })?;\n"""
    pending_new = """                // The Ack has already been handed to the carrier under the same\n                // outbound transaction lock.  Seal and send the deferred first\n                // application offer before releasing that lock, guaranteeing it\n                // cannot overtake the Ack and must consume a later nonce.\n                let envelope = {\n                    let mut session = session.lock().await;\n                    match session.seal_file_transfer_message(offer, false) {\n                        Ok(envelope) => envelope,\n                        Err(err) => {\n                            outbound_tx.authority.fail_closed();\n                            return Err(err.to_string().into());\n                        }\n                    }\n                };\n                if let Err(err) = outbound_tx.send_half.send_envelope(&envelope).await {\n                    outbound_tx.authority.fail_closed();\n                    return Err(err.to_string().into());\n                }\n"""
    text = replace_once(text, pending_old, pending_new, "deferred initial file offer")

    text = replace_once(
        text,
        """    send_half\n        .lock()\n        .await\n        .close()\n        .await\n        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;\n""",
        """    {\n        let mut outbound = outbound.lock().await;\n        outbound.authority.fail_closed();\n        outbound\n            .send_half\n            .close()\n            .await\n            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;\n    }\n""",
        "GUI outbound close",
    )

    tests_anchor = """    #[test]\n    fn to_hex_encodes_lowercase_fixed_width() {\n"""
    tests_insert = """    #[test]\n    fn viewer_outbound_authority_blocks_application_during_ack_delivery() {\n        let mut authority = ViewerOutboundAuthority::default();\n        assert!(authority.application_allowed());\n        authority.begin_ack_delivery().unwrap();\n        assert!(!authority.application_allowed());\n        assert_eq!(authority.phase, ViewerOutboundPhase::AckDeliveryPending);\n        assert!(authority.begin_ack_delivery().is_err());\n        authority.ack_delivered().unwrap();\n        assert!(authority.application_allowed());\n        assert_eq!(authority.phase, ViewerOutboundPhase::Stable);\n    }\n\n    #[test]\n    fn viewer_outbound_authority_is_terminal_after_ambiguous_ack_failure() {\n        let mut authority = ViewerOutboundAuthority::default();\n        authority.begin_ack_delivery().unwrap();\n        authority.fail_closed();\n        assert_eq!(authority.phase, ViewerOutboundPhase::Dead);\n        assert!(!authority.application_allowed());\n        assert!(authority.ack_delivered().is_err());\n        assert!(authority.begin_ack_delivery().is_err());\n    }\n\n    #[test]\n    fn to_hex_encodes_lowercase_fixed_width() {\n"""
    text = replace_once(text, tests_anchor, tests_insert, "outbound phase regressions")

    forbidden = [
        "let send_half = Arc::new(tokio::sync::Mutex::new(send_half));",
        "send_half.lock().await.send_envelope(&envelope).await",
        "&Arc<tokio::sync::Mutex<AnySendHalf>>",
    ]
    for needle in forbidden:
        if needle in text:
            raise SystemExit(f"forbidden pre-barrier topology remains: {needle}")
    required = [
        "ViewerOutboundPhase::AckDeliveryPending",
        "send_viewer_application_envelope",
        "outbound_tx.send_half.send_envelope(&ack_envelope).await",
        "session.install_rekey_keys(&keys);",
        "ack_delivered()",
        "fail_closed()",
    ]
    for needle in required:
        if needle not in text:
            raise SystemExit(f"required outbound-barrier anchor missing: {needle}")

    PATH.write_text(text)
    print(f"constructed viewer outbound Ack barrier: {git_blob_sha1(PATH.read_bytes())}")


if __name__ == "__main__":
    main()
