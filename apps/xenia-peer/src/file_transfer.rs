// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Daemon-side file-transfer handling, extracted from `main.rs`.
//!
//! The wire message dispatch (`handle_envelope`) is I/O-coupled (it seals and
//! sends over the transport), but the accept/reject *decision* for an incoming
//! Offer -- filename sanitization, size cap, concurrent-transfer cap -- is
//! factored into [`FileTransferState::evaluate_offer`], a pure function that is
//! unit-tested here without any transport or session.

use std::collections::HashMap;
use std::path::Path;

use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

use xenia_peer_core::transport::SendEnvelope;
use xenia_peer_core::{
    FILE_TRANSFER_CHUNK_SIZE, FileTransferMessage, IncomingFileStager, LaneSession,
};

use crate::AnySendHalf;
use crate::m1_runtime::M1RuntimeSession;

/// Cap on simultaneously-open incoming transfers. Incoming payload bytes are
/// staged to private same-directory files rather than retained in heap memory,
/// but each accepted Offer still consumes file descriptors, disk capacity, and
/// authenticated session bookkeeping until it completes or is dropped.
pub(crate) const MAX_CONCURRENT_INCOMING_TRANSFERS: usize = 8;

/// A transfer this side is sending. One at a time in this first cut --
/// `--send-file` offers a single file per daemon run.
pub(crate) struct OutgoingTransfer {
    pub(crate) transfer_id: u64,
    pub(crate) data: Vec<u8>,
    pub(crate) started: bool,
}

/// A transfer this side is receiving.
struct IncomingTransfer {
    name: String,
    expected_size: u64,
    stager: IncomingFileStager,
}

/// Per-connection file-transfer state: the single outbound transfer (if any)
/// and the set of in-flight inbound transfers.
pub(crate) struct FileTransferState {
    pub(crate) outgoing: Option<OutgoingTransfer>,
    incoming: HashMap<u64, IncomingTransfer>,
}

/// Immutable per-run configuration for inbound transfers.
#[derive(Clone, Copy)]
pub(crate) struct FileTransferConfig<'a> {
    /// Directory received files are written to; `None` disables receiving.
    pub(crate) recv_file_dir: Option<&'a Path>,
    /// Reject any offered/received file larger than this many bytes.
    pub(crate) max_bytes: u64,
}

/// The decision for an inbound Offer, computed with no I/O.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OfferDecision {
    /// Accept and stage under this sanitized bare filename.
    Accept { safe_name: String },
    /// Reject with a human-readable reason sent back to the peer.
    Reject { reason: String },
}

impl FileTransferState {
    pub(crate) fn new() -> Self {
        Self {
            outgoing: None,
            incoming: HashMap::new(),
        }
    }

    /// Decide whether to accept an inbound Offer. Pure: no transport, no
    /// filesystem, no consent gate (the gate is applied by the caller only
    /// once the decision is Accept). Encodes, in priority order: receiving
    /// disabled, unusable filename (path traversal / empty), size cap,
    /// concurrent-transfer cap.
    pub(crate) fn evaluate_offer(
        &self,
        config: &FileTransferConfig,
        name: &str,
        size: u64,
    ) -> OfferDecision {
        let reject = |reason: String| OfferDecision::Reject { reason };
        match (config.recv_file_dir, sanitize_transfer_filename(name)) {
            (None, _) => reject("file transfer is disabled on this daemon".to_string()),
            (Some(_), None) => reject("unusable filename".to_string()),
            (Some(_), Some(_)) if size > config.max_bytes => {
                reject(format!("file exceeds {}-byte cap", config.max_bytes))
            }
            (Some(_), Some(_)) if self.incoming.len() >= MAX_CONCURRENT_INCOMING_TRANSFERS => {
                reject(format!(
                    "too many concurrent transfers (max {MAX_CONCURRENT_INCOMING_TRANSFERS})"
                ))
            }
            (Some(_), Some(safe_name)) => OfferDecision::Accept { safe_name },
        }
    }
}

/// Reduce a wire-provided filename to a bare basename with no path
/// separators, so a received file always lands directly inside
/// `--recv-file-dir` and never escapes it via `..` or an absolute path.
/// Returns `None` for empty, `.`, or `..`.
pub(crate) fn sanitize_transfer_filename(name: &str) -> Option<String> {
    let candidate = Path::new(name).file_name()?.to_str()?.to_string();
    if candidate.is_empty() || candidate == "." || candidate == ".." {
        return None;
    }
    Some(candidate)
}

/// Decode and act on one file-transfer bare envelope. Runs inside the main
/// send loop (not the recv task) so it can reuse the loop's own `send_half`
/// for any reply -- see the recv task's comment on why file-transfer
/// envelopes are forwarded here rather than handled inline.
pub(crate) async fn handle_envelope(
    envelope: &[u8],
    send_half: &mut AnySendHalf,
    session: &AsyncMutex<LaneSession>,
    m1_runtime: &AsyncMutex<M1RuntimeSession>,
    state: &mut FileTransferState,
    config: &FileTransferConfig<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let message = match session.lock().await.open_file_transfer_message(envelope) {
        Ok(message) => message,
        Err(err) => {
            warn!(error = %err, "failed to open file-transfer envelope");
            return Ok(());
        }
    };
    match message {
        FileTransferMessage::Offer {
            transfer_id,
            name,
            size,
            blake3_hash,
        } => {
            let decision = state.evaluate_offer(config, &name, size);
            let reply = match decision {
                OfferDecision::Accept { safe_name } => {
                    if let Err(err) = m1_runtime.lock().await.allow_file_receive_flow() {
                        warn!(error = %err, "file transfer offer rejected by M1 consent gate");
                        FileTransferMessage::Reject {
                            transfer_id,
                            reason: "file receive is not permitted by current consent".to_string(),
                        }
                    } else {
                        let recv_dir = config
                            .recv_file_dir
                            .expect("accepted offer requires configured receive directory");
                        let dest = recv_dir.join(&safe_name);
                        match IncomingFileStager::create(&dest, size, blake3_hash) {
                            Ok(stager) => {
                                state.incoming.insert(
                                    transfer_id,
                                    IncomingTransfer {
                                        name: safe_name,
                                        expected_size: size,
                                        stager,
                                    },
                                );
                                info!(transfer_id, name, size, "file transfer offer accepted");
                                FileTransferMessage::Accept { transfer_id }
                            }
                            Err(err) => {
                                warn!(transfer_id, error = %err, "file receive staging could not be created");
                                FileTransferMessage::Reject {
                                    transfer_id,
                                    reason: "receiver could not allocate private staging"
                                        .to_string(),
                                }
                            }
                        }
                    }
                }
                OfferDecision::Reject { reason } => {
                    info!(
                        transfer_id,
                        name, size, reason, "file transfer offer rejected"
                    );
                    FileTransferMessage::Reject {
                        transfer_id,
                        reason,
                    }
                }
            };
            let envelope = session
                .lock()
                .await
                .seal_file_transfer_message(reply, true)?;
            send_half.send_envelope(&envelope).await?;
        }
        FileTransferMessage::Accept { transfer_id } => {
            let Some(transfer) = state
                .outgoing
                .as_mut()
                .filter(|t| t.transfer_id == transfer_id)
            else {
                warn!(transfer_id, "Accept for unknown/stale outgoing transfer");
                return Ok(());
            };
            transfer.started = true;
            info!(
                transfer_id,
                bytes = transfer.data.len(),
                "transfer accepted, sending chunks"
            );
            for (i, chunk) in transfer.data.chunks(FILE_TRANSFER_CHUNK_SIZE).enumerate() {
                if let Err(err) = m1_runtime.lock().await.allow_file_send_flow() {
                    warn!(error = %err, "outgoing file transfer halted by M1 consent gate");
                    return Ok(());
                }
                let offset = (i * FILE_TRANSFER_CHUNK_SIZE) as u64;
                let msg = FileTransferMessage::Chunk {
                    transfer_id,
                    offset,
                    data: chunk.to_vec(),
                };
                let envelope = session.lock().await.seal_file_transfer_message(msg, true)?;
                send_half.send_envelope(&envelope).await?;
            }
            let complete = FileTransferMessage::Complete { transfer_id };
            let envelope = session
                .lock()
                .await
                .seal_file_transfer_message(complete, true)?;
            send_half.send_envelope(&envelope).await?;
            info!(transfer_id, "all chunks sent, awaiting verification");
        }
        FileTransferMessage::Reject {
            transfer_id,
            reason,
        } => {
            if state
                .outgoing
                .as_ref()
                .is_some_and(|t| t.transfer_id == transfer_id)
            {
                warn!(transfer_id, reason, "outgoing transfer rejected by peer");
                state.outgoing = None;
            }
        }
        FileTransferMessage::Chunk {
            transfer_id,
            offset,
            data,
        } => {
            if let Err(err) = m1_runtime.lock().await.allow_file_receive_flow() {
                warn!(error = %err, "incoming file chunk rejected by M1 consent gate; dropping transfer");
                state.incoming.remove(&transfer_id);
                return Ok(());
            }
            let Some(transfer) = state.incoming.get_mut(&transfer_id) else {
                warn!(transfer_id, "chunk for unknown/stale incoming transfer");
                return Ok(());
            };
            if let Err(err) = transfer.stager.append(offset, &data) {
                warn!(transfer_id, error = %err, "invalid incoming file chunk; dropping transfer");
                state.incoming.remove(&transfer_id);
                return Ok(());
            }
        }
        FileTransferMessage::Complete { transfer_id } => {
            let Some(transfer) = state.incoming.remove(&transfer_id) else {
                warn!(transfer_id, "Complete for unknown/stale incoming transfer");
                return Ok(());
            };
            let delivery_ok = if let Err(err) = m1_runtime.lock().await.allow_file_receive_flow() {
                warn!(error = %err, "completed file transfer rejected by M1 consent gate; not published");
                false
            } else {
                match transfer.stager.finish() {
                    Ok(()) => {
                        info!(
                            transfer_id,
                            name = transfer.name,
                            bytes = transfer.expected_size,
                            "file transfer verified and persisted"
                        );
                        true
                    }
                    Err(err) => {
                        warn!(transfer_id, error = %err, "incoming file verification/publication failed");
                        false
                    }
                }
            };
            let verified = FileTransferMessage::Verified {
                transfer_id,
                ok: delivery_ok,
            };
            let envelope = session
                .lock()
                .await
                .seal_file_transfer_message(verified, true)?;
            send_half.send_envelope(&envelope).await?;
        }
        FileTransferMessage::Verified { transfer_id, ok } => {
            if state
                .outgoing
                .as_ref()
                .is_some_and(|t| t.transfer_id == transfer_id)
            {
                info!(transfer_id, ok, "outgoing transfer verification result");
                state.outgoing = None;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_path_components_to_a_bare_basename() {
        assert_eq!(
            sanitize_transfer_filename("report.pdf").as_deref(),
            Some("report.pdf")
        );
        assert_eq!(
            sanitize_transfer_filename("/etc/passwd").as_deref(),
            Some("passwd")
        );
        assert_eq!(
            sanitize_transfer_filename("../../secret").as_deref(),
            Some("secret")
        );
        assert_eq!(
            sanitize_transfer_filename("a/b/c/thing.txt").as_deref(),
            Some("thing.txt")
        );
    }

    #[test]
    fn sanitize_rejects_traversal_only_and_empty_names() {
        assert_eq!(sanitize_transfer_filename(""), None);
        assert_eq!(sanitize_transfer_filename("."), None);
        assert_eq!(sanitize_transfer_filename(".."), None);
        assert_eq!(sanitize_transfer_filename("../.."), None);
        assert_eq!(sanitize_transfer_filename("/"), None);
    }

    fn accepting_config() -> FileTransferConfig<'static> {
        FileTransferConfig {
            recv_file_dir: Some(Path::new("/tmp/inbox")),
            max_bytes: 1000,
        }
    }

    #[test]
    fn offer_rejected_when_receiving_disabled() {
        let state = FileTransferState::new();
        let config = FileTransferConfig {
            recv_file_dir: None,
            max_bytes: 1000,
        };
        assert!(matches!(
            state.evaluate_offer(&config, "file.bin", 10),
            OfferDecision::Reject { .. }
        ));
    }

    #[test]
    fn offer_rejected_for_path_traversal_name() {
        let state = FileTransferState::new();
        assert!(matches!(
            state.evaluate_offer(&accepting_config(), "..", 10),
            OfferDecision::Reject { .. }
        ));
    }

    #[test]
    fn offer_rejected_over_size_cap() {
        let state = FileTransferState::new();
        match state.evaluate_offer(&accepting_config(), "big.bin", 1001) {
            OfferDecision::Reject { reason } => assert!(reason.contains("cap")),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn offer_rejected_over_concurrent_cap() {
        let dir = std::env::temp_dir().join(format!(
            "xenia-peer-offer-cap-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&dir).unwrap();
        let mut state = FileTransferState::new();
        let empty_hash = *blake3::hash(b"").as_bytes();
        for i in 0..MAX_CONCURRENT_INCOMING_TRANSFERS as u64 {
            let path = dir.join(format!("f{i}"));
            state.incoming.insert(
                i,
                IncomingTransfer {
                    name: format!("f{i}"),
                    expected_size: 0,
                    stager: IncomingFileStager::create(&path, 0, empty_hash).unwrap(),
                },
            );
        }
        match state.evaluate_offer(&accepting_config(), "one-too-many.bin", 10) {
            OfferDecision::Reject { reason } => assert!(reason.contains("concurrent")),
            other => panic!("expected reject, got {other:?}"),
        }
        drop(state);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn offer_accepted_returns_sanitized_name() {
        let state = FileTransferState::new();
        assert_eq!(
            state.evaluate_offer(&accepting_config(), "/uploads/report.pdf", 10),
            OfferDecision::Accept {
                safe_name: "report.pdf".to_string()
            }
        );
    }
}
