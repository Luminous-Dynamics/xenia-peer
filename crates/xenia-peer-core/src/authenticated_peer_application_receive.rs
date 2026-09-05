// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Deadline-owned receive boundary for authenticated Xenia application traffic.
//!
//! [`crate::AuthenticatedPeerApplicationChannelV1`] already owns the exact
//! same-peer carrier plus xenia-wire AEAD/replay state. This module closes the
//! cancellation/reuse gap for callers that need an external authorization or
//! request deadline while waiting for one application payload.
//!
//! The public function consumes the authenticated application channel by value.
//! On success it returns both the channel and one opened payload. On any
//! deadline, carrier, domain, AEAD, replay, or other receive failure it returns
//! only an error, so a channel whose receive future may have consumed partial
//! carrier framing is dropped rather than made available for reuse.
//!
//! Because the channel is moved into the returned async future itself, dropping
//! or cancelling that outer future also drops the channel. Caller-side task
//! cancellation therefore cannot recover a possibly partially advanced carrier.

use std::{future::Future, time::Instant};

use thiserror::Error;
use tokio::time;

use crate::{
    AuthenticatedPeerApplicationChannelErrorV1, AuthenticatedPeerApplicationChannelV1,
    OpenedPeerApplicationPayloadV1, transport::Transport,
};

/// Fail-closed failures for one deadline-owned authenticated application receive.
#[derive(Debug, Error)]
pub enum AuthenticatedPeerApplicationReceiveErrorV1 {
    /// The caller-supplied monotonic receive deadline expired before one opened
    /// application payload completed safely.
    #[error("authenticated peer application receive deadline expired")]
    ReceiveDeadlineExpired,
    /// Same-peer carrier, payload-domain, AEAD, replay, or wire validation failed.
    #[error(transparent)]
    Channel(#[from] AuthenticatedPeerApplicationChannelErrorV1),
}

/// Consume one authenticated application channel while waiting for exactly one
/// opened payload before `deadline`.
///
/// On success, returns `(channel, opened_payload)` so the same channel may be
/// used for the next serial application operation.
///
/// On **any** error, no channel is returned. This is intentional: cancelling a
/// carrier receive at a deadline can leave a stream implementation after some
/// bytes of a framed envelope have already been consumed. Dropping the owned
/// channel prevents callers from treating that potentially desynchronized
/// carrier/replay state as healthy reusable authority.
///
/// The deadline is checked before the receive begins and after a successful
/// receive completes. The in-flight receive is bounded with
/// `tokio::time::timeout_at` using the same monotonic deadline.
///
/// Cancelling or dropping this entire async operation is also fail-closed: the
/// channel is owned by the future, so cancellation drops it instead of making a
/// possibly partially consumed carrier available for reuse.
///
/// This function does not interpret the application plaintext. Successful
/// output still requires higher-layer schema and authorization validation.
pub async fn recv_opened_payload_before_deadline_v1<T: Transport>(
    mut channel: AuthenticatedPeerApplicationChannelV1<T>,
    deadline: Instant,
) -> Result<
    (
        AuthenticatedPeerApplicationChannelV1<T>,
        OpenedPeerApplicationPayloadV1,
    ),
    AuthenticatedPeerApplicationReceiveErrorV1,
> {
    let opened = await_before_deadline_v1(channel.recv_opened_payload(), deadline).await??;
    if Instant::now() >= deadline {
        return Err(AuthenticatedPeerApplicationReceiveErrorV1::ReceiveDeadlineExpired);
    }
    Ok((channel, opened))
}

async fn await_before_deadline_v1<F, T>(
    future: F,
    deadline: Instant,
) -> Result<T, AuthenticatedPeerApplicationReceiveErrorV1>
where
    F: Future<Output = T>,
{
    if Instant::now() >= deadline {
        return Err(AuthenticatedPeerApplicationReceiveErrorV1::ReceiveDeadlineExpired);
    }

    let tokio_deadline = time::Instant::from_std(deadline);
    match time::timeout_at(tokio_deadline, future).await {
        Ok(value) => {
            if Instant::now() >= deadline {
                return Err(AuthenticatedPeerApplicationReceiveErrorV1::ReceiveDeadlineExpired);
            }
            Ok(value)
        }
        Err(_) => Err(AuthenticatedPeerApplicationReceiveErrorV1::ReceiveDeadlineExpired),
    }
}

#[cfg(test)]
mod tests {
    use std::{future, time::Duration};

    use super::*;

    #[tokio::test]
    async fn ready_future_completes_before_deadline() {
        let value = await_before_deadline_v1(
            future::ready(42_u8),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert_eq!(value, 42);
    }

    #[tokio::test]
    async fn already_expired_deadline_refuses_without_waiting() {
        let result = await_before_deadline_v1(future::pending::<()>(), Instant::now()).await;
        assert!(matches!(
            result,
            Err(AuthenticatedPeerApplicationReceiveErrorV1::ReceiveDeadlineExpired)
        ));
    }
}
