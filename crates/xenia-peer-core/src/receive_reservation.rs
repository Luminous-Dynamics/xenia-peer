// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Logical byte reservations for inbound file-transfer admission.
//!
//! A reservation is acquired before receive staging is created and held for the
//! lifetime of the in-flight transfer. Dropping the reservation releases its
//! bytes automatically, so cancellation, verification failure, publication
//! failure, and successful completion all converge on the same accounting path.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug)]
struct ReceiveReservationPoolInner {
    capacity: u64,
    reserved: AtomicU64,
}

/// Shared logical byte budget for concurrently admitted inbound transfers.
#[derive(Clone, Debug)]
pub struct ReceiveReservationPool {
    inner: Arc<ReceiveReservationPoolInner>,
}

/// RAII lease for bytes admitted from a [`ReceiveReservationPool`].
///
/// The lease is intentionally non-cloneable: each successful admission has one
/// owner, and dropping that owner releases the exact number of reserved bytes.
#[derive(Debug)]
pub struct ReceiveReservation {
    inner: Arc<ReceiveReservationPoolInner>,
    bytes: u64,
}

/// Failure to reserve logical receive capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReceiveReservationError {
    /// The requested reservation would exceed the configured aggregate budget.
    #[error(
        "receive reservation exceeds capacity: requested {requested} bytes with {reserved} already reserved (capacity {capacity})"
    )]
    CapacityExceeded {
        /// Bytes requested by the new transfer.
        requested: u64,
        /// Bytes already reserved by active transfers.
        reserved: u64,
        /// Aggregate reservation capacity.
        capacity: u64,
    },
}

impl ReceiveReservationPool {
    /// Create a pool with an aggregate logical byte capacity.
    pub fn new(capacity: u64) -> Self {
        Self {
            inner: Arc::new(ReceiveReservationPoolInner {
                capacity,
                reserved: AtomicU64::new(0),
            }),
        }
    }

    /// Total logical byte capacity of the pool.
    pub fn capacity(&self) -> u64 {
        self.inner.capacity
    }

    /// Bytes currently reserved by live leases.
    pub fn reserved_bytes(&self) -> u64 {
        self.inner.reserved.load(Ordering::SeqCst)
    }

    /// Capacity not currently reserved.
    pub fn available_bytes(&self) -> u64 {
        self.capacity().saturating_sub(self.reserved_bytes())
    }

    /// Reserve `bytes` until the returned lease is dropped.
    pub fn try_reserve(&self, bytes: u64) -> Result<ReceiveReservation, ReceiveReservationError> {
        let mut reserved = self.inner.reserved.load(Ordering::SeqCst);
        loop {
            let Some(next) = reserved.checked_add(bytes) else {
                return Err(ReceiveReservationError::CapacityExceeded {
                    requested: bytes,
                    reserved,
                    capacity: self.capacity(),
                });
            };
            if next > self.capacity() {
                return Err(ReceiveReservationError::CapacityExceeded {
                    requested: bytes,
                    reserved,
                    capacity: self.capacity(),
                });
            }
            match self.inner.reserved.compare_exchange_weak(
                reserved,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    return Ok(ReceiveReservation {
                        inner: Arc::clone(&self.inner),
                        bytes,
                    });
                }
                Err(actual) => reserved = actual,
            }
        }
    }
}

impl ReceiveReservation {
    /// Bytes held by this lease.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl Drop for ReceiveReservation {
    fn drop(&mut self) {
        let previous = self.inner.reserved.fetch_sub(self.bytes, Ordering::SeqCst);
        debug_assert!(previous >= self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservation_rejects_aggregate_overcommit() {
        let pool = ReceiveReservationPool::new(10);
        let first = pool.try_reserve(7).unwrap();
        assert_eq!(first.bytes(), 7);
        assert_eq!(pool.reserved_bytes(), 7);
        assert_eq!(pool.available_bytes(), 3);
        assert!(matches!(
            pool.try_reserve(4),
            Err(ReceiveReservationError::CapacityExceeded {
                requested: 4,
                reserved: 7,
                capacity: 10,
            })
        ));
    }

    #[test]
    fn dropping_reservation_releases_capacity() {
        let pool = ReceiveReservationPool::new(10);
        {
            let _lease = pool.try_reserve(10).unwrap();
            assert_eq!(pool.available_bytes(), 0);
        }
        assert_eq!(pool.reserved_bytes(), 0);
        assert!(pool.try_reserve(10).is_ok());
    }

    #[test]
    fn cloned_pools_share_one_accounting_domain() {
        let pool = ReceiveReservationPool::new(12);
        let clone = pool.clone();
        let first = pool.try_reserve(5).unwrap();
        let second = clone.try_reserve(7).unwrap();
        assert_eq!(pool.reserved_bytes(), 12);
        drop(first);
        assert_eq!(clone.reserved_bytes(), 7);
        drop(second);
        assert_eq!(pool.reserved_bytes(), 0);
    }
}
