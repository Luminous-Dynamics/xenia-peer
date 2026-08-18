// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bounded-memory outbound file-transfer sources.
//!
//! [`TransferSource::open_file_limited`] opens a file once, hashes it by
//! streaming from that same handle, rewinds it, and later emits bounded chunks
//! from the same handle after the peer accepts the authenticated offer. This
//! avoids whole-file heap buffering and narrows hash/send TOCTOU exposure. A
//! second streaming hash is checked before completion so same-inode mutation
//! after the offer is detected locally rather than reported as a successful send.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt, AsyncSeekExt};

const HASH_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug)]
enum TransferSourceKind {
    Memory(Vec<u8>),
    File(tokio::fs::File),
}

#[derive(Debug)]
struct CleanupPath(Option<PathBuf>);

impl Drop for CleanupPath {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && let Err(err) = std::fs::remove_file(&path)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %path.display(),
                error = %err,
                "outbound staged file could not be removed"
            );
        }
    }
}

/// One bounded chunk emitted from a [`TransferSource`].
#[derive(Debug, PartialEq, Eq)]
pub struct TransferChunk {
    /// Exact byte offset committed by the chunk.
    pub offset: u64,
    /// Chunk payload. Its size is bounded by the caller's requested chunk size.
    pub data: Vec<u8>,
}

/// Failure while preparing or streaming an outbound transfer source.
#[derive(Debug, thiserror::Error)]
pub enum TransferSourceError {
    /// Filesystem I/O failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The source exceeds the caller's configured transfer limit.
    #[error("transfer source exceeds {max_bytes}-byte limit (observed {observed_bytes} bytes)")]
    SizeLimitExceeded {
        /// Configured maximum transfer size.
        max_bytes: u64,
        /// Size observed before refusing the source.
        observed_bytes: u64,
    },
    /// Source length no longer matches the authenticated offer metadata.
    #[error("transfer source length changed after offer: expected {expected}, observed {observed}")]
    LengthChanged {
        /// Size committed by the offer.
        expected: u64,
        /// Size observed while sending.
        observed: u64,
    },
    /// Source contents no longer match the authenticated offer hash.
    #[error("transfer source contents changed after offer")]
    HashChanged,
    /// A zero-sized chunk request cannot make streaming progress.
    #[error("transfer chunk size must be non-zero")]
    ZeroChunkSize,
}

/// Prepared outbound source with authenticated size/hash metadata and a bounded
/// chunk reader.
#[derive(Debug)]
pub struct TransferSource {
    kind: TransferSourceKind,
    size: u64,
    blake3_hash: [u8; 32],
    offset: u64,
    send_hasher: blake3::Hasher,
    end_verified: bool,
    // Declared after `kind` so the file handle is dropped before cleanup tries
    // to unlink an owned staged path (important on Windows).
    cleanup_path: CleanupPath,
}

impl TransferSource {
    /// Prepare an owned in-memory payload.
    ///
    /// This constructor exists for legacy/mobile ABI compatibility. New desktop
    /// file paths should prefer [`Self::open_file_limited`].
    pub fn from_memory(data: Vec<u8>) -> Self {
        let size = data.len() as u64;
        let blake3_hash = *blake3::hash(&data).as_bytes();
        Self {
            kind: TransferSourceKind::Memory(data),
            size,
            blake3_hash,
            offset: 0,
            send_hasher: blake3::Hasher::new(),
            end_verified: false,
            cleanup_path: CleanupPath(None),
        }
    }

    /// Open and prepare a file without buffering the whole file in memory.
    ///
    /// The source is streamed once to compute the authenticated offer hash,
    /// bounded by `max_bytes`, then the same open handle is rewound for later
    /// chunk transmission.
    pub async fn open_file_limited(
        path: &Path,
        max_bytes: u64,
    ) -> Result<Self, TransferSourceError> {
        let mut file = tokio::fs::File::open(path).await?;
        let metadata_len = file.metadata().await?.len();
        if metadata_len > max_bytes {
            return Err(TransferSourceError::SizeLimitExceeded {
                max_bytes,
                observed_bytes: metadata_len,
            });
        }

        let mut hasher = blake3::Hasher::new();
        let mut size = 0_u64;
        let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            let read_u64 = read as u64;
            let Some(next) = size.checked_add(read_u64) else {
                return Err(TransferSourceError::SizeLimitExceeded {
                    max_bytes,
                    observed_bytes: u64::MAX,
                });
            };
            if next > max_bytes {
                return Err(TransferSourceError::SizeLimitExceeded {
                    max_bytes,
                    observed_bytes: next,
                });
            }
            hasher.update(&buffer[..read]);
            size = next;
        }
        file.seek(SeekFrom::Start(0)).await?;

        Ok(Self {
            kind: TransferSourceKind::File(file),
            size,
            blake3_hash: *hasher.finalize().as_bytes(),
            offset: 0,
            send_hasher: blake3::Hasher::new(),
            end_verified: false,
            cleanup_path: CleanupPath(None),
        })
    }

    /// Open an already-staged file whose size/hash were computed by the staging
    /// path, optionally deleting the staged path when this source is dropped.
    ///
    /// The opened handle's current metadata length must still match `size`.
    /// During transmission a second streaming hash verifies the supplied digest.
    pub async fn open_prehashed_file(
        path: PathBuf,
        size: u64,
        blake3_hash: [u8; 32],
        cleanup_on_drop: bool,
    ) -> Result<Self, TransferSourceError> {
        // From this point, `cleanup_on_drop` transfers ownership of the staged
        // path to this constructor even if opening/validation fails.
        let cleanup_path = CleanupPath(cleanup_on_drop.then_some(path.clone()));
        let file = tokio::fs::File::open(&path).await?;
        let observed = file.metadata().await?.len();
        if observed != size {
            return Err(TransferSourceError::LengthChanged {
                expected: size,
                observed,
            });
        }
        Ok(Self {
            kind: TransferSourceKind::File(file),
            size,
            blake3_hash,
            offset: 0,
            send_hasher: blake3::Hasher::new(),
            end_verified: false,
            cleanup_path,
        })
    }

    /// Size committed by the outbound offer.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// BLAKE3 digest committed by the outbound offer.
    pub fn blake3_hash(&self) -> [u8; 32] {
        self.blake3_hash
    }

    /// Bytes emitted so far.
    pub fn bytes_sent(&self) -> u64 {
        self.offset
    }

    /// Emit the next chunk, verifying exact source length/hash before returning
    /// `None` at end-of-source.
    pub async fn next_chunk(
        &mut self,
        max_chunk_size: usize,
    ) -> Result<Option<TransferChunk>, TransferSourceError> {
        if max_chunk_size == 0 {
            return Err(TransferSourceError::ZeroChunkSize);
        }
        if self.end_verified {
            return Ok(None);
        }
        if self.offset == self.size {
            self.verify_end().await?;
            self.end_verified = true;
            return Ok(None);
        }

        let remaining = self.size - self.offset;
        let remaining_for_chunk = usize::try_from(remaining).unwrap_or(usize::MAX);
        let want = max_chunk_size.min(remaining_for_chunk);
        let offset = self.offset;
        let data = match &mut self.kind {
            TransferSourceKind::Memory(data) => {
                let start = usize::try_from(offset).map_err(|_| {
                    TransferSourceError::LengthChanged {
                        expected: self.size,
                        observed: offset,
                    }
                })?;
                let end = start
                    .checked_add(want)
                    .ok_or(TransferSourceError::LengthChanged {
                        expected: self.size,
                        observed: offset,
                    })?;
                if end > data.len() {
                    return Err(TransferSourceError::LengthChanged {
                        expected: self.size,
                        observed: data.len() as u64,
                    });
                }
                data[start..end].to_vec()
            }
            TransferSourceKind::File(file) => {
                let mut chunk = vec![0_u8; want];
                let mut filled = 0_usize;
                while filled < want {
                    let read = file.read(&mut chunk[filled..]).await?;
                    if read == 0 {
                        return Err(TransferSourceError::LengthChanged {
                            expected: self.size,
                            observed: offset.saturating_add(filled as u64),
                        });
                    }
                    filled += read;
                }
                chunk
            }
        };

        self.send_hasher.update(&data);
        self.offset = self.offset.saturating_add(data.len() as u64);
        Ok(Some(TransferChunk { offset, data }))
    }

    async fn verify_end(&mut self) -> Result<(), TransferSourceError> {
        if let TransferSourceKind::File(file) = &mut self.kind {
            let mut probe = [0_u8; 1];
            if file.read(&mut probe).await? != 0 {
                return Err(TransferSourceError::LengthChanged {
                    expected: self.size,
                    observed: self.size.saturating_add(1),
                });
            }
        }
        if self.send_hasher.finalize().as_bytes() != &self.blake3_hash {
            return Err(TransferSourceError::HashChanged);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "xenia-transfer-source-{}-{}-{name}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[tokio::test]
    async fn memory_source_emits_exact_bounded_chunks() {
        let payload = b"abcdefghij".to_vec();
        let expected_hash = *blake3::hash(&payload).as_bytes();
        let mut source = TransferSource::from_memory(payload);
        assert_eq!(source.size(), 10);
        assert_eq!(source.blake3_hash(), expected_hash);

        let mut chunks = Vec::new();
        while let Some(chunk) = source.next_chunk(4).await.unwrap() {
            chunks.push(chunk);
        }
        assert_eq!(
            chunks,
            vec![
                TransferChunk {
                    offset: 0,
                    data: b"abcd".to_vec(),
                },
                TransferChunk {
                    offset: 4,
                    data: b"efgh".to_vec(),
                },
                TransferChunk {
                    offset: 8,
                    data: b"ij".to_vec(),
                },
            ]
        );
        assert_eq!(source.bytes_sent(), 10);
    }

    #[tokio::test]
    async fn file_source_hashes_and_streams_without_whole_file_buffering() {
        let path = temp_path("stream.bin");
        let payload = vec![0x5A; HASH_BUFFER_SIZE * 2 + 17];
        std::fs::write(&path, &payload).unwrap();
        let mut source = TransferSource::open_file_limited(&path, payload.len() as u64)
            .await
            .unwrap();
        assert_eq!(source.size(), payload.len() as u64);
        assert_eq!(source.blake3_hash(), *blake3::hash(&payload).as_bytes());

        let mut rebuilt = Vec::new();
        while let Some(chunk) = source.next_chunk(8192).await.unwrap() {
            rebuilt.extend_from_slice(&chunk.data);
        }
        assert_eq!(rebuilt, payload);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn source_detects_same_length_mutation_after_offer() {
        let path = temp_path("mutated.bin");
        std::fs::write(&path, b"original").unwrap();
        let mut source = TransferSource::open_file_limited(&path, 1024).await.unwrap();
        std::fs::write(&path, b"mutated!").unwrap();

        while source.bytes_sent() < source.size() {
            assert!(source.next_chunk(3).await.unwrap().is_some());
        }
        assert!(matches!(
            source.next_chunk(3).await,
            Err(TransferSourceError::HashChanged)
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn prehashed_staged_source_removes_owned_path_on_drop() {
        let path = temp_path("staged.bin");
        let payload = b"staged";
        std::fs::write(&path, payload).unwrap();
        let hash = *blake3::hash(payload).as_bytes();
        let source =
            TransferSource::open_prehashed_file(path.clone(), payload.len() as u64, hash, true)
                .await
                .unwrap();
        drop(source);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn oversized_file_is_refused_before_offer() {
        let path = temp_path("too-large.bin");
        std::fs::write(&path, b"12345").unwrap();
        assert!(matches!(
            TransferSource::open_file_limited(&path, 4).await,
            Err(TransferSourceError::SizeLimitExceeded { .. })
        ));
        std::fs::remove_file(path).unwrap();
    }
}
