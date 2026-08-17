# Xenia Application File Staging V20

## Scope

V20 changes the Android/mobile **outbound producer/storage path**, not the peer-visible file-transfer wire protocol. The authenticated `Offer { size, blake3_hash }`, `Accept`, 64 KiB `Chunk`, `Complete`, and `Verified` messages remain unchanged.

The purpose is to remove whole-file Java/native heap materialization from the preferred Storage Access Framework (SAF) path while preserving the existing authenticated whole-file hash semantics.

## Preferred Android path

1. The UI resolves the SAF display name and optional `OpenableColumns.SIZE` without calling `readBytes()`.
2. Native code reserves a real slot in the bounded two-command file-transfer lane.
3. Kotlin reuses one 64 KiB `ByteArray` while reading the SAF `InputStream`.
4. JNI copies only the current chunk into Rust.
5. Rust writes that chunk into an app-private staging file and updates BLAKE3 incrementally.
6. The staging lease is a fixed five minutes and is **not** extended by chunk progress.
7. `finish` verifies any provider-declared length, finalizes BLAKE3, and consumes the pre-reserved command slot.
8. Xenia sends the existing authenticated `Offer(size, hash)`.
9. Only after the peer accepts does the session reopen the staged file with Tokio and send 64 KiB protocol chunks.
10. The staged path is deleted when the outgoing transfer is rejected, verified/completed, fails, or the session drops.

Providers that do not expose a stable size are supported. Native staging enforces the fixed 100 MiB mobile ceiling incrementally.

## Resource bounds

- Java reusable transfer chunk: 64 KiB.
- Native append slice: at most the current Java chunk.
- Protocol file chunk: 64 KiB.
- Per-file mobile ceiling: 100 MiB.
- File-command capacity: 2.
- At most one dequeued staged outgoing transfer may additionally remain active while two other staged commands/permits exist. The conservative staged-file disk ceiling is therefore 300 MiB.
- Stream/staging lease: 300,000 ms absolute; append progress does not extend it.

These are implementation-safety bounds, not authenticated peer-visible session parameters.

## Diagnostics

`FileTransferAdmissionSnapshotV2` adds:

- `active_reserved`
- `active_copying`
- `active_streaming`
- `active_stream_bytes`
- `available_command_slots`
- `command_capacity`

`active_stream_bytes` intentionally describes only uploads **currently being staged**. It does not claim to measure staged files already queued or active in the transfer state machine.

V19's V1 snapshot remains available for ABI compatibility.

## Failure semantics

V20 adds native admission status `8 = IO_ERROR` for staging/open/write/read failures. Existing status values 0..7 remain unchanged.

A staging failure does not silently enqueue a partial file. Expiry/cancel/session teardown delete partial staging paths and return the held queue permit.

## Security notes

- Staging filenames are process-generated with `create_new(true)` in an app-private/sibling staging directory when a receive directory is available.
- User-supplied names are reduced to a bare basename before staging metadata enters the command.
- The peer still authenticates the whole-file BLAKE3 digest in the original `Offer`; V20 does not weaken integrity to make streaming easier.
- No staged stream can hold command capacity forever by making progress: the five-minute deadline is absolute.
- Legacy whole-buffer C/Kotlin APIs remain for compatibility; current Android picker code uses the streaming path.

## Runtime merge gates

Run with the repository's Rust 1.94 toolchain before merge:

```bash
cargo check --workspace --all-targets --locked
cargo test -p xenia-mobile-ffi --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The mobile FFI test suite includes a paused-Tokio expiry regression requiring an abandoned partial staging file to be removed and its queue capacity returned.

Also exercise a real Android SAF provider with:

- known and unknown reported sizes;
- a near-100 MiB file;
- provider read failure mid-stream;
- session disconnect during staging;
- peer rejection after staging;
- a deliberately slow stream that crosses the five-minute lease.
