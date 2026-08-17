# Xenia Application Receive Staging V21

## Scope

V21 closes the receive-side resource-pressure gap left by V20 and hardens when staged outbound commands are allowed to become active. It does **not** change the authenticated file-transfer wire protocol: `Offer { size, blake3_hash }`, `Accept`, 64 KiB `Chunk`, `Complete`, `Verified`, and `Reject` keep their current encoding and meaning.

The central invariant is:

> At every point in an accepted inbound transfer, durable staged content is exactly the byte prefix `[0, received_bytes)`, and the incremental BLAKE3 state represents exactly that prefix.

## Shared receive primitive

`xenia-peer-core::IncomingFileStager` is the common receiver used by the daemon, native viewer, and mobile viewer.

For every accepted `Offer`, it:

1. creates a private `create_new` staging inode in the final destination directory;
2. accepts only the exact next offset (`offset == received_bytes`);
3. rejects arithmetic overflow or any chunk extending beyond the authenticated offered size;
4. writes the chunk directly to disk and updates BLAKE3 incrementally;
5. requires `received_bytes == offered_size` at `Complete`;
6. requires the computed BLAKE3 digest to equal the authenticated offer digest;
7. calls `sync_all` before publication;
8. publishes with a same-directory hard link, which fails rather than clobbering an existing final path;
9. removes the hidden staging path on success, failure, disconnect, or ordinary state drop.

The old `persist_received_file(&[u8])` helper remains exported for compatibility, but the three live receiver state machines no longer accumulate inbound transfer bodies in a `Vec<u8>`.

## Receiver integration

- `xenia-peer`: shared incremental staging, at most 8 concurrent inbound transfers.
- `xenia-viewer`: shared incremental staging, at most 8 concurrent inbound transfers.
- `xenia-mobile-ffi`: shared incremental staging, at most 4 concurrent inbound transfers.

These concurrency limits bound open staging handles and per-session state. They do **not** reserve filesystem free space. A peer that is permitted to send files may therefore consume disk up to the configured per-file policy multiplied by the active-transfer cap before the operating system itself refuses further writes. Free-space/quota admission remains a separate follow-up rather than an implied V21 guarantee.

## Crash cleanup

`IncomingFileStager::Drop` removes partial staging during ordinary teardown. V21 additionally exports `cleanup_orphaned_receive_staging`, which is called when each receiver starts.

The scavenger selects only Xenia's reserved name shape:

`.xenia-receive-<decimal pid>-<32 hex>.tmp`

Unrelated files are ignored. Entries carrying the current process ID are also preserved, so opening another session in the same process cannot delete a live staged transfer. Older-process matches are removed best-effort; failures are logged and do not widen the filename match.

## Mobile storage separation

Android now passes two explicit private storage roots into native code:

- received files: `filesDir/received`;
- outbound SAF staging: `noBackupFilesDir/outbound-staging`.

Outbound staging is no longer derived from the receive destination. Xenia removes only its exact `upload-<16 hex>.part` orphan pattern from that outbound directory.

## Outbound activation correction

V20 reserved bounded command capacity before expensive SAF staging, but the consumer could still dequeue an already-staged command when another outgoing transfer was active or before the authenticated application surface existed. That could turn successful bounded staging into needless discard.

V21 gates `ft_cmd_rx.recv()` itself. A command is dequeued only when:

- the authenticated application surface exists; and
- no outgoing transfer is currently active.

The bounded queue therefore retains staged commands until they can actually become the active transfer. The defensive busy check remains, but it is no longer the normal scheduling path.

## Security and resource properties

V21 provides:

- strict sequential receive offsets (gap/overlap fail closed);
- incremental whole-file integrity verification;
- no whole-file receive heap buffer on daemon/native/mobile receivers;
- no-clobber final publication;
- private same-directory staging;
- cleanup on normal failure/teardown plus bounded restart scavenging;
- bounded concurrent inbound state;
- authenticated-and-idle activation of already-staged mobile outbound commands.

V21 deliberately does **not** claim:

- filesystem free-space or quota reservation;
- globally transactional publication across multiple files;
- resumable/random-access transfer;
- deduplication/content-addressed storage;
- wire-protocol changes.

Strict sequential delivery is intentional for this protocol revision: it keeps receiver state small, makes integrity state unambiguous, and prevents a peer from driving sparse/gapped allocation behavior through authenticated chunks.

## Merge gates

Run the accumulated source/model contract suite:

```bash
bash scripts/run_transport_session_contracts.sh
```

Then run the repository Rust 1.94 gates before merge:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo test -p xenia-peer-core --locked
cargo test -p xenia-mobile-ffi --locked
cargo test -p xenia-peer --all-targets --locked
cargo test -p xenia-viewer --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

For Android/JNI, also compile the JNI translation unit with warnings as errors and exercise SAF providers with known/unknown lengths, peer rejection, disconnect during transfer, and process restart with an intentionally orphaned staging file.
