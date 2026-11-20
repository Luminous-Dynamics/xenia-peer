# Fail-Closed QUIC Envelope I/O After Cancellation

**Status:** Additive transport correctness fix v0.1.  
**Tracking:** [Xenia #529](https://github.com/Luminous-Dynamics/xenia-peer/issues/529) for bounded send/preemption work; this PR addresses framing correctness in the existing single-stream QUIC transport.  
**Implementation:** `crates/xenia-transport-quic/src/lib.rs`.

## 1. Defect found in the live transport

The current Xenia Iroh QUIC transport sends each length-prefixed envelope as:

1. four-byte big-endian payload length;
2. complete payload bytes.

The original writer wrapped `SendStream::write_all` for both pieces in `tokio::time::timeout`. This is unsafe for a persistent framed stream.

The lockfile pins Iroh **1.0.2**. Its own `iroh::endpoint::SendStream` documentation states:
- `write` is cancellation-safe and returns the number of bytes written;
- `write_all` is not cancellation-safe and may have written a prefix when cancelled;
- `finish` prevents further writes to that stream.

Tokio similarly documents `AsyncReadExt::read_exact` as cancellation-unsafe: a cancelled read can consume some bytes without returning them to the caller.

Therefore an envelope timeout could leave a prefix of a length field/payload on a stream that the application later tries to reuse. The next envelope would then be interpreted as the missing tail of the previous envelope. The existing transport error contract already says timeout is session-fatal; the implementation was not enforcing that invariant.

## 2. New sender behavior

The envelope writer now loops over Iroh's cancellation-safe `SendStream::write`:
- each successful call returns exact prefix progress;
- a zero-byte success is treated as WriteZero;
- the offset advances only by the returned byte count;
- the four-byte length and payload use the same progress-reporting loop.

If any write I/O error or deadline timeout occurs after writing begins:
- the send stream is finished immediately;
- its local terminal flag is set;
- a later send call returns `UnexpectedEof` without touching the stream;
- no subsequent envelope can be appended to a partial envelope.

An input rejected for `EnvelopeTooLarge` is validated before any write and does **not** poison an otherwise healthy stream.

The same terminal flag moves with the send half when `QuicTransport::split` is called. Explicit `finish()` also marks the half terminal.

## 3. New receiver behavior

A timed-out/erroring `read_exact` can consume part of the four-byte length prefix or payload. The receiver now treats every envelope-read error/timeout as terminal:
- the receive half records terminal state;
- `RecvStream::stop(0)` notifies the peer to stop sending on that direction;
- a subsequent receive returns `UnexpectedEof` immediately;
- split receive halves retain that terminal state.

This is deliberately fail-closed. It does not try to guess how many bytes were consumed or search for a plausible next length prefix. The caller must tear down/re-establish the session rather than parse a possibly desynchronized stream.

## 4. Why not resynchronize?

Length-prefixed binary framing has no safe generic resynchronization marker. Scanning arbitrary payload bytes for a plausible length field can turn attacker-controlled content into a forged envelope boundary. A reset/reconnect with a fresh authenticated session transcript is safer than trying to salvage a stream whose framing offset is unknown.

The current implementation uses `finish()` after a partially written envelope. The peer may receive the already-queued prefix and then EOF; its `read_exact` fails and its receiver becomes terminal. A future refinement may use QUIC `reset()` with a registered application error code, but must first define the cross-platform peer error mapping.

## 5. State model

| Event | Send side | Receive side |
|---|---|---|
| Successful envelope | Remains open | Remains open |
| Oversized outgoing envelope rejected before write | Remains open | N/A |
| I/O error after send begins | Finish + terminal | Peer observes EOF/error; terminal on read |
| Send deadline after any successful prefix write | Finish + terminal | Peer observes incomplete envelope; terminal on read |
| Read deadline/error | N/A | Terminal |
| Explicit finish | Terminal | Unchanged |
| Split transport | Terminal state follows owning half | Terminal state follows owning half |

## 6. Tests and failure corpus

[quic-envelope-cancellation-v0.1.json](../../benchmarks/quic-envelope-cancellation-v0.1.json) contains 10 synthetic state/fault cases.

Unit tests verify:
- only pre-write size rejection is classified as non-terminal;
- timeout, I/O error and unexpected EOF are terminal;
- terminal stream sides reject subsequent operations;
- successful receive does not mark the side terminal;
- receive errors mark the side terminal.

These are state/helper tests; they do not substitute for an Iroh loopback timeout test under backpressure, nor for compilation/execution.

## 7. Next transport work

This correction is separate from #529's sender fairness work. It does not:
- add multiple streams or QUIC DATAGRAM;
- implement bounded video fragments or sender scheduling;
- implement cross-stream priority or independent congestion control;
- retry an envelope or infer whether an application-level operation committed;
- add durable resume/reconciliation for partial file transfers.

Those require operation IDs, transfer chunk receipts and the bounded fragmentation contract. A timed-out Xenia envelope write is treated as session-fatal; the application must reconcile any protected effect whose dispatch outcome could be ambiguous.

## 8. Claim boundary

**Authored:** cancellation-safe write loop, finish-on-send-error/timeout, terminal send/receive state, terminal state transfer through split, helper-level unit tests and synthetic workload corpus.

**Not yet validated:** Rust compilation, rustfmt, Clippy, unit-test execution, Iroh loopback fault injection, platform qualification, interoperability with old peers, or measured latency/throughput.

No SOTA or production-readiness claim is made.