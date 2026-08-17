# Xenia Application Lane Recovery Profile V1

V17 strengthens local application-flow behavior after V16 bounded the relevant queues in time and memory. This profile is **local implementation policy**, not a new peer-visible session schema revision.

## Desktop audio freshness

The desktop GUI ingress remains four decoded audio frames, but overflow changes from **drop newest** to **drop oldest**. At the protocol maximum of 20 ms per frame, this preserves the same 80 ms ingress memory/time bound while preferentially retaining the most recent decoded audio. The jitter and device-buffer budgets from V16 remain unchanged.

This does not claim an end-to-end latency SLA. Network delay, codec execution, OS mixer and hardware remain outside the local application-buffer contract.

## Lane-pressure evidence

`LanePressureCountersV1` records four local classes: superseded items dropped, explicit rejections, stale work discarded, and fatal semantic deadlines. V17 wires desktop audio supersession and host-video stale/deadline behavior into these counters. The counters are diagnostic evidence and are not authenticated protocol state.

## Mobile file-transfer reservation

V16's `xenia_check_send_file` remains for ABI compatibility, but it is only advisory. V17 adds a capacity-reserving path using Tokio bounded-channel owned permits:

1. reserve one command slot with `xenia_reserve_send_file`;
2. only after successful reservation request/copy the Java byte array;
3. commit with `xenia_commit_send_file`;
4. cancel on payload-acquisition failure.

The reservation binds the expected payload length and expires after 30 seconds. The C boundary validates the live token and exact reserved length before copying payload bytes; the consuming commit rechecks afterward. Invalid or size-mismatched commits fail closed. A canceled/expired reservation drops its owned permit and returns capacity to the queue. The engine Drop path clears outstanding reservations immediately.

The reservation is local admission only. It does not mean the remote peer accepted the transfer.

## Security rule

**When pressure occurs, preserve current semantic state rather than stale history; make the recovery action observable; reserve scarce local admission capacity before performing expensive payload materialization.**
