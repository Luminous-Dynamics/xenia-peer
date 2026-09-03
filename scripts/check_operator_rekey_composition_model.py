#!/usr/bin/env python3
"""Bounded independent two-party safety model for Xenia operator rekey V1.

This model intentionally does not import or execute the production Rust state
machines or the one-sided initiator model. It explores an abstract host,
receiver, and ordered reverse carrier and checks the composition invariants in
OPERATOR_REKEY_COMPOSITION_INVARIANTS_V1.json.

It is executable design evidence, not a formal proof of Rust, cryptography,
carrier delivery, scheduling, crash atomicity, OS behavior, or hardware.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Iterable


class HostPhase(str, Enum):
    STABLE = "stable"
    PREPARED = "prepared"
    DELIVERY_UNKNOWN = "delivery_unknown"
    PENDING_ACK = "pending_ack"
    DEAD = "dead"


class ReceiverPhase(str, Enum):
    STABLE = "stable"
    PROPOSAL_AUTHENTICATED = "proposal_authenticated"
    ACK_PENDING = "committed_ack_pending_delivery"
    DEAD = "dead"


class ReverseKind(str, Enum):
    APP = "app"
    ACK = "ack"
    ACK_OLD_KEY = "ack_old_key"
    ACK_WRONG_DOMAIN = "ack_wrong_domain"
    ACK_WRONG_SEQUENCE = "ack_wrong_sequence"


class Event(str, Enum):
    HOST_PREPARE = "host_prepare"
    HOST_BEGIN_SEND = "host_begin_send"
    PROPOSAL_SEND_OK = "proposal_send_ok"
    PROPOSAL_SEND_FAIL_BEFORE_WRITE = "proposal_send_fail_before_write"
    PROPOSAL_SEND_FAIL_AFTER_ESCAPE = "proposal_send_fail_after_escape"
    PROPOSAL_DELIVER = "proposal_deliver"
    INVALID_PROPOSAL_WRONG_ROLE = "invalid_proposal_wrong_role_same_key"
    INVALID_PROPOSAL_PREVIOUS_KEY = "invalid_proposal_previous_key"
    REPLAY_PROPOSAL = "replay_proposal"
    RECEIVER_VALIDATION_FAIL = "receiver_validation_fail_before_commit"
    RECEIVER_COMMIT = "receiver_commit_and_preseal_ack_seq0"
    ACK_SEND_OK = "ack_send_ok"
    ACK_SEND_FAIL_BEFORE_WRITE = "ack_send_fail_before_write"
    ACK_SEND_FAIL_AFTER_ESCAPE = "ack_send_fail_after_escape"
    REPLAY_ACK = "replay_ack"
    INJECT_ACK_OLD_KEY = "inject_ack_old_key"
    INJECT_ACK_WRONG_DOMAIN = "inject_ack_wrong_domain"
    INJECT_ACK_WRONG_SEQUENCE = "inject_ack_wrong_sequence"
    DELIVER_REVERSE_HEAD = "deliver_reverse_head"
    ACK_TIMEOUT = "ack_timeout"
    HOST_APP_ATTEMPT = "host_application_traffic_attempt"
    RECEIVER_APP_ATTEMPT = "receiver_application_traffic_attempt"
    DISCONNECT = "disconnect"
    FRESH_HANDSHAKE = "fresh_authenticated_handshake"


@dataclass(frozen=True, order=True)
class ReverseMessage:
    kind: ReverseKind
    epoch: int


@dataclass(frozen=True)
class State:
    generation: int = 0
    host_phase: HostPhase = HostPhase.STABLE
    receiver_phase: ReceiverPhase = ReceiverPhase.STABLE
    host_local_epoch: int = 0
    host_confirmed_epoch: int = 0
    receiver_epoch: int = 0
    prepared_epoch: int = -1

    proposal_available: bool = False
    proposal_may_have_escaped: bool = False
    proposal_delivered: bool = False
    proposal_replay_epoch: int = -1

    ack_seq0_reserved: bool = False
    ack_may_have_escaped: bool = False
    ack_delivered: bool = False
    ack_replay_epoch: int = -1

    host_cutover_active: bool = False
    reverse_fifo: tuple[ReverseMessage, ...] = ()

    @property
    def host_application_authority(self) -> bool:
        return self.host_phase is HostPhase.STABLE

    @property
    def receiver_application_authority(self) -> bool:
        return self.receiver_phase is ReceiverPhase.STABLE


MAX_EPOCH = 2
MAX_REVERSE_FIFO = 3


def enabled_events(state: State) -> Iterable[Event]:
    if (
        state.host_phase is HostPhase.STABLE
        and state.receiver_phase is ReceiverPhase.STABLE
        and state.host_confirmed_epoch == state.receiver_epoch
    ):
        yield Event.HOST_PREPARE

    if state.host_phase is HostPhase.PREPARED:
        yield Event.HOST_BEGIN_SEND

    if state.host_phase is HostPhase.DELIVERY_UNKNOWN:
        yield Event.PROPOSAL_SEND_OK
        yield Event.PROPOSAL_SEND_FAIL_BEFORE_WRITE
        yield Event.PROPOSAL_SEND_FAIL_AFTER_ESCAPE

    if state.proposal_available and state.receiver_phase is not ReceiverPhase.DEAD:
        yield Event.PROPOSAL_DELIVER

    if state.receiver_phase is not ReceiverPhase.DEAD:
        yield Event.INVALID_PROPOSAL_WRONG_ROLE
        yield Event.INVALID_PROPOSAL_PREVIOUS_KEY
        if state.proposal_replay_epoch >= 0:
            yield Event.REPLAY_PROPOSAL

    if state.receiver_phase is ReceiverPhase.PROPOSAL_AUTHENTICATED:
        yield Event.RECEIVER_VALIDATION_FAIL
        yield Event.RECEIVER_COMMIT

    if state.receiver_phase is ReceiverPhase.ACK_PENDING:
        yield Event.ACK_SEND_OK
        yield Event.ACK_SEND_FAIL_BEFORE_WRITE
        yield Event.ACK_SEND_FAIL_AFTER_ESCAPE

    if state.ack_replay_epoch >= 0 and len(state.reverse_fifo) < MAX_REVERSE_FIFO:
        yield Event.REPLAY_ACK

    if state.host_phase is HostPhase.PENDING_ACK:
        if len(state.reverse_fifo) < MAX_REVERSE_FIFO:
            yield Event.INJECT_ACK_OLD_KEY
            yield Event.INJECT_ACK_WRONG_DOMAIN
            yield Event.INJECT_ACK_WRONG_SEQUENCE
        yield Event.ACK_TIMEOUT

    if state.reverse_fifo:
        yield Event.DELIVER_REVERSE_HEAD

    if state.host_phase is not HostPhase.DEAD:
        yield Event.HOST_APP_ATTEMPT

    if state.receiver_phase is not ReceiverPhase.DEAD:
        yield Event.RECEIVER_APP_ATTEMPT

    if not (
        state.host_phase is HostPhase.DEAD
        and state.receiver_phase is ReceiverPhase.DEAD
    ):
        yield Event.DISCONNECT

    if state.host_phase is HostPhase.DEAD or state.receiver_phase is ReceiverPhase.DEAD:
        yield Event.FRESH_HANDSHAKE


def transition(state: State, event: Event) -> State:
    if event not in set(enabled_events(state)):
        raise AssertionError(f"disabled event {event.value} from {state}")

    if event is Event.HOST_PREPARE:
        if state.host_confirmed_epoch >= MAX_EPOCH:
            return replace(state, host_phase=HostPhase.DEAD)
        return replace(
            state,
            host_phase=HostPhase.PREPARED,
            prepared_epoch=state.host_confirmed_epoch + 1,
            proposal_available=False,
            proposal_may_have_escaped=False,
            proposal_delivered=False,
            ack_seq0_reserved=False,
            ack_may_have_escaped=False,
            ack_delivered=False,
        )

    if event is Event.HOST_BEGIN_SEND:
        return replace(
            state,
            host_phase=HostPhase.DELIVERY_UNKNOWN,
            host_cutover_active=True,
        )

    if event is Event.PROPOSAL_SEND_OK:
        return replace(
            state,
            host_phase=HostPhase.PENDING_ACK,
            host_local_epoch=state.prepared_epoch,
            proposal_available=True,
            proposal_may_have_escaped=True,
            proposal_replay_epoch=state.prepared_epoch,
        )

    if event is Event.PROPOSAL_SEND_FAIL_BEFORE_WRITE:
        return replace(
            state,
            host_phase=HostPhase.DEAD,
            proposal_available=False,
            proposal_may_have_escaped=False,
        )

    if event is Event.PROPOSAL_SEND_FAIL_AFTER_ESCAPE:
        return replace(
            state,
            host_phase=HostPhase.DEAD,
            proposal_available=True,
            proposal_may_have_escaped=True,
            proposal_replay_epoch=state.prepared_epoch,
        )

    if event is Event.PROPOSAL_DELIVER:
        if state.prepared_epoch != state.receiver_epoch + 1:
            return replace(
                state,
                receiver_phase=ReceiverPhase.DEAD,
                proposal_available=False,
                proposal_delivered=True,
            )
        return replace(
            state,
            receiver_phase=ReceiverPhase.PROPOSAL_AUTHENTICATED,
            proposal_available=False,
            proposal_delivered=True,
        )

    if event in (
        Event.INVALID_PROPOSAL_WRONG_ROLE,
        Event.INVALID_PROPOSAL_PREVIOUS_KEY,
        Event.REPLAY_PROPOSAL,
        Event.RECEIVER_VALIDATION_FAIL,
    ):
        return replace(state, receiver_phase=ReceiverPhase.DEAD)

    if event is Event.RECEIVER_COMMIT:
        return replace(
            state,
            receiver_phase=ReceiverPhase.ACK_PENDING,
            receiver_epoch=state.prepared_epoch,
            ack_seq0_reserved=True,
        )

    if event is Event.ACK_SEND_OK:
        queue = state.reverse_fifo + (ReverseMessage(ReverseKind.ACK, state.receiver_epoch),)
        return replace(
            state,
            receiver_phase=ReceiverPhase.STABLE,
            ack_seq0_reserved=False,
            ack_may_have_escaped=True,
            ack_replay_epoch=state.receiver_epoch,
            reverse_fifo=queue,
        )

    if event is Event.ACK_SEND_FAIL_BEFORE_WRITE:
        return replace(
            state,
            receiver_phase=ReceiverPhase.DEAD,
            ack_seq0_reserved=False,
            ack_may_have_escaped=False,
        )

    if event is Event.ACK_SEND_FAIL_AFTER_ESCAPE:
        queue = state.reverse_fifo + (ReverseMessage(ReverseKind.ACK, state.receiver_epoch),)
        return replace(
            state,
            receiver_phase=ReceiverPhase.DEAD,
            ack_seq0_reserved=False,
            ack_may_have_escaped=True,
            ack_replay_epoch=state.receiver_epoch,
            reverse_fifo=queue,
        )

    if event is Event.REPLAY_ACK:
        return replace(
            state,
            reverse_fifo=state.reverse_fifo
            + (ReverseMessage(ReverseKind.ACK, state.ack_replay_epoch),),
        )

    invalid_ack_kind = {
        Event.INJECT_ACK_OLD_KEY: ReverseKind.ACK_OLD_KEY,
        Event.INJECT_ACK_WRONG_DOMAIN: ReverseKind.ACK_WRONG_DOMAIN,
        Event.INJECT_ACK_WRONG_SEQUENCE: ReverseKind.ACK_WRONG_SEQUENCE,
    }.get(event)
    if invalid_ack_kind is not None:
        return replace(
            state,
            reverse_fifo=state.reverse_fifo
            + (ReverseMessage(invalid_ack_kind, state.host_local_epoch),),
        )

    if event is Event.DELIVER_REVERSE_HEAD:
        head = state.reverse_fifo[0]
        remaining = state.reverse_fifo[1:]

        if head.kind is ReverseKind.ACK:
            if (
                state.host_phase is HostPhase.PENDING_ACK
                and head.epoch == state.host_local_epoch
            ):
                return replace(
                    state,
                    host_phase=HostPhase.STABLE,
                    host_confirmed_epoch=head.epoch,
                    host_cutover_active=False,
                    ack_delivered=True,
                    reverse_fifo=remaining,
                )
            return replace(
                state,
                host_phase=HostPhase.DEAD,
                reverse_fifo=remaining,
            )

        if head.kind in (
            ReverseKind.ACK_OLD_KEY,
            ReverseKind.ACK_WRONG_DOMAIN,
            ReverseKind.ACK_WRONG_SEQUENCE,
        ):
            return replace(
                state,
                host_phase=HostPhase.DEAD,
                reverse_fifo=remaining,
            )

        if (
            state.host_phase is HostPhase.STABLE
            and head.epoch == state.host_confirmed_epoch
        ):
            return replace(state, reverse_fifo=remaining)

        # Includes the V1 quiescence gap: a legitimate old-epoch console
        # application message that was queued ahead of Ack reaches a host that
        # has already committed locally and is PendingAck. V1 fails closed.
        return replace(
            state,
            host_phase=HostPhase.DEAD,
            reverse_fifo=remaining,
        )

    if event is Event.ACK_TIMEOUT:
        return replace(state, host_phase=HostPhase.DEAD)

    if event is Event.HOST_APP_ATTEMPT:
        if state.host_application_authority:
            return state
        return replace(state, host_phase=HostPhase.DEAD)

    if event is Event.RECEIVER_APP_ATTEMPT:
        if state.receiver_application_authority:
            if len(state.reverse_fifo) >= MAX_REVERSE_FIFO:
                return state
            return replace(
                state,
                reverse_fifo=state.reverse_fifo
                + (ReverseMessage(ReverseKind.APP, state.receiver_epoch),),
            )
        return replace(state, receiver_phase=ReceiverPhase.DEAD)

    if event is Event.DISCONNECT:
        return replace(
            state,
            host_phase=HostPhase.DEAD,
            receiver_phase=ReceiverPhase.DEAD,
        )

    if event is Event.FRESH_HANDSHAKE:
        return State(generation=state.generation + 1)

    raise AssertionError(f"unhandled event: {event.value}")


def assert_state_invariants(state: State) -> None:
    # OEC-001: simultaneous authority can never straddle epochs.
    if state.host_application_authority and state.receiver_application_authority:
        assert state.host_confirmed_epoch == state.receiver_epoch

    assert state.host_confirmed_epoch <= state.host_local_epoch

    if state.host_phase is HostPhase.PENDING_ACK:
        assert state.host_cutover_active
        assert state.host_local_epoch == state.host_confirmed_epoch + 1
        assert not state.host_application_authority

    if state.receiver_phase is ReceiverPhase.PROPOSAL_AUTHENTICATED:
        assert not state.receiver_application_authority
        assert not state.ack_seq0_reserved

    if state.receiver_phase is ReceiverPhase.ACK_PENDING:
        assert not state.receiver_application_authority
        assert state.receiver_epoch == state.prepared_epoch
        assert state.ack_seq0_reserved

    if state.host_cutover_active:
        assert state.host_phase is not HostPhase.STABLE


def assert_transition_invariants(before: State, event: Event, after: State) -> None:
    # OEC-002: begin_send creates a one-way host ambiguity domain. Only delivery
    # of the exact valid current-transition Ack can restore Stable in-generation.
    if (
        before.host_cutover_active
        and before.generation == after.generation
        and not after.host_cutover_active
    ):
        assert event is Event.DELIVER_REVERSE_HEAD
        assert before.reverse_fifo
        ack = before.reverse_fifo[0]
        assert ack.kind is ReverseKind.ACK
        assert before.host_phase is HostPhase.PENDING_ACK
        assert ack.epoch == before.host_local_epoch
        assert after.host_phase is HostPhase.STABLE

    # OEC-003: receiver commit is monotonic within a connection generation.
    if before.generation == after.generation:
        assert after.receiver_epoch >= before.receiver_epoch
        if after.receiver_epoch > before.receiver_epoch:
            assert event is Event.RECEIVER_COMMIT
            assert after.receiver_epoch == before.prepared_epoch
            assert after.ack_seq0_reserved

    # OEC-004: if receiver resumes new-epoch app traffic before the host has
    # confirmed it, the exact same FIFO already contains that epoch's Ack ahead
    # of the newly appended application message.
    if (
        event is Event.RECEIVER_APP_ATTEMPT
        and before.receiver_application_authority
        and after.reverse_fifo != before.reverse_fifo
    ):
        appended = after.reverse_fifo[-1]
        assert appended.kind is ReverseKind.APP
        if (
            appended.epoch > before.host_confirmed_epoch
            and before.host_phase is not HostPhase.DEAD
        ):
            assert any(
                msg.kind is ReverseKind.ACK and msg.epoch == appended.epoch
                for msg in before.reverse_fifo
            )

    # OEC-005: ambiguity and invalid authority traffic fail closed.
    if event in (
        Event.PROPOSAL_SEND_FAIL_BEFORE_WRITE,
        Event.PROPOSAL_SEND_FAIL_AFTER_ESCAPE,
        Event.ACK_TIMEOUT,
    ):
        assert after.host_phase is HostPhase.DEAD

    if event in (
        Event.INVALID_PROPOSAL_WRONG_ROLE,
        Event.INVALID_PROPOSAL_PREVIOUS_KEY,
        Event.REPLAY_PROPOSAL,
        Event.RECEIVER_VALIDATION_FAIL,
        Event.ACK_SEND_FAIL_BEFORE_WRITE,
        Event.ACK_SEND_FAIL_AFTER_ESCAPE,
    ):
        assert after.receiver_phase is ReceiverPhase.DEAD

    if (
        event is Event.DELIVER_REVERSE_HEAD
        and before.reverse_fifo
        and before.reverse_fifo[0].kind
        in (
            ReverseKind.ACK_OLD_KEY,
            ReverseKind.ACK_WRONG_DOMAIN,
            ReverseKind.ACK_WRONG_SEQUENCE,
        )
    ):
        assert after.host_phase is HostPhase.DEAD

    # OEC-006: replay is never a second transition.
    if event is Event.REPLAY_PROPOSAL:
        assert after.receiver_epoch == before.receiver_epoch
    if event is Event.REPLAY_ACK:
        assert after.host_local_epoch == before.host_local_epoch
        assert after.host_confirmed_epoch == before.host_confirmed_epoch

    # OEC-007: only a fresh authenticated handshake changes generation, and it
    # clears all old-generation carrier/rekey state.
    if event is Event.FRESH_HANDSHAKE:
        assert after == State(generation=before.generation + 1)
    else:
        assert after.generation == before.generation


def _state_json(state: State) -> dict:
    return {
        "generation": state.generation,
        "host_phase": state.host_phase.value,
        "receiver_phase": state.receiver_phase.value,
        "host_local_epoch": state.host_local_epoch,
        "host_confirmed_epoch": state.host_confirmed_epoch,
        "receiver_epoch": state.receiver_epoch,
        "prepared_epoch": state.prepared_epoch,
        "proposal_available": state.proposal_available,
        "proposal_may_have_escaped": state.proposal_may_have_escaped,
        "proposal_delivered": state.proposal_delivered,
        "proposal_replay_epoch": state.proposal_replay_epoch,
        "ack_seq0_reserved": state.ack_seq0_reserved,
        "ack_may_have_escaped": state.ack_may_have_escaped,
        "ack_delivered": state.ack_delivered,
        "ack_replay_epoch": state.ack_replay_epoch,
        "host_cutover_active": state.host_cutover_active,
        "host_application_authority": state.host_application_authority,
        "receiver_application_authority": state.receiver_application_authority,
        "reverse_fifo": [
            {"kind": msg.kind.value, "epoch": msg.epoch}
            for msg in state.reverse_fifo
        ],
    }


def _trace_json(trace: tuple[Event, ...]) -> list[str]:
    return [event.value for event in trace]


def explore(max_depth: int) -> dict:
    initial = State()
    assert_state_invariants(initial)

    reached: set[State] = {initial}
    frontier: set[State] = {initial}
    first_trace: dict[State, tuple[Event, ...]] = {initial: tuple()}
    transitions: set[tuple[State, Event, State]] = set()
    checked_prefixes = 1
    witnesses: dict[str, tuple[Event, ...]] = {}

    for _depth in range(max_depth):
        next_frontier: set[State] = set()
        for state in frontier:
            trace = first_trace[state]
            for event in enabled_events(state):
                after = transition(state, event)
                assert_transition_invariants(state, event, after)
                assert_state_invariants(after)

                transitions.add((state, event, after))
                checked_prefixes += 1
                new_trace = trace + (event,)
                first_trace.setdefault(after, new_trace)
                reached.add(after)
                next_frontier.add(after)

                if event is Event.PROPOSAL_SEND_FAIL_AFTER_ESCAPE:
                    witnesses.setdefault("proposal_send_failure_after_escape", new_trace)
                if event is Event.RECEIVER_COMMIT and state.host_phase is HostPhase.DEAD:
                    witnesses.setdefault("receiver_commit_after_ambiguous_proposal", new_trace)
                if event is Event.RECEIVER_VALIDATION_FAIL:
                    witnesses.setdefault("receiver_validation_failure_before_commit", new_trace)
                if event is Event.ACK_SEND_FAIL_AFTER_ESCAPE:
                    witnesses.setdefault("ack_send_failure_after_escape", new_trace)
                if event is Event.PROPOSAL_SEND_FAIL_BEFORE_WRITE:
                    witnesses.setdefault("proposal_send_failure_before_write", new_trace)
                if (
                    event is Event.DELIVER_REVERSE_HEAD
                    and state.host_phase is HostPhase.PENDING_ACK
                    and state.reverse_fifo
                    and state.reverse_fifo[0].kind is ReverseKind.APP
                    and any(
                        msg.kind is ReverseKind.ACK
                        for msg in state.reverse_fifo[1:]
                    )
                ):
                    witnesses.setdefault("old_console_message_ahead_of_ack", new_trace)
                if (
                    event is Event.DELIVER_REVERSE_HEAD
                    and state.host_phase is HostPhase.PENDING_ACK
                    and state.reverse_fifo
                    and state.reverse_fifo[0].kind is ReverseKind.ACK
                ):
                    witnesses.setdefault("valid_ack_cutover", new_trace)
                if (
                    event is Event.DELIVER_REVERSE_HEAD
                    and state.host_phase is HostPhase.STABLE
                    and state.reverse_fifo
                    and state.reverse_fifo[0].kind is ReverseKind.ACK
                ):
                    witnesses.setdefault("duplicate_ack_rejected_after_confirmation", new_trace)
                if event is Event.DELIVER_REVERSE_HEAD and state.reverse_fifo:
                    invalid_name = {
                        ReverseKind.ACK_OLD_KEY: "old_key_ack_rejected",
                        ReverseKind.ACK_WRONG_DOMAIN: "wrong_domain_ack_rejected",
                        ReverseKind.ACK_WRONG_SEQUENCE: "wrong_sequence_ack_rejected",
                    }.get(state.reverse_fifo[0].kind)
                    if invalid_name:
                        witnesses.setdefault(invalid_name, new_trace)
                if event is Event.REPLAY_PROPOSAL:
                    witnesses.setdefault("replayed_proposal_rejected", new_trace)
                if (
                    event is Event.FRESH_HANDSHAKE
                    and (
                        state.reverse_fifo
                        or state.proposal_available
                        or state.proposal_may_have_escaped
                        or state.ack_may_have_escaped
                    )
                ):
                    witnesses.setdefault("fresh_handshake_clears_stale_carrier", new_trace)

        frontier = next_frontier

    canonical_states = sorted(
        (_state_json(state) for state in reached),
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
    )
    canonical_transitions = sorted(
        (
            {
                "before": _state_json(before),
                "event": event.value,
                "after": _state_json(after),
            }
            for before, event, after in transitions
        ),
        key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")),
    )
    digest_input = json.dumps(
        {"states": canonical_states, "transitions": canonical_transitions},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    required_witnesses = {
        "proposal_send_failure_before_write",
        "proposal_send_failure_after_escape",
        "receiver_commit_after_ambiguous_proposal",
        "receiver_validation_failure_before_commit",
        "ack_send_failure_after_escape",
        "old_console_message_ahead_of_ack",
        "valid_ack_cutover",
        "duplicate_ack_rejected_after_confirmation",
        "old_key_ack_rejected",
        "wrong_domain_ack_rejected",
        "wrong_sequence_ack_rejected",
        "replayed_proposal_rejected",
        "fresh_handshake_clears_stale_carrier",
    }
    missing = required_witnesses - witnesses.keys()
    assert not missing, f"missing representative witness traces: {sorted(missing)}"

    return {
        "schema": "xenia.operator-rekey-composition-model-report.v1",
        "model": "operator-rekey-v1-two-party-ordered-carrier",
        "claim_boundary": (
            "Bounded independent abstract-state composition under the modeled "
            "ordered reverse stream and fail-closed recovery assumptions; not "
            "a formal proof of implementation code, cryptography, carrier "
            "delivery, crash/hardware atomicity, scheduler, or OS behavior."
        ),
        "max_depth": max_depth,
        "bounded_max_key_epoch": MAX_EPOCH,
        "bounded_reverse_fifo_slots": MAX_REVERSE_FIFO,
        "checked_trace_prefixes": checked_prefixes,
        "reachable_state_count": len(reached),
        "transition_count": len(transitions),
        "state_graph_sha256": hashlib.sha256(digest_input).hexdigest(),
        "invariant_ids_checked": [f"OEC-{index:03d}" for index in range(1, 8)],
        "representative_traces": {
            name: _trace_json(trace) for name, trace in sorted(witnesses.items())
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-depth", type=int, default=12)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if args.max_depth < 1 or args.max_depth > 14:
        raise SystemExit("--max-depth must be between 1 and 14")

    report = explore(args.max_depth)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
