#!/usr/bin/env python3
"""Exhaustive safety model for the daemon-side operator rekey initiator.

This is deliberately independent of the Rust implementation.  It models the
security-relevant externally observable transition contract rather than calling
production code, then explores every enabled trace through a bounded number of
steps and checks invariants after every transition.

It is *not* a formal proof of the Rust program, transport, scheduler, or crypto.
It is executable design evidence that the intended state machine has no short
trace violating the fail-closed properties we claim in
OPERATOR_REKEY_INVARIANTS_V1.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable


class Phase(str, Enum):
    STABLE = "stable"
    PREPARED = "prepared"
    PENDING_ACK = "pending_ack"
    DEAD = "dead"


class Event(str, Enum):
    PREPARE = "prepare"
    SEND_OK = "send_ok"
    SEND_FAIL_BEFORE_WRITE = "send_fail_before_write"
    SEND_FAIL_AFTER_ESCAPE = "send_fail_after_escape"
    ACK_VALID_NEW_KEY = "ack_valid_new_key"
    ACK_OLD_KEY = "ack_old_key"
    ACK_WRONG_IDENTITY = "ack_wrong_identity"
    ACK_TIMEOUT = "ack_timeout"
    APPLICATION_TRAFFIC = "application_traffic"
    PEER_CLOSE = "peer_close"
    FRESH_HANDSHAKE = "fresh_handshake"


@dataclass(frozen=True, order=True)
class State:
    generation: int = 0
    phase: Phase = Phase.STABLE
    local_key_epoch: int = 0
    confirmed_key_epoch: int = 0
    proposal_may_have_escaped: bool = False

    @property
    def application_authority(self) -> bool:
        return self.phase is Phase.STABLE


@dataclass(frozen=True)
class Step:
    before: State
    event: Event
    after: State


MAX_EPOCH = 3


def enabled_events(state: State) -> Iterable[Event]:
    if state.phase is Phase.STABLE:
        yield Event.PREPARE
        yield Event.APPLICATION_TRAFFIC
        yield Event.PEER_CLOSE
    elif state.phase is Phase.PREPARED:
        yield Event.SEND_OK
        yield Event.SEND_FAIL_BEFORE_WRITE
        yield Event.SEND_FAIL_AFTER_ESCAPE
        yield Event.PEER_CLOSE
    elif state.phase is Phase.PENDING_ACK:
        yield Event.ACK_VALID_NEW_KEY
        yield Event.ACK_OLD_KEY
        yield Event.ACK_WRONG_IDENTITY
        yield Event.ACK_TIMEOUT
        yield Event.APPLICATION_TRAFFIC
        yield Event.PEER_CLOSE
    elif state.phase is Phase.DEAD:
        yield Event.FRESH_HANDSHAKE


def transition(state: State, event: Event) -> State:
    if event not in set(enabled_events(state)):
        raise AssertionError(f"disabled event {event} from {state}")

    if event is Event.PREPARE:
        return State(
            generation=state.generation,
            phase=Phase.PREPARED,
            local_key_epoch=state.local_key_epoch,
            confirmed_key_epoch=state.confirmed_key_epoch,
            proposal_may_have_escaped=False,
        )

    if event is Event.APPLICATION_TRAFFIC:
        if state.phase is Phase.STABLE:
            return state
        # Production treats application authority while rekey is unconfirmed as
        # a protocol violation and tears the authenticated channel down.
        return State(
            generation=state.generation,
            phase=Phase.DEAD,
            local_key_epoch=state.local_key_epoch,
            confirmed_key_epoch=state.confirmed_key_epoch,
            proposal_may_have_escaped=state.proposal_may_have_escaped,
        )

    if event is Event.SEND_OK:
        if state.local_key_epoch >= MAX_EPOCH:
            # The bounded model stops extending epochs instead of pretending an
            # unbounded integer proof.  Fresh handshake remains modeled below.
            return State(
                generation=state.generation,
                phase=Phase.DEAD,
                local_key_epoch=state.local_key_epoch,
                confirmed_key_epoch=state.confirmed_key_epoch,
                proposal_may_have_escaped=True,
            )
        return State(
            generation=state.generation,
            phase=Phase.PENDING_ACK,
            local_key_epoch=state.local_key_epoch + 1,
            confirmed_key_epoch=state.confirmed_key_epoch,
            proposal_may_have_escaped=True,
        )

    if event in (Event.SEND_FAIL_BEFORE_WRITE, Event.SEND_FAIL_AFTER_ESCAPE):
        return State(
            generation=state.generation,
            phase=Phase.DEAD,
            local_key_epoch=state.local_key_epoch,
            confirmed_key_epoch=state.confirmed_key_epoch,
            proposal_may_have_escaped=event is Event.SEND_FAIL_AFTER_ESCAPE,
        )

    if event is Event.ACK_VALID_NEW_KEY:
        return State(
            generation=state.generation,
            phase=Phase.STABLE,
            local_key_epoch=state.local_key_epoch,
            confirmed_key_epoch=state.local_key_epoch,
            proposal_may_have_escaped=True,
        )

    if event in (Event.ACK_OLD_KEY, Event.ACK_WRONG_IDENTITY, Event.ACK_TIMEOUT):
        return State(
            generation=state.generation,
            phase=Phase.DEAD,
            local_key_epoch=state.local_key_epoch,
            confirmed_key_epoch=state.confirmed_key_epoch,
            proposal_may_have_escaped=True,
        )

    if event is Event.PEER_CLOSE:
        return State(
            generation=state.generation,
            phase=Phase.DEAD,
            local_key_epoch=state.local_key_epoch,
            confirmed_key_epoch=state.confirmed_key_epoch,
            proposal_may_have_escaped=state.proposal_may_have_escaped,
        )

    if event is Event.FRESH_HANDSHAKE:
        return State(generation=state.generation + 1)

    raise AssertionError(f"unhandled event: {event}")


def assert_state_invariants(state: State) -> None:
    # ORI-005 / ORI-010: authority exists only in Stable, never while a
    # transition is prepared, awaiting confirmation, or dead.
    assert state.application_authority == (state.phase is Phase.STABLE)

    # Stable state reached after a possibly escaped Proposal is only safe after
    # exact new-key confirmation.  The initial/fresh-handshake Stable state has
    # proposal_may_have_escaped == False.
    if state.phase is Phase.STABLE and state.proposal_may_have_escaped:
        assert state.local_key_epoch > 0
        assert state.confirmed_key_epoch == state.local_key_epoch

    # Confirmation cannot run ahead of local key commit.
    assert state.confirmed_key_epoch <= state.local_key_epoch

    # A pending Ack always follows the one-way local new-key commit and cannot
    # already be confirmed.
    if state.phase is Phase.PENDING_ACK:
        assert state.proposal_may_have_escaped
        assert state.local_key_epoch == state.confirmed_key_epoch + 1
        assert not state.application_authority

    if state.phase in (Phase.PREPARED, Phase.DEAD):
        assert not state.application_authority


def assert_transition_invariants(step: Step) -> None:
    before, event, after = step.before, step.event, step.after

    # ORI-002/004: the local traffic-key epoch advances only after a locally
    # successful Proposal send.  Neither kind of reported send failure commits.
    if after.local_key_epoch > before.local_key_epoch:
        assert event is Event.SEND_OK
        assert after.local_key_epoch == before.local_key_epoch + 1
    if event in (Event.SEND_FAIL_BEFORE_WRITE, Event.SEND_FAIL_AFTER_ESCAPE):
        assert after.local_key_epoch == before.local_key_epoch
        assert after.phase is Phase.DEAD

    # The nastiest carrier ambiguity is explicitly represented: the complete
    # Proposal may have escaped even though send reports failure.  It must never
    # return to Stable in the same connection generation.
    if event is Event.SEND_FAIL_AFTER_ESCAPE:
        assert after.proposal_may_have_escaped
        assert after.phase is Phase.DEAD

    # ORI-007/008/009: only the exact new-key Ack confirms.  Old-key Ack,
    # identity mismatch, and timeout are terminal for the current connection.
    if before.phase is Phase.PENDING_ACK:
        if event is Event.ACK_VALID_NEW_KEY:
            assert after.phase is Phase.STABLE
            assert after.confirmed_key_epoch == after.local_key_epoch
        elif event in (
            Event.ACK_OLD_KEY,
            Event.ACK_WRONG_IDENTITY,
            Event.ACK_TIMEOUT,
            Event.APPLICATION_TRAFFIC,
            Event.PEER_CLOSE,
        ):
            assert after.phase is Phase.DEAD

    # ORI-010: the only transition out of Dead is a fresh handshake, which
    # creates a new connection generation and resets all rekey state.
    if before.phase is Phase.DEAD:
        assert event is Event.FRESH_HANDSHAKE
        assert after.phase is Phase.STABLE
        assert after.generation == before.generation + 1
        assert after.local_key_epoch == 0
        assert after.confirmed_key_epoch == 0
        assert not after.proposal_may_have_escaped

    if event is not Event.FRESH_HANDSHAKE:
        assert after.generation == before.generation


def explore(max_depth: int) -> dict:
    initial = State()
    assert_state_invariants(initial)

    frontier: list[tuple[State, tuple[Event, ...]]] = [(initial, tuple())]
    reached: set[State] = {initial}
    transitions: set[tuple[State, Event, State]] = set()
    checked_prefixes = 1
    longest_trace: tuple[Event, ...] = tuple()

    for _depth in range(max_depth):
        next_frontier: list[tuple[State, tuple[Event, ...]]] = []
        for state, trace in frontier:
            for event in enabled_events(state):
                after = transition(state, event)
                step = Step(state, event, after)
                assert_transition_invariants(step)
                assert_state_invariants(after)
                transitions.add((state, event, after))

                new_trace = trace + (event,)
                checked_prefixes += 1
                if len(new_trace) > len(longest_trace):
                    longest_trace = new_trace
                reached.add(after)
                next_frontier.append((after, new_trace))
        frontier = next_frontier

    canonical_states = [
        {
            **asdict(state),
            "phase": state.phase.value,
            "application_authority": state.application_authority,
        }
        for state in sorted(reached)
    ]
    canonical_transitions = [
        {
            "before": {
                **asdict(before),
                "phase": before.phase.value,
            },
            "event": event.value,
            "after": {
                **asdict(after),
                "phase": after.phase.value,
            },
        }
        for before, event, after in sorted(
            transitions,
            key=lambda item: (item[0], item[1].value, item[2]),
        )
    ]

    digest_input = json.dumps(
        {"states": canonical_states, "transitions": canonical_transitions},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    return {
        "schema": "xenia.operator-rekey-state-model-report.v1",
        "model": "daemon-initiator-fail-closed-v1",
        "claim_boundary": (
            "Bounded exhaustive abstract-state exploration; not a formal proof "
            "of Rust implementation, cryptography, transport, scheduler, or hardware."
        ),
        "max_depth": max_depth,
        "bounded_max_key_epoch": MAX_EPOCH,
        "checked_trace_prefixes": checked_prefixes,
        "reachable_state_count": len(reached),
        "transition_count": len(transitions),
        "longest_trace_length": len(longest_trace),
        "state_graph_sha256": hashlib.sha256(digest_input).hexdigest(),
        "properties_checked": [
            "authority iff Stable",
            "send failure never commits local key",
            "reported failure after possible Proposal escape cannot restore authority",
            "only successful send advances local key epoch",
            "only exact new-key Ack confirms pending epoch",
            "old-key/wrong-identity Ack and timeout fail closed",
            "application traffic during PendingAck fails closed",
            "Dead can return to Stable only through a fresh handshake generation",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-depth", type=int, default=9)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()
    if args.max_depth < 1 or args.max_depth > 12:
        raise SystemExit("--max-depth must be between 1 and 12")

    report = explore(args.max_depth)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
