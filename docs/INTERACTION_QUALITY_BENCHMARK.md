# Xenia Interaction Quality Benchmark v0.1

Status: research and evaluation specification; no product conformance or usability result claimed  
Related: #496, #497, #455, #392, #460, #461, #463, PR #462, #469, #471

## 1. Purpose

Xenia should make remote computing understandable and governable, not merely attractive. The goal is **calibrated trust**: people should understand what the software knows, what it is doing, what authority exists, what remains uncertain, and how to stop or limit an interaction.

A visually polished interface can still be unsafe if it makes stale evidence look current, presents an identity as verified when it is only self-reported, implies that dismissal is denial, or hides the difference between ending a viewer window and revoking remote authority.

This benchmark therefore evaluates three surfaces as one human-facing system:

- **Sovereign Operations Console:** device, identity, session, policy, operator and evidence management.
- **Consent Experience:** the authority boundary at which a recipient reviews and decides a request.
- **Xenia Viewer:** the live remote workspace, input boundary, stream state and recovery controls.

The benchmark is presentation and interaction assurance. It does not modify or replace daemon authorization, signed consent payloads, protocol semantics, cryptographic verification, or remote-input enforcement.

## 2. The paradigm shift: from reassuring appearance to observable control

Conventional dashboard quality is often judged by visual consistency, task completion and subjective satisfaction. Those remain useful, but they are insufficient for a high-consequence remote-control application.

Xenia should make five shifts:

1. **From status colors to state provenance.** A green badge is not an explanation. Each security-relevant claim must be labelled with the subsystem that establishes it and the evidence/freshness available.
2. **From permission labels to effect previews.** People should see what an operation actually enables, which direction data can move, what the target is, and what duration or persistence applies.
3. **From trust-by-brand to calibrated trust.** Measure whether user confidence tracks the true state. A user who feels confident while misunderstanding authority is a failure, not a success.
4. **From hidden recovery to first-class control.** Deny, dismiss, revoke, disconnect and recover must have distinct meanings and discoverable paths.
5. **From visual-only accessibility to semantic interaction.** The same state and controls must be exposed through keyboard navigation, browser accessibility semantics and the native accessibility tree.

The design objective is not to maximise approval, session duration, or perceived reassurance. It is to minimise dangerous misunderstanding while keeping legitimate work efficient.

## 3. A state model the interface must preserve

Never collapse these distinct facts into a single generic "secure" or "connected" indicator.

| Dimension | What the interface may say | What it must not imply |
|---|---|---|
| Identity | Verified peer identity, or explicitly unverified identity | A display name alone proves identity |
| Transport | Direct, relayed, reconnecting, or unknown path when measured | Direct means safer, or unknown means direct |
| Cryptographic channel | Encrypted/verified only when the relevant handshake state establishes it | A lock icon proves endpoint trust or authorization |
| Authorization | Exact daemon-granted capability set and its current status | UI visibility creates permission |
| Remote input | Enabled, disabled, awaiting authority, or unavailable according to the actual input state | Pointer focus alone grants remote control |
| Stream | Receiving, stale, paused, degraded, or unavailable, with measurement semantics | Update rate equals display presentation FPS |
| Evidence | Verified record, locally observed event, peer-reported event, or unavailable evidence | A signed record proves comprehension or voluntariness |

Unknown, unavailable, stale, expired, denied, revoked, degraded, reconnecting and healthy are separate states. Missing telemetry must never default to healthy.

For timing, use a local monotonic receipt clock for "received X ago" measurements. Do not calculate an age by subtracting unsynchronised host and client wall clocks. If a raw host timestamp is displayed, label its clock domain.

Every displayed claim should have a traceable source in the implementation. Presentation code may format an authoritative state; it must not invent or promote that state.

## 4. Surface-specific design requirements

### 4.1 Sovereign Operations Console

Organise the information hierarchy around operator questions:

1. Who is the peer, operator and target device?
2. What authority was requested and what authority is currently granted?
3. What is happening now, and what is measured versus unavailable?
4. What changed, who initiated it, and what evidence supports the statement?
5. What can the operator safely do next?

Separate DID authentication from operator-role authorization. Distinguish a signed audit record from a live session state. Make stale evidence visible. High-density evidence tables may use two-dimensional scrolling where the data genuinely requires it, but the surrounding page and actions must still reflow.

### 4.2 Consent Experience

The consent decision should be a short, inspectable capability contract:

- requester and verified identity status;
- target device and display being accessed;
- requested operations (view, input, clipboard, audio, file transfer, or other capabilities only when they actually exist);
- data direction and scope;
- duration, expiry and persistence;
- consequences and limitations of ending, dismissing, denying and revoking;
- any material uncertainty or missing information.

Use plain language first; expose technical identifiers and signed evidence as supporting detail. Approval and denial must be distinct, deliberate actions. Dismissal must not silently approve or deny. Initial focus should not land on the consequential approval action.

A request that is stale, expired, mismatched to a session, or ambiguous must not be made to look valid by a more polished dialog. The daemon remains authoritative.

### 4.3 Xenia Viewer

Use a persistent session rail and a dominant workspace. The rail should answer, at a glance:

- which peer/device is being viewed;
- whether identity has been verified;
- the observed transport path;
- which capabilities are currently granted;
- whether remote input is actually enabled;
- whether the stream is current, degraded or unavailable;
- how to end the session or take the supported revocation action.

The inspector should be collapsible and grouped into Stream, Host and Audio. Show only useful high-level signals by default; expose advanced counters on demand. Label host-reported and locally measured values separately.

The person at the remote host also needs a persistent, locally accessible indication when their screen is being viewed or controlled, with a clearly named way to stop the relevant access. This is the human-facing realization of the existing security requirement in [#392](https://github.com/Luminous-Dynamics/xenia-peer/issues/392), which already calls for a visible session indicator and mid-session revoke; this benchmark does not create a duplicate authority feature. The exact UI surface is platform-dependent and should be implemented only where its semantics are reliable. A controller-side toolbar is not a substitute for recipient-side visibility.

Fit and 1:1 modes are explicit. Any future zoom, pan, scaling, multi-monitor or inspector resize work must preserve the source-image coordinate contract.

## 5. Benchmark protocol

Run separate tasks for recipients and operators. Record the task wording, participant role, platform, assistive technology (where used), build SHA, test data, and observed outcomes. Do not combine unlike tasks into one average score.

### A. Consent comprehension

Show scenarios with varied identity, target, operation scope, data direction and expiry. After the user reviews the request, ask them to identify:

- who is requesting access;
- which device/screen is the target;
- what the requester can and cannot do;
- what data can move in each direction;
- when the access expires and whether it persists;
- what dismissal does;
- what revocation can prevent and what it cannot undo.

**Primary measures:** correctness per critical fact, critical misunderstandings, decision choice, confidence, and time to decision.

**Formative target:** at least 90% correct on each critical fact, not merely on an aggregate average. Any critical misunderstanding about target, operation scope, data direction or duration triggers redesign even when the aggregate score passes. Before beta, target 95% or better on each critical fact across a larger, preregistered sample.

### B. Decision quality and negative controls

Include at least these scenarios:

1. a valid, narrow, time-bounded request;
2. a request that adds an unexpected capability;
3. a request for the wrong target device;
4. a stale or expired request;
5. a request whose identity or scope cannot be verified;
6. a reconnect in which the session identity or correlation context changes.

Measure dangerous false approval separately from ordinary errors. A critical false approval blocks the tested design from passing. Report the number of participants and scenarios; zero observed errors in a small formative study is not proof of zero population risk.

### C. Control and recovery

Ask users to dismiss without deciding, deny, revoke, disconnect, identify whether remote input is active, and recover after a simulated stream or transport degradation.

Measure success rate, action count, time-to-deny, time-to-revoke, time-to-disconnect, and unintended actions. Do not optimise approval speed as a primary metric. A safer action being slower is acceptable when the extra time supports comprehension; a safe stop being hard to find is not.

### D. State calibration

Present connected, connecting, relayed, degraded, frozen/stale-frame, revoked, expired, unknown-identity and unavailable-telemetry states. Ask users what is known, what remains uncertain and what actions are currently possible.

Measure both correctness and confidence. Compare confidence against actual correctness using a calibration score (for example, Brier score for probability judgements) and report overconfidence on high-consequence mistakes separately.

### E. Usability and workload

Record task completion, task time, errors, number of help requests and a standard usability/workload measure. Use SUS or UMUX-Lite for perceived usability and NASA-TLX where task workload is material. These are complementary measures; none is a substitute for consent comprehension or authorization-safety testing.

## 6. Accessibility and visual validation gates

### Browser console and consent

Target WCAG 2.2 Level AA. At minimum, validate:

- 4.5:1 contrast for normal text and 3:1 for large text;
- 3:1 non-text contrast for meaningful control boundaries and state indicators;
- keyboard operation, visible focus, and focus not obscured;
- status messages exposed to assistive technology;
- semantic names, descriptions and lifecycle for modal dialogs;
- no loss of information or functionality at 320 CSS px reflow, except genuinely two-dimensional content;
- text resizing to 200%, and 400% zoom/reflow testing;
- text-spacing overrides and reduced-motion preferences;
- touch targets that meet WCAG 2.2 minimum requirements, with 40–44 CSS px as the preferred Xenia design target where practical.

The 40–44 CSS px target is a product usability preference, not the WCAG 2.2 AA minimum. Keep those two claims separate.

Automated accessibility scans are useful for regressions, but they cannot establish full conformance. Run keyboard-only and screen-reader checks in real browsers and record the browser, OS and assistive-technology versions.

### Native viewer

The current viewer manifest disables eframe default features and does not explicitly enable `accesskit`. Investigate the pinned eframe 0.29.1 implementation and supported platform adapters before changing dependency features. Then test accessible roles, names, enabled state and status updates through the accessibility tree.

Do not pull a current egui testing crate into the pinned 0.29 dependency graph without verifying version compatibility. The harness and application should use compatible egui/eframe versions.

### Visual regression matrix

Capture reproducible screenshots for:

- 1440 CSS px desktop;
- 768 CSS px tablet;
- 360 CSS px mobile;
- 320 CSS px reflow;
- 200% text resize;
- 400% browser zoom/reflow;
- empty, loading, pending, denied, revoked, degraded, stale and error states;
- reduced-motion preference;
- keyboard focus on every primary action and dialog control.

Attach screenshots to the PR and record the exact build/commit. A screenshot is evidence of rendering, not evidence of protocol correctness or WCAG conformance.

## 7. Remote-input invariants (non-negotiable)

Every viewer layout or interaction change must preserve all of the following:

- source coordinates are normalised against the actual displayed image rectangle, not the window or inspector;
- positions outside the visible clip are rejected;
- local UI keyboard focus never sends new remote key-down events;
- losing the remote image target releases previously forwarded keys and pointer buttons exactly once;
- key-up corresponds only to a previously forwarded key-down and preserves the required modifier state;
- pointer release remains paired with a forwarded press even if the physical release occurs outside the image;
- revoked, expired, disconnected or unknown authority fails closed at the enforcement point.

Unit tests and GUI harness tests should cover these transitions. Interactive tests on real DPI/scaling and window-focus combinations remain necessary.

## 8. Competitive baseline and Xenia's differentiation

Existing remote-support products already establish a substantial baseline. Official product documentation shows:

| Product | Documented interaction baseline | Implication for Xenia |
|---|---|---|
| TeamViewer | In-session toolbar with quick actions and controls; an attended-session screen-sharing indicator with a visible end-session affordance on supported Windows configurations | A session toolbar and a recipient-visible indicator are product hygiene, not a unique differentiator |
| RustDesk | Incoming access modes (custom/full/view) and distinct toggles for keyboard/mouse, clipboard, file transfer, audio, terminal, TCP tunnel, restart and recording; RustDesk Server Pro further separates device access control from in-session Control Roles | Granular permissions and role policy already exist in the market; Xenia must demonstrate a more inspectable, per-session explanation and evidence binding, not merely checkbox granularity |
| AnyDesk | A recipient-authorized Screen Privacy / Privacy Mode that hides remote screen contents and blocks remote-side input and sound while enabled; permission must be granted by the remote client | Recipient control and privacy modes are also established. Xenia should explain the exact effects and limitations of each control, including what it cannot undo |

Sources: [TeamViewer remote-session toolbar](https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-remote/remote-control/remote-session-toolbar/), [TeamViewer screen-sharing indicator](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/security/enable-screen-sharing-indicator-for-your-remote-sessions/), [RustDesk incoming access permissions](https://rustdesk.com/docs/en/self-host/client-configuration/advanced-settings/), [RustDesk Control Roles](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/control-role/), [RustDesk Access Control](https://rustdesk.com/docs/en/self-host/rustdesk-server-pro/permissions/), and [AnyDesk Screen Privacy](https://support.anydesk.com/docs/screen-privacy).

These are documented feature baselines, not independent measurements of usability, accessibility, reliability, security, or user comprehension. Documentation does not establish that the products behave identically across all platforms, plans or deployment modes. Any performance or UX superiority claim requires matched, reproducible testing.

Xenia's proposed differentiation should therefore be a stronger **authority-and-evidence interaction contract**:

- **Per-session effect preview:** show exactly which capabilities are requested, for which target, by which verified requester, for what purpose, in which data direction, and until when. Capability labels must correspond to the canonical request, not a client-authored summary.
- **Evidence provenance:** for each high-consequence state, identify whether it comes from daemon-enforced authority, authenticated peer identity, transport observation, local measurement or peer-reported telemetry.
- **Explicit uncertainty:** missing, stale, unverified and unavailable information remains visible as such. Do not make a session look healthy merely because a field is absent.
- **Recipient-side control:** make viewing/controlling state visible at the host and provide the supported local stop path, aligned with the existing [#392](https://github.com/Luminous-Dynamics/xenia-peer/issues/392) requirement for a visible indicator and mid-session revocation.
- **Bounded claims:** make it clear that a signed consent event proves the recorded decision and bound request, not comprehension, voluntariness, downstream deletion or reversal of completed effects, as specified in [#455](https://github.com/Luminous-Dynamics/xenia-peer/issues/455).
- **Fail-closed transitions:** on expiry, revocation, identity/session mismatch or reconnect ambiguity, new remote effects remain blocked until the authoritative state is reconciled.

This is a research differentiation hypothesis, not a claim that Xenia currently outperforms commercial products. The consent UI presently renders a free-form scope string; the complete structured contract and its canonical binding remain follow-up work under #455, #460 and #496.

## 9. Evidence ledger for every release

Report these evidence classes separately:

| Evidence class | Example | What it proves |
|---|---|---|
| Structural | source review, state-source mapping, invariant tests | intended code paths and boundaries exist |
| Automated | format, build, unit, browser and accessibility checks | specified checks passed at an exact SHA |
| Rendered | real-browser screenshots and DPI captures | the recorded rendering at the recorded viewport |
| Assistive technology | keyboard and screen-reader test record | observed behavior with named AT/platform versions |
| Human factors | task results and comprehension data | observed user outcomes for the stated sample and tasks |
| Enforcement | daemon-side stale/replay/authorization tests | the enforcement boundary rejects invalid operations |

A green CI job does not prove a human understands consent. A strong contrast ratio does not prove a layout works at 320px. A signed consent event does not prove voluntariness. Keep these distinctions in the release evidence.

## 10. Delivery sequence

1. **Now:** keep the three existing surfaces separate; complete review of #462, #469, #471 and the input-safety work; resolve exact-head failures without weakening supply-chain or security gates.
2. **Next:** build browser keyboard/focus tests and a 320px/200%/400% visual regression matrix for the console and consent surface.
3. **In parallel:** investigate the pinned native eframe AccessKit feature and accessible-tree coverage (#497).
4. **Then:** run the first small formative recipient/operator study using the protocol in #496. Publish failures and sample limitations.
5. **Before beta:** repeat with a larger, preregistered cohort, independently review accessibility, and publish the evidence ledger.

## References

- [W3C WCAG 2.2](https://www.w3.org/TR/WCAG22/)
- [W3C Understanding Reflow (1.4.10)](https://www.w3.org/WAI/WCAG22/Understanding/reflow.html)
- [WAI-ARIA Authoring Practices: Modal Dialog Pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/)
- [egui accessibility guide](https://github.com/emilk/egui/blob/main/docs/accessibility.md)
- [egui/eframe 0.29.1 accessibility notes](https://docs.rs/crate/egui/0.29.1)
- [TeamViewer remote-session toolbar](https://www.teamviewer.com/en/global/support/knowledge-base/teamviewer-remote/remote-control/remote-session-toolbar/)
- [TeamViewer screen-sharing indicator](https://www.teamviewer.com/en-us/global/support/knowledge-base/teamviewer-remote/security/enable-screen-sharing-indicator-for-your-remote-sessions/)
