# Xenia Visual System v0.1

Status: initial implementation, visual changes only
Prepared: 2026-11-16
Scope: Xenia Sovereign Operations Console and the next native-viewer design increment.

## Product direction

Xenia should look like a calm, precise instrument for granting and observing remote authority. It should not look like a neon hacker dashboard, a generic admin template, or a gaming overlay.

The visual hierarchy is:

1. **Who is connected?** Identity, target device and connection path.
2. **What authority exists?** Requested and granted capabilities, operation scope, direction and expiry.
3. **What is happening now?** Active effects, stream health, queues, frame freshness and errors.
4. **What evidence exists?** Approval/denial/revocation history, signed checkpoints and verifiable artifacts.

The user should never need to infer a security state from an icon, color or animation alone. Labels and the underlying authorization state remain authoritative.

## Visual language

- Deep graphite/navy surfaces, high-contrast text and restrained sea-glass accent.
- Teal is reserved for primary action, focus and neutral protocol activity; green is for a positively established healthy/approved state; amber is for pending/attention; red is for denial, failure or revocation where that is the actual meaning.
- Avoid large glow effects, constant animation, tiny all-caps labels and dense monospaced body text.
- Use monospaced text only for identifiers, hashes, addresses and machine evidence.
- Use generous spacing around consent, revocation and other high-consequence actions.
- Tables remain data-dense, but row hover, tabular numerals, clear column hierarchy and horizontal overflow should keep them scannable.
- At narrow widths, navigation wraps or scrolls and data tables may scroll horizontally; action controls remain reachable.

## Initial design tokens

The current implementation lives in `apps/sovereign-admin/styles/main.css`.

| Token | Purpose |
|---|---|
| `--bg` | Application canvas |
| `--bg-elevated` | Header / elevated shell |
| `--surface`, `--surface-raised` | Cards, dialogs and grouped content |
| `--fg`, `--fg-dim`, `--fg-muted` | Primary, secondary and tertiary text |
| `--accent`, `--accent-strong` | Primary action and keyboard focus |
| `--ok`, `--warn`, `--err` | Semantic state colors |
| `--border`, `--border-strong` | Surface and control boundaries |
| `--radius-sm/md/lg` | Consistent component geometry |

The CSS refresh preserves existing Leptos component classes and route behavior. It is a styling foundation, not proof of WCAG conformance. Calculated contrast for the directly paired declared tokens is 16.71:1 for primary text/background, 8.16:1 for secondary text/background, 4.59:1 for muted text/surface, and 10.90:1 for accent-on-primary-button text. These calculations do not replace sampling every rendered/translucent component state in a browser.

## Security-state presentation rules

- Distinguish unknown, connecting, connected, degraded, denied, revoked and expired. Do not collapse unknown into disconnected or healthy.
- Approval, denial and revocation use explicit text in addition to color.
- An operator role chip shows the daemon-granted role; it must not be styled like a DID login or imply broader authority.
- A consent prompt should ultimately show requester, target, purpose, exact requested operations, data scope, direction, duration/expiry, persistence, and the consequences/limits of revocation before its decision buttons.
- Denial must remain visually discoverable and as easy to choose as approval.
- A signed consent record is evidence of a recorded decision, not proof of understanding, voluntariness or absence of coercion.
- A completed session does not mean its effects have been reversed. Revocation prevents future authorized effects; it cannot undo completed actions.

## Interaction and accessibility baseline

Target WCAG 2.2 AA as an engineering baseline, with stronger touch sizing where practical:

- Normal text contrast at least 4.5:1; large text at least 3:1.
- UI boundaries, control states and meaningful graphics at least 3:1 against adjacent colors.
- Never use color as the sole signal for state or action.
- Provide a persistent, visible keyboard-focus indicator.
- Reflow at 320 CSS px without loss of information/functionality except genuinely two-dimensional content such as wide evidence tables.
- Text must remain usable at 200% zoom.
- Respect `prefers-reduced-motion`.
- Aim for 40–44 CSS px minimum control heights on primary interactive controls.
- Dialogs need semantic names, initial focus, a contained Tab sequence, Escape behavior where appropriate, inert background interaction and focus restoration. CSS overlay styling alone is not a compliant modal implementation.

Reference: [W3C WCAG 2.2](https://www.w3.org/TR/wcag/) and [WAI-ARIA modal dialog pattern](https://www.w3.org/WAI/ARIA/apg/patterns/dialog-modal/).

## Native viewer visual direction (next increment)

The viewer is a different product surface from the browser admin console. Preserve the large screen workspace and remote input coordinates; improve the surrounding shell:

- **Top session rail:** target/identity, direct vs relay transport, encrypted-session status, granted authority and explicit disconnect.
- **Workspace:** scale-to-fit by default with an explicit 1:1 mode; never change the coordinate transform silently while input is captured.
- **Inspector:** collapsible Host, Stream and Audio sections with clear status labels and disclosure of advanced counters.
- **Stream health:** show displayed FPS, frame age only when clock semantics permit it, bitrate, dropped/stale frames and bounded queue pressure; distinguish measured from unavailable.
- **Privacy:** host telemetry and identity fields are shown only when permitted; redact by default in shared screenshots and exported diagnostics.
- **Input state:** visible indication when remote input is disabled, awaiting authority or revoked; do not confuse local pointer focus with remote-control authority.
- **Accessibility:** keyboard navigation around the viewer chrome must never synthesize remote key events while focus is in a local control.

The current native GUI has a status strip and always-visible Host/Audio telemetry columns. Refactor this separately with explicit GUI tests for image-rectangle normalization and local-vs-remote focus before altering layout.

## Verification checklist for each visual PR

- No protocol, cryptographic, consent authorization, ledger or transport behavior changes.
- Existing route/test IDs and functional controls remain intact.
- Desktop width (1440 px), tablet width (768 px), narrow mobile width (360 px) and 320 CSS px reflow inspection.
- 200% zoom inspection.
- Keyboard-only navigation and visible focus.
- Reduced-motion setting.
- Contrast sampling for body text, muted text, buttons, status chips and borders.
- Consent-dialog keyboard and screen-reader semantics tested independently from its appearance.
- Screenshots from a real browser build are attached before calling the visual pass complete.

## Phased delivery

1. **Console foundation:** visual tokens, header/navigation, typography, controls, tables, evidence panels and modal appearance. No runtime behavior changes.
2. **Consent interaction:** semantic and keyboard-correct dialog, clear request summary, explicit effect scope and denial/revocation communication.
3. **Native viewer shell:** session rail, responsive workspace, collapsible diagnostics and local/remote focus separation.
4. **Polish and validation:** real-browser screenshot review, accessibility audit, high-DPI/Wayland testing, empty/loading/error states, and usability testing with remote operators and recipients.
