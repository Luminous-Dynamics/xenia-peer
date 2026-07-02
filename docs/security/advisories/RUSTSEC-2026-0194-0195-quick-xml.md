# RUSTSEC-2026-0194 / RUSTSEC-2026-0195 — quick-xml 0.39.x advisories

Status: temporary transitive dependency exception.

## Advisories

- RUSTSEC-2026-0194: duplicate-attribute checking can become quadratic.
- RUSTSEC-2026-0195: `NsReader` namespace declaration handling can allocate without a bounded per-element namespace declaration limit.

Both advisories are remediated by `quick-xml >= 0.41.0`.

## Why this is present

`quick-xml 0.39.2` is still pulled transitively by:

- `plist -> netdev -> netwatch -> iroh`
- `wayland-scanner -> smithay/winit/eframe GUI build stack`

A direct `cargo update -p quick-xml --precise 0.41.0` cannot remove the vulnerable minor line while parent crates require `quick-xml ^0.39.2`.

## Xenia exposure note

Xenia does not directly parse untrusted XML through `quick-xml`.

The exception is still treated as release debt because the vulnerable crate is present in the resolved dependency graph. The highest-risk runtime path to keep watching is the `plist -> netdev -> netwatch -> iroh` path. The `wayland-scanner` path is build/code-generation related through the GUI stack.

## Removal condition

Remove both deny exceptions when dependency resolution can move all `quick-xml` instances to `>= 0.41.0`.

Validation commands:

```bash
cargo update -p iroh -p netwatch -p netdev -p plist -p wayland-scanner
cargo tree -i quick-xml@0.39.2
cargo deny check advisories bans licenses sources

Update the `deny.toml` references so both advisory reasons point to the combined doc:

```bash id="mjh8et"
python3 - <<'PY'
from pathlib import Path

p = Path("deny.toml")
s = p.read_text()
s = s.replace(
    "docs/security/advisories/RUSTSEC-2026-0194-quick-xml.md",
    "docs/security/advisories/RUSTSEC-2026-0194-0195-quick-xml.md",
)
p.write_text(s)
PY
