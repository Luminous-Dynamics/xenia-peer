# RUSTSEC-2026-0194 — quick-xml duplicate attribute CPU exhaustion

Status: temporary transitive build-time dependency exception.

## Why this is present

`quick-xml 0.39.2` is pulled transitively by:

- `wayland-scanner v0.31.10`
- `wayland-scanner -> smithay/winit/eframe GUI build stack`

Normal compatible updates currently keep the same `quick-xml 0.39.x` line.

## Xenia exposure note

Xenia does not directly parse untrusted XML through `quick-xml`.

The remaining advisory path is through `wayland-scanner`, a procedural
macro/code-generation dependency used by the Wayland GUI stack. This is treated
as release debt because the vulnerable crate is still present in the lock graph,
but it is not a known runtime XML ingestion path in Xenia.

## Removal condition

Remove the deny exception when dependency resolution can move all `quick-xml`
instances to `>= 0.41.0`.

Validation commands:

```bash
cargo update -p wayland-scanner
cargo tree -i quick-xml@0.39.2
cargo deny check advisories bans licenses sources


Now add the advisory ignore to `deny.toml`. This script preserves the existing `[advisories]` section if present:

```bash id="lzwb26"
python3 - <<'PY'
from pathlib import Path

p = Path("deny.toml")
s = p.read_text()

advisory = '"RUSTSEC-2026-0194"'

if advisory in s:
    print("RUSTSEC-2026-0194 already present in deny.toml")
    raise SystemExit(0)

lines = s.splitlines()
out = []
in_adv = False
inserted = False

for i, line in enumerate(lines):
    stripped = line.strip()

    if stripped == "[advisories]":
        in_adv = True
        out.append(line)
        continue

    if in_adv and stripped.startswith("[") and stripped.endswith("]"):
        out.extend([
            "",
            "ignore = [",
            "  # Temporary: quick-xml 0.39.2 is pulled by wayland-scanner",
            "  # in the Wayland GUI build/codegen stack. See:",
            "  # docs/security/advisories/RUSTSEC-2026-0194-quick-xml.md",
            f"  {advisory},",
            "]",
        ])
        inserted = True
        in_adv = False

    out.append(line)

if in_adv and not inserted:
    out.extend([
        "",
        "ignore = [",
        "  # Temporary: quick-xml 0.39.2 is pulled by wayland-scanner",
        "  # in the Wayland GUI build/codegen stack. See:",
        "  # docs/security/advisories/RUSTSEC-2026-0194-quick-xml.md",
        f"  {advisory},",
        "]",
    ])
    inserted = True

if not inserted:
    out.extend([
        "",
        "[advisories]",
        "ignore = [",
        "  # Temporary: quick-xml 0.39.2 is pulled by wayland-scanner",
        "  # in the Wayland GUI build/codegen stack. See:",
        "  # docs/security/advisories/RUSTSEC-2026-0194-quick-xml.md",
        f"  {advisory},",
        "]",
    ])

p.write_text("\n".join(out) + "\n")
PY
