# RUSTSEC-2026-0194 / RUSTSEC-2026-0195 — quick-xml denial-of-service advisories

Status: **dependency lock remediated; fresh CI confirmation pending** (2026-10-12).

## Findings

- RUSTSEC-2026-0194: duplicate-attribute checking can become quadratic.
- RUSTSEC-2026-0195: NsReader namespace-declaration handling can allocate without a bounded per-element limit.
- Both are fixed in quick-xml >= 0.41.0. See the upstream advisory records: https://rustsec.org/advisories/RUSTSEC-2026-0194.html and https://rustsec.org/advisories/RUSTSEC-2026-0195.html.

## Dependency path and remediation

The previous locked graph included quick-xml 0.39.4 through wayland-scanner 0.31.10. The current remediation updates wayland-scanner to 0.31.11, whose published manifest requires quick-xml ^0.41; the existing plist 1.10.0 path already resolves to quick-xml 0.41.0.

The lockfile therefore removes the quick-xml 0.39.4 package entry and leaves only quick-xml 0.41.0. The matching RUSTSEC-2026-0194 and RUSTSEC-2026-0195 ignores have been removed from deny.toml; the unrelated, previously tracked bincode exception remains unchanged.

## Validation boundary

This is a lockfile and dependency-constraint review, not a claim that CI has passed. Fresh exact-head cargo deny check advisories bans licenses sources, cargo vet --locked, Rust compilation, and runtime qualification remain required. If the resolver or CI reports another dependency path back to a vulnerable quick-xml release, fail closed and restore an explicit tracked blocker rather than re-add a silent blanket suppression.
