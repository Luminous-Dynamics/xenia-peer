# Local source-delta audit: clipboard-win 5.4.3

**Review kind:** local dependency source-delta review for a Cargo-vet exemption  
**Reviewed package:** \`clipboard-win 5.4.3\`  
**Previous locked package:** \`clipboard-win 5.4.1\`  
**Review scope:** published source delta, manifest/dependency surface, and directly changed safety-relevant code  
**Reviewer attribution:** local repository-maintainer review; this is not an external auditor's attestation

## Exact source identity

The crate manifest for 5.4.3 declares:

- Package: \`clipboard-win\`
- Version: \`5.4.3\`
- License: \`BSL-1.0\`
- Upstream repository: \`https://github.com/DoumanAsh/clipboard-win\`
- Published source commit: \`ed27008ae5d1f10cfbb266de039f0fb35fd05a56\`

The 5.4.1 source identity used for comparison is upstream commit:

\`3b27cf2bfd1adcfa6e0264eb51c1025ddaf0f342\`

The 5.4.3 registry checksum locked by Xenia is:

\`052af7878466feccda12ba7a6a67d019d712f296809559b47c12c8cc196d3a9a\`

The lockfile checksum is corroborated by the crates.io index entry and independent downstream lockfiles. CI still performs the canonical registry/checksum and build verification.

## Manifest and dependency-surface comparison

The 5.4.3 manifest has no new normal or build dependencies compared with the 5.4.1 manifest. The package uses the existing Windows-target dependency \`error-code\`; \`windows-win\` remains optional and tied to the existing \`monitor\` feature. The package remains Windows-only at the crate root.

The source modules \`src/sys.rs\`, \`src/utils.rs\`, \`src/html.rs\`, \`src/monitor.rs\`, and \`src/types.rs\` are byte-identical between the compared source commits. The Win32 FFI declarations and the existing global-memory/clipboard resource management helpers were not changed in this version delta.

## Safety-relevant source changes

### 1. HTML clipboard fragment bounds validation

In 5.4.1, \`get_html\` parsed \`StartFragment\` and \`EndFragment\`, checked that subtraction did not underflow, and checked that the requested fragment length was no larger than the full clipboard buffer length. It then used raw pointer arithmetic and \`copy_nonoverlapping\` from \`data.as_ptr().add(start_idx)\`.

That check did not independently establish that the start offset was within the buffer. An externally supplied HTML clipboard payload could contain inconsistent offsets. A length smaller than the whole buffer does not prove that the range beginning at an arbitrary offset lies within the buffer.

In 5.4.3, the raw pointer copy is replaced by a bounds-checked slice lookup:

\`\`\`rust
match data.get(start_idx..start_idx + size) {
    Some(html) => out.extend_from_slice(html.as_bytes()),
    None => return Err(invalid_data()),
}
\`\`\`

The existing \`checked_sub\` validates the ordering of the parsed endpoints; \`str::get\` validates the complete range against the UTF-8 buffer before copying. Invalid external offsets now return \`invalid_data\` rather than reaching unchecked pointer arithmetic. This is a positive safety change in the exact code path that parses data that may originate outside the crate.

### 2. Clipboard-open retry delay

The retry loop in \`Clipboard::new_attempts_for\` changes from \`Sleep(0)\` to \`Sleep(5)\` milliseconds. The upstream change documents the five-millisecond delay as matching Chromium's Windows clipboard retry behavior. This affects contention/backoff timing; it does not add a new privilege, network, filesystem or cryptographic capability.

### 3. Documentation and lint configuration

Other differences in the reviewed files are a documentation sample wording change, a documentation URL formatting change, and a Clippy attribute adjustment. They do not expand runtime authority or dependency scope.

## Existing unsafe surface and limitations

This is a delta review, not a fresh audit of all historical unsafe code. Existing Win32 FFI, global-memory locking, clipboard ownership, bitmap/file-list parsing, and the optional monitor's unsafe \`Send\` implementation remain present and are not materially changed by this release. They still require platform-specific testing and remain part of the package's inherited risk surface.

The review did not execute the crate's Windows-specific tests locally. Xenia's Windows CI build verifies that the package resolves and compiles in the workspace, but that is not equivalent to runtime Windows clipboard testing. A future dedicated Windows test matrix should exercise malformed HTML offsets (including start beyond end, end beyond the buffer, integer-boundary values, and empty fragments), normal text/file-list/bitmap transfers, clipboard contention, and close/lock behavior.

## Disposition

For Xenia's current use as a Windows clipboard backend, the reviewed 5.4.3 delta is acceptable for a **local, version-specific** \`safe-to-deploy\` exemption:

- no additional dependency surface;
- an out-of-range HTML fragment copy is replaced by a safe range-checked slice;
- the only other runtime change is a small retry backoff adjustment;
- no new authority, network or filesystem capability is introduced by the delta.

This exemption applies only to \`clipboard-win 5.4.3\`. It does not grant blanket approval to future versions. A subsequent version requires a fresh delta review or an accepted upstream cargo-vet audit.

## Reproducibility references

- 5.4.1 upstream source commit: \`https://github.com/DoumanAsh/clipboard-win/tree/3b27cf2bfd1adcfa6e0264eb51c1025ddaf0f342\`
- 5.4.3 upstream source commit: \`https://github.com/DoumanAsh/clipboard-win/tree/ed27008ae5d1f10cfbb266de039f0fb35fd05a56\`
- 5.4.3 manifest: \`https://github.com/DoumanAsh/clipboard-win/blob/ed27008ae5d1f10cfbb266de039f0fb35fd05a56/Cargo.toml\`
- Upstream package registry: \`https://crates.io/crates/clipboard-win/5.4.3\`
