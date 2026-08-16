#!/usr/bin/env python3
"""Static security contract for xenia-zk-codec."""
from __future__ import annotations
import pathlib, sys, tomllib
root = pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '.').resolve()
crate = root/'crates'/'xenia-zk-codec'
fail=[]
def req(c,m):
    if not c: fail.append(m)
manifest=crate/'Cargo.toml'; source=crate/'src'/'lib.rs'
req(manifest.is_file(),'xenia-zk-codec manifest missing')
req(source.is_file(),'xenia-zk-codec source missing')
if manifest.is_file():
    with manifest.open('rb') as h: deps=set(tomllib.load(h).get('dependencies',{}))
    req('xenia-zk-protocol' in deps,'codec must depend on protocol substrate')
    for forbidden in ('winterfell','miden-vm','ed25519-dalek','ml-dsa','holochain'):
        req(forbidden not in deps,f'codec absorbed forbidden implementation dependency: {forbidden}')
if source.is_file():
    s=source.read_text()
    for frag in (
        'bound_envelope_frame_before_deserialization(encoded, policy)?',
        'pub fn decode_json_envelope_bounded',
        'pub fn decode_binary_envelope_v1',
        'pub fn encode_binary_envelope_v1',
        'BINARY_ENVELOPE_MAGIC_V1',
        'LengthExceedsFrame',
        'TrailingBytes',
        'if declared > self.remaining()',
        'check_len(field, declared, limit)?',
        'Vec::with_capacity(authentication_count)',
        'if min_auth_bytes > cursor.remaining()',
        'binary_decoder_rejects_every_truncation_and_trailing_byte',
        'binary_declared_lengths_are_bounded_before_allocation',
        'json_unknown_fields_fail_closed',
        'json_duplicate_fields_fail_closed',
        'policy.max_authentication_entries.min(u16::MAX as usize)',
        'policy.max_signature_bytes.min(u32::MAX as usize)',
    ): req(frag in s,f'codec invariant missing: {frag}')
# The decoder constructs the protocol envelope explicitly. On no-Rust runners,
# ensure each security-relevant field appears exactly once in that initializer.
marker='Ok(ProofEnvelopeV3 {'
start=s.find(marker)
req(start >= 0, 'ProofEnvelopeV3 decoder initializer missing')
end=s.find('\n    })', start)
req(end > start, 'ProofEnvelopeV3 decoder initializer is malformed')
initializer=s[start:end]
for field in (
    'protocol_version', 'statement', 'proof_system', 'verifier_id',
    'parameter_set_id', 'timestamp_unix_seconds', 'nonce',
    'public_inputs_hash', 'proof', 'extensions_digest', 'authentication',
):
    req(initializer.count(f'\n        {field},') == 1,
        f'ProofEnvelopeV3 decoder field must appear exactly once: {field}')
fuzz_manifest=(root/'fuzz'/'Cargo.toml').read_text()
fuzz_target=(root/'fuzz'/'fuzz_targets'/'fuzz_zk_envelope_codec.rs')
req('xenia-zk-codec' in fuzz_manifest, 'codec fuzz crate dependency missing')
req('fuzz_zk_envelope_codec' in fuzz_manifest, 'codec fuzz target is not registered')
req(fuzz_target.is_file(), 'codec fuzz target source missing')
if fuzz_target.is_file():
    fs=fuzz_target.read_text()
    req('assert_eq!(reencoded, data)' in fs, 'binary fuzz target must enforce canonical re-encoding')
    req('decode_json_envelope_bounded' in fs, 'JSON codec is not fuzzed')
workspace=(root/'Cargo.toml').read_text()
req('"crates/xenia-zk-codec"' in workspace,'codec crate is not a workspace member')
lock=(root/'Cargo.lock').read_text()
req('name = "xenia-zk-codec"' in lock,'codec crate is missing from Cargo.lock')
if fail:
    print('ZK codec boundary check FAILED',file=sys.stderr)
    for f in fail: print(' - '+f,file=sys.stderr)
    raise SystemExit(1)
print('ZK codec boundary check passed')
