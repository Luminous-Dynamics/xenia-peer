#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parents[1]
src=(root/'crates/xenia-zk-auth/src/lib.rs').read_text()
manifest=(root/'Cargo.toml').read_text()
lock=(root/'Cargo.lock').read_text()
checks={
 'workspace_member': '"crates/xenia-zk-auth"' in manifest,
 'locked_package': 'name = "xenia-zk-auth"' in lock,
 'ed25519_suite': 'AuthenticationSuiteId::ED25519' in src,
 'mldsa65_suite': 'AuthenticationSuiteId::ML_DSA_65_FIPS204' in src,
 'ed_sig_ceiling': 'signature.len() != ED25519_SIGNATURE_BYTES' in src,
 'pq_sig_ceiling': 'signature.len() != ML_DSA_65_SIGNATURE_BYTES' in src,
 'canonical_key_id': src.count('signer_key_id(') >= 4,
 'trait_impls': src.count('impl ProofAuthenticationVerifier for') == 2,
}
for k,v in checks.items(): print(('PASS' if v else 'FAIL'), k)
raise SystemExit(0 if all(checks.values()) else 1)
