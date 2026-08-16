#![no_main]

use libfuzzer_sys::fuzz_target;
use xenia_zk_codec::{
    decode_binary_envelope_v1, decode_json_envelope_bounded, encode_binary_envelope_v1,
    encode_json_envelope,
};
use xenia_zk_protocol::policy::EnvelopePolicy;

fuzz_target!(|data: &[u8]| {
    let policy = EnvelopePolicy {
        max_encoded_envelope_bytes: 64 * 1024,
        max_proof_bytes: 32 * 1024,
        max_signature_bytes: 16 * 1024,
        max_authentication_entries: 8,
        ..EnvelopePolicy::default()
    };

    if let Ok(decoded) = decode_binary_envelope_v1(data, &policy) {
        // Binary V1 is canonical: any accepted frame must re-encode byte-for-byte.
        let reencoded = encode_binary_envelope_v1(&decoded, &policy).expect("accepted binary envelope must re-encode");
        assert_eq!(reencoded, data);
        let round_trip = decode_binary_envelope_v1(&reencoded, &policy).expect("re-encoded binary envelope must decode");
        assert_eq!(round_trip, decoded);
    }

    if let Ok(decoded) = decode_json_envelope_bounded(data, &policy) {
        // JSON syntax itself is intentionally noncanonical, but the parsed
        // protocol object must survive the crate-owned serializer round trip.
        let reencoded = encode_json_envelope(&decoded).expect("accepted JSON envelope must re-encode");
        let round_trip = decode_json_envelope_bounded(&reencoded, &policy).expect("re-encoded JSON envelope must decode");
        assert_eq!(round_trip, decoded);
    }
});
