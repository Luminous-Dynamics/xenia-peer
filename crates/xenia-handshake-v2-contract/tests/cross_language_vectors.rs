use sha2::{Digest, Sha256};
use xenia_handshake_v2_contract::{
    HostFinalizeV2, HostHelloV2, ML_DSA_65_PK_LEN, ML_DSA_65_SIG_LEN, ML_KEM_768_CT_LEN,
    ML_KEM_768_PK_LEN, ViewerResponseV2, compose_v5_context, encode_host_finalize_v2,
    encode_host_hello_v2, encode_viewer_response_v2, host_signature_transcript_v2,
    viewer_signature_transcript_v2,
};
use xenia_negotiation::{CapabilityOfferEntryV1, CapabilityOfferV1, negotiate_capabilities};
use xenia_negotiation_codec::encode_capability_offer;

fn entry(name: &[u8], versions: &[&[u8]]) -> CapabilityOfferEntryV1 {
    CapabilityOfferEntryV1::new(
        name.to_vec(),
        versions.iter().map(|version| version.to_vec()),
    )
    .unwrap()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn representative_v2_message_and_signature_transcript_vectors_are_frozen() {
    let host_offer_semantic = CapabilityOfferV1::from_entries([
        entry(
            b"xenia.causal-authority",
            &[b"draft-04", b"draft-03"],
        ),
        entry(b"xenia.operator-rekey", &[b"v1"]),
    ])
    .unwrap();
    let viewer_offer_semantic = CapabilityOfferV1::from_entries([
        entry(b"xenia.causal-authority", &[b"draft-04"]),
        entry(b"xenia.operator-rekey", &[b"v1"]),
    ])
    .unwrap();
    let negotiation = negotiate_capabilities(&host_offer_semantic, &viewer_offer_semantic).unwrap();

    assert_eq!(
        hex(&negotiation.binding_hash()),
        "320f9374b3db961ed169aac86d2c3e6c2c36ea885f143b2dd991c8ee75f3c57b"
    );

    let host_offer = encode_capability_offer(&host_offer_semantic);
    let viewer_offer = encode_capability_offer(&viewer_offer_semantic);
    let mut base_v4 = [0u8; 32];
    for (index, byte) in base_v4.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let final_v5 = compose_v5_context(&base_v4, &negotiation.binding_hash());
    assert_eq!(
        hex(&final_v5),
        "9f59efa7ef0959faf57c2490eb438d5537e1485f4bf4f2841cc0df76a647f584"
    );

    let host = HostHelloV2 {
        ed25519_pk: [0x11; 32],
        ml_dsa_pk: [0x22; ML_DSA_65_PK_LEN],
        kem_pk: [0x33; ML_KEM_768_PK_LEN],
        nonce: [0x44; 32],
        base_v4_context_hash: base_v4,
        host_offer,
    };
    let response = ViewerResponseV2 {
        ed25519_pk: [0x66; 32],
        ml_dsa_pk: [0x77; ML_DSA_65_PK_LEN],
        kem_ct: [0x88; ML_KEM_768_CT_LEN],
        nonce: [0x99; 32],
        viewer_offer,
        final_v5_context_hash: final_v5,
        signature: [0xbb; 64],
        ml_dsa_signature: [0xcc; ML_DSA_65_SIG_LEN],
    };
    let finalize = HostFinalizeV2 {
        final_v5_context_hash: final_v5,
        signature: [0xdd; 64],
        ml_dsa_signature: [0xee; ML_DSA_65_SIG_LEN],
    };

    let host_bytes = encode_host_hello_v2(&host).unwrap();
    let response_bytes = encode_viewer_response_v2(&response).unwrap();
    let finalize_bytes = encode_host_finalize_v2(&finalize).unwrap();
    assert_eq!(host_bytes.len(), 3348);
    assert_eq!(response_bytes.len(), 6615);
    assert_eq!(finalize_bytes.len(), 3409);
    assert_eq!(
        hex(&Sha256::digest(&host_bytes)),
        "c63e7bd4a331f03bdf295ee0845a08eb936a9625d7a8bc413a14c13166c25b0a"
    );
    assert_eq!(
        hex(&Sha256::digest(&response_bytes)),
        "7e3ab9366d8336e284a5ba595ffa505610f43869a5c66fbbf942bc69e7049b0b"
    );
    assert_eq!(
        hex(&Sha256::digest(&finalize_bytes)),
        "ec55f4899e10022511681709db3d496c96b7e20faa35ba573e12f3e994782b44"
    );

    let viewer_transcript = viewer_signature_transcript_v2(&host_bytes, &response).unwrap();
    let host_transcript = host_signature_transcript_v2(&host_bytes, &response).unwrap();
    assert_eq!(viewer_transcript.len(), 6794);
    assert_eq!(host_transcript.len(), 10231);
    assert_eq!(
        hex(&Sha256::digest(&viewer_transcript)),
        "fccfc6314ddcf38c5464fca454343c95716e191c8afeac22f96be49ac49c8456"
    );
    assert_eq!(
        hex(&Sha256::digest(&host_transcript)),
        "add97be37fb648148d5cb7c80f41d283187ad1e744cbd317b98fa6dc09a9f364"
    );
}
