use iroh::{Endpoint, endpoint::presets};
use xenia_peer_core::transport::{MAX_ENVELOPE_BYTES, Transport, TransportError};
use xenia_peer_core::{
    RawAudio, RawTelemetry, Session, SessionRole, SyntheticAudioKind, SyntheticAudioSource,
    TelemetrySample, TelemetryValue, frame::PixelFormat,
};
use xenia_transport_quic::{QuicTransport, XENIA_QUIC_ALPN};

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i & 0xFF) as u8))
        .collect()
}

async fn quic_endpoint() -> Endpoint {
    Endpoint::builder(presets::Minimal)
        .alpns(vec![XENIA_QUIC_ALPN.to_vec()])
        .bind()
        .await
        .unwrap()
}

async fn quic_pair() -> (QuicTransport, QuicTransport, Endpoint, Endpoint) {
    let server_endpoint = quic_endpoint().await;
    let client_endpoint = quic_endpoint().await;
    let server_addr = server_endpoint.addr();

    let server = {
        let endpoint = server_endpoint.clone();
        tokio::spawn(async move { QuicTransport::accept_one(&endpoint).await.unwrap() })
    };

    let client = QuicTransport::connect(&client_endpoint, server_addr)
        .await
        .unwrap();
    let server = server.await.unwrap();

    (server, client, server_endpoint, client_endpoint)
}

async fn assert_bidirectional_burst<S, C>(mut server: S, mut client: C)
where
    S: Transport,
    C: Transport,
{
    let client_to_server = [
        payload(0x00, 0),
        payload(0x10, 1),
        payload(0x20, 31),
        payload(0x30, 1024),
        payload(0x40, 4097),
    ];
    let server_to_client = [
        payload(0x80, 0),
        payload(0x90, 2),
        payload(0xA0, 33),
        payload(0xB0, 2048),
        payload(0xC0, 8193),
    ];

    for envelope in &client_to_server {
        client.send_envelope(envelope).await.unwrap();
    }
    for expected in &client_to_server {
        let received = server.recv_envelope().await.unwrap();
        assert_eq!(&received, expected);
    }

    for envelope in &server_to_client {
        server.send_envelope(envelope).await.unwrap();
    }
    for expected in &server_to_client {
        let received = client.recv_envelope().await.unwrap();
        assert_eq!(&received, expected);
    }
}

async fn assert_oversize_send_rejected<S, C>(mut server: S, mut client: C)
where
    S: Transport,
    C: Transport,
{
    let too_large = vec![0u8; MAX_ENVELOPE_BYTES as usize + 1];

    let client_err = client.send_envelope(&too_large).await.unwrap_err();
    assert!(matches!(client_err, TransportError::EnvelopeTooLarge(_)));

    let server_err = server.send_envelope(&too_large).await.unwrap_err();
    assert!(matches!(server_err, TransportError::EnvelopeTooLarge(_)));

    let sentinel = b"still usable after local oversize rejection".to_vec();
    client.send_envelope(&sentinel).await.unwrap();
    assert_eq!(server.recv_envelope().await.unwrap(), sentinel);
}

async fn assert_telemetry_metadata_roundtrip<S, C>(mut server: S, mut client: C)
where
    S: Transport,
    C: Transport,
{
    let mut host = Session::with_fixture(SessionRole::Host, [0xBB; 8], 0x01);
    let mut viewer = Session::with_fixture(SessionRole::Viewer, [0xBB; 8], 0x01);
    host.install_key([0x44; 32]);
    viewer.install_key([0x44; 32]);

    let telemetry = RawTelemetry {
        frame_id: host.next_frame_id(),
        timestamp_ms: 1_700_000_002_000,
        backend: "test".to_string(),
        samples: vec![TelemetrySample {
            name: "memory.used.bytes".to_string(),
            value: TelemetryValue::U64(4096),
            unit: Some("bytes".to_string()),
            timestamp_ms: 1_700_000_002_000,
        }],
    };
    let envelope = host
        .seal_frame(&telemetry.clone().into_frame().unwrap())
        .unwrap();
    server.send_envelope(&envelope).await.unwrap();
    let received = client.recv_envelope().await.unwrap();
    let opened = viewer.open_frame(&received).unwrap();
    assert_eq!(opened.pixel_format, PixelFormat::Telemetry);
    assert_eq!(RawTelemetry::from_frame(&opened).unwrap(), telemetry);
}

async fn assert_audio_metadata_roundtrip<S, C>(mut server: S, mut client: C)
where
    S: Transport,
    C: Transport,
{
    let mut host = Session::with_fixture(SessionRole::Host, [0xBC; 8], 0x01);
    let mut viewer = Session::with_fixture(SessionRole::Viewer, [0xBC; 8], 0x01);
    host.install_key([0x66; 32]);
    viewer.install_key([0x66; 32]);

    let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Noise);
    let audio = source.next_frame(1_700_000_004_000);
    let frame_id = host.next_frame_id();
    let frame = audio.clone().into_frame(frame_id).unwrap();
    let envelope = host.seal_frame(&frame).unwrap();
    server.send_envelope(&envelope).await.unwrap();
    let received = client.recv_envelope().await.unwrap();
    let opened = viewer.open_frame(&received).unwrap();
    assert_eq!(opened.pixel_format, PixelFormat::Audio);
    assert_eq!(RawAudio::from_frame(&opened).unwrap(), audio);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_preserves_envelope_boundaries_and_order() {
    let (server, client, server_endpoint, client_endpoint) = quic_pair().await;
    assert_bidirectional_burst(server, client).await;
    client_endpoint.close().await;
    server_endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_rejects_oversize_send_without_poisoning_connection() {
    let (server, client, server_endpoint, client_endpoint) = quic_pair().await;
    assert_oversize_send_rejected(server, client).await;
    client_endpoint.close().await;
    server_endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_carries_sealed_telemetry_metadata() {
    let (server, client, server_endpoint, client_endpoint) = quic_pair().await;
    assert_telemetry_metadata_roundtrip(server, client).await;
    client_endpoint.close().await;
    server_endpoint.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quic_carries_sealed_audio_metadata() {
    let (server, client, server_endpoint, client_endpoint) = quic_pair().await;
    assert_audio_metadata_roundtrip(server, client).await;
    client_endpoint.close().await;
    server_endpoint.close().await;
}
