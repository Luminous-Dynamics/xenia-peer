use futures_util::SinkExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use xenia_peer_core::transport::{TcpTransport, Transport, TransportError, MAX_ENVELOPE_BYTES};
use xenia_peer_core::{
    advertisement::{AdvertisedAudioCodec, AudioAdvertisement},
    frame::PixelFormat,
    RawAudio, RawCapabilities, RawTelemetry, Session, SessionRole, SyntheticAudioKind,
    SyntheticAudioSource, TelemetrySample, TelemetryValue,
};
use xenia_transport_ws::WsTransport;

fn payload(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| seed.wrapping_add((i & 0xFF) as u8))
        .collect()
}

async fn tcp_pair() -> (TcpTransport, TcpTransport) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).ok();
        TcpTransport::new(stream)
    });

    let client = TcpTransport::connect(&addr.to_string()).await.unwrap();
    let server = server.await.unwrap();
    (server, client)
}

async fn ws_pair() -> (WsTransport, WsTransport) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).ok();
        let ws = accept_async(stream).await.unwrap();
        WsTransport::Server(ws)
    });

    let client = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
    let server = server.await.unwrap();
    (server, client)
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
    let mut host = Session::with_fixture(SessionRole::Host, [0xAA; 8], 0x01);
    let mut viewer = Session::with_fixture(SessionRole::Viewer, [0xAA; 8], 0x01);
    host.install_key([0x33; 32]);
    viewer.install_key([0x33; 32]);

    let telemetry = RawTelemetry {
        frame_id: host.next_frame_id(),
        timestamp_ms: 1_700_000_001_000,
        backend: "test".to_string(),
        samples: vec![TelemetrySample {
            name: "cpu.total.percent".to_string(),
            value: TelemetryValue::F64(42.0),
            unit: Some("%".to_string()),
            timestamp_ms: 1_700_000_001_000,
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
    let mut host = Session::with_fixture(SessionRole::Host, [0xAC; 8], 0x01);
    let mut viewer = Session::with_fixture(SessionRole::Viewer, [0xAC; 8], 0x01);
    host.install_key([0x55; 32]);
    viewer.install_key([0x55; 32]);

    let mut source = SyntheticAudioSource::new(1, SyntheticAudioKind::Sine);
    let audio = source.next_frame(1_700_000_003_000);
    let frame_id = host.next_frame_id();
    let frame = audio.clone().into_frame(frame_id).unwrap();
    let envelope = host.seal_frame(&frame).unwrap();
    server.send_envelope(&envelope).await.unwrap();
    let received = client.recv_envelope().await.unwrap();
    let opened = viewer.open_frame(&received).unwrap();
    assert_eq!(opened.pixel_format, PixelFormat::Audio);
    assert_eq!(RawAudio::from_frame(&opened).unwrap(), audio);
}

async fn assert_capabilities_roundtrip<S, C>(mut server: S, mut client: C)
where
    S: Transport,
    C: Transport,
{
    let mut host = Session::with_fixture(SessionRole::Host, [0xAD; 8], 0x01);
    let mut viewer = Session::with_fixture(SessionRole::Viewer, [0xAD; 8], 0x01);
    host.install_key([0x77; 32]);
    viewer.install_key([0x77; 32]);

    let capabilities = RawCapabilities {
        frame_id: host.next_frame_id(),
        timestamp_ms: 1_700_000_005_000,
        audio: Some(AudioAdvertisement {
            codecs: vec![AdvertisedAudioCodec::RawPcm],
            selected_codec: AdvertisedAudioCodec::RawPcm,
            sample_rate_hz: 48_000,
            max_channels: 2,
            frame_duration_ms: vec![10, 20],
        }),
        video_format: PixelFormat::Passthrough,
        telemetry_enabled: true,
        input_control_enabled: false,
        clipboard_enabled: false,
        lane_envelope_version: xenia_peer_core::frame::LANE_ENVELOPE_SCHEMA_VERSION,
        lane_envelope_magic: xenia_peer_core::frame::LANE_ENVELOPE_MAGIC,
    };
    let frame = capabilities.clone().into_frame().unwrap();
    let envelope = host.seal_control_frame(&frame).unwrap();
    server.send_envelope(&envelope).await.unwrap();
    let received = client.recv_envelope().await.unwrap();
    let opened = viewer.open_frame(&received).unwrap();
    assert_eq!(opened.pixel_format, PixelFormat::Capabilities);
    assert_eq!(RawCapabilities::from_frame(&opened).unwrap(), capabilities);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_preserves_envelope_boundaries_and_order() {
    let (server, client) = tcp_pair().await;
    assert_bidirectional_burst(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_preserves_envelope_boundaries_and_order() {
    let (server, client) = ws_pair().await;
    assert_bidirectional_burst(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_rejects_oversize_send_without_poisoning_connection() {
    let (server, client) = tcp_pair().await;
    assert_oversize_send_rejected(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_rejects_oversize_send_without_poisoning_connection() {
    let (server, client) = ws_pair().await;
    assert_oversize_send_rejected(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_carries_sealed_telemetry_metadata() {
    let (server, client) = tcp_pair().await;
    assert_telemetry_metadata_roundtrip(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_carries_sealed_telemetry_metadata() {
    let (server, client) = ws_pair().await;
    assert_telemetry_metadata_roundtrip(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_carries_sealed_audio_metadata() {
    let (server, client) = tcp_pair().await;
    assert_audio_metadata_roundtrip(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_carries_sealed_audio_metadata() {
    let (server, client) = ws_pair().await;
    assert_audio_metadata_roundtrip(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_carries_sealed_capabilities_metadata() {
    let (server, client) = tcp_pair().await;
    assert_capabilities_roundtrip(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_carries_sealed_capabilities_metadata() {
    let (server, client) = ws_pair().await;
    assert_capabilities_roundtrip(server, client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_detects_truncated_envelope_as_unexpected_eof() {
    use tokio::io::AsyncWriteExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream.write_all(&16u32.to_be_bytes()).await.unwrap();
        stream.write_all(b"only-partial").await.unwrap();
        // Drop the stream before the advertised envelope length is satisfied.
    });

    let mut client = TcpTransport::connect(&addr.to_string()).await.unwrap();
    let err = client.recv_envelope().await.unwrap_err();
    assert!(matches!(err, TransportError::UnexpectedEof));
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn websocket_rejects_text_protocol_fault() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        stream.set_nodelay(true).ok();
        let mut ws = accept_async(stream).await.unwrap();
        ws.send(Message::Text("not a xenia sealed envelope".into()))
            .await
            .unwrap();
    });

    let mut client = WsTransport::connect(&format!("ws://{addr}")).await.unwrap();
    let err = client.recv_envelope().await.unwrap_err();
    assert!(matches!(err, TransportError::UnexpectedEof));
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_rejects_oversize_receive_before_allocation() {
    use tokio::io::AsyncWriteExt;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (ready_tx, ready_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        ready_tx.send(()).unwrap();
        stream
            .write_all(&(MAX_ENVELOPE_BYTES + 1).to_be_bytes())
            .await
            .unwrap();
    });

    let mut client = TcpTransport::connect(&addr.to_string()).await.unwrap();
    ready_rx.await.unwrap();
    let err = client.recv_envelope().await.unwrap_err();
    assert!(matches!(err, TransportError::EnvelopeTooLarge(_)));
    server.await.unwrap();
}
