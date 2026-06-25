use xenia_peer_core::Session;

#[test]
fn telemetry_tracks_last_frame_latency() {
    let mut host = Session::host();
    host.install_key([0x42; 32]);
    let _ = host.seal_captured_rgba(2, 2, vec![0; 16]);
    assert!(host.last_frame_latency_ms() < 100);
}
