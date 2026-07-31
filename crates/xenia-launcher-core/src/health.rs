// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A minimal, dependency-light client for `xenia-peer`'s (and
//! `xenia-operator-agent`'s) unauthenticated `GET /health` liveness probe.
//!
//! Deliberately not a general HTTP client crate -- see the dependency
//! comment in `Cargo.toml`. This never infers health by scraping log
//! output (a structured JSON endpoint the daemon itself controls is a far
//! more honest signal than pattern-matching its logs, and doesn't break
//! the moment a log message's wording changes).

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, serde::Deserialize, PartialEq, Clone)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_secs: u64,
    pub ledger_entry_count: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum HealthError {
    #[error("connecting to the daemon's health endpoint: {0}")]
    Connect(#[source] std::io::Error),
    #[error("health probe timed out")]
    Timeout,
    #[error("reading the health response: {0}")]
    Io(#[source] std::io::Error),
    #[error("the health endpoint returned a non-200 status: {0}")]
    HttpStatus(String),
    #[error("malformed health response body: {0}")]
    Malformed(String),
}

/// `GET http://{base_url}/health`, with an overall `deadline`. `base_url`
/// is `host:port` (no scheme) -- see [`crate::config::DaemonConfig::health_base_url`].
pub async fn probe(base_url: &str, deadline: Duration) -> Result<HealthResponse, HealthError> {
    timeout(deadline, probe_inner(base_url))
        .await
        .map_err(|_| HealthError::Timeout)?
}

async fn probe_inner(base_url: &str) -> Result<HealthResponse, HealthError> {
    let mut stream = TcpStream::connect(base_url)
        .await
        .map_err(HealthError::Connect)?;

    let request = format!(
        "GET /health HTTP/1.1\r\nHost: {base_url}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(HealthError::Io)?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .map_err(HealthError::Io)?;

    let response = String::from_utf8_lossy(&raw);
    let mut parts = response.splitn(2, "\r\n\r\n");
    let head = parts
        .next()
        .ok_or_else(|| HealthError::Malformed("empty response".into()))?;
    let body = parts.next().unwrap_or("");

    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| HealthError::Malformed("missing status line".into()))?;
    // "HTTP/1.1 200 OK" -- the second whitespace-delimited field is the
    // status code. Anything other than exactly "200" is treated as a
    // failure; this endpoint has no redirects or alternate success codes.
    let status_code = status_line.split_whitespace().nth(1).unwrap_or("");
    if status_code != "200" {
        return Err(HealthError::HttpStatus(status_line.to_string()));
    }

    serde_json::from_str(body.trim()).map_err(|e| HealthError::Malformed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A tiny fake HTTP server, just enough of the shape the real
    /// `health_handler` produces, to test the client without depending on
    /// a real `xenia-peer` binary being built.
    async fn fake_health_server(body: &'static str, status_line: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
        });
        addr.to_string()
    }

    #[tokio::test]
    async fn parses_a_real_shaped_health_response() {
        let addr = fake_health_server(
            r#"{"status":"ok","uptime_secs":42,"ledger_entry_count":3}"#,
            "HTTP/1.1 200 OK",
        )
        .await;
        let health = probe(&addr, Duration::from_secs(2)).await.unwrap();
        assert_eq!(
            health,
            HealthResponse {
                status: "ok".to_string(),
                uptime_secs: 42,
                ledger_entry_count: 3,
            }
        );
    }

    #[tokio::test]
    async fn a_non_200_status_is_an_error_not_a_silently_accepted_health() {
        let addr = fake_health_server("not found", "HTTP/1.1 404 Not Found").await;
        let err = probe(&addr, Duration::from_secs(2)).await.unwrap_err();
        assert!(matches!(err, HealthError::HttpStatus(_)));
    }

    #[tokio::test]
    async fn connecting_to_nothing_is_a_connect_error() {
        // Port 1 is reserved (tcpmux) and nothing should ever be
        // listening on it during a test run.
        let err = probe("127.0.0.1:1", Duration::from_millis(500))
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            HealthError::Connect(_) | HealthError::Timeout
        ));
    }

    #[tokio::test]
    async fn an_unresponsive_server_times_out_rather_than_hanging() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            // Accept the connection, then never respond.
            std::future::pending::<()>().await;
        });
        let err = probe(&addr, Duration::from_millis(200)).await.unwrap_err();
        assert!(matches!(err, HealthError::Timeout));
    }
}
