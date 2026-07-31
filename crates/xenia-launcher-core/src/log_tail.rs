// Copyright (c) 2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Subscribe to a daemon's log file (`--log-file`, see
//! [`crate::config::DaemonConfig::log_file`]) as a stream of lines, for a
//! launcher UI's log pane.
//!
//! Deliberately a *file* subscription, not a captured-stdout pipe: a
//! detached/service-supervised daemon may have no console at all, and a
//! log file survives the daemon restarting independently of whether the
//! launcher itself was watching at the time. This also isn't a health
//! signal -- see [`crate::health`] for that; this module exists purely to
//! surface log content to a human, never to answer "is the daemon OK."

use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio_stream::Stream;

/// Tail `path` starting from its current end (existing content isn't
/// replayed -- a launcher UI that starts before the daemon, or reattaches
/// mid-session, only wants *new* lines from here on). Returns a `Stream`
/// of lines; each item is a completed line already stripped of its
/// terminator. Polls for new content rather than using a filesystem
/// watcher -- simpler, and a log file's write rate is low enough that a
/// short poll interval is imperceptible without pulling in a
/// platform-specific inotify/ReadDirectoryChangesW dependency for it.
pub async fn tail(
    path: PathBuf,
    poll_interval: std::time::Duration,
) -> std::io::Result<impl Stream<Item = std::io::Result<String>>> {
    let mut file = tokio::fs::File::open(&path).await?;
    let end = file.seek(std::io::SeekFrom::End(0)).await?;
    tracing::debug!(path = %path.display(), start_offset = end, "started tailing log file");

    let reader = BufReader::new(file);
    let lines = reader.lines();
    let interval = tokio::time::interval(poll_interval);
    Ok(PollingLines { lines, interval })
}

// A small adapter so `tail`'s stream only yields when a new complete line
// is actually available, instead of the caller having to drive polling
// itself. tokio's `Lines` already blocks (async-ly) inside `next_line`
// until more bytes arrive or EOF -- the polling here is specifically for
// the EOF case, where a plain `Lines` stream would end instead of waiting
// for the daemon to write more.
struct PollingLines {
    lines: tokio::io::Lines<BufReader<tokio::fs::File>>,
    interval: tokio::time::Interval,
}

impl Stream for PollingLines {
    type Item = std::io::Result<String>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        loop {
            match std::pin::Pin::new(&mut self.lines).poll_next_line(cx) {
                std::task::Poll::Ready(Ok(Some(line))) => {
                    return std::task::Poll::Ready(Some(Ok(line)));
                }
                std::task::Poll::Ready(Ok(None)) => {
                    // EOF for now -- wait for the next poll tick rather
                    // than ending the stream; more lines may still arrive.
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Some(Err(e))),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
            match self.interval.poll_tick(cx) {
                std::task::Poll::Ready(_) => continue,
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn only_yields_lines_written_after_the_subscription_started() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "old line, before subscribing").unwrap();
        }

        let mut stream = Box::pin(
            tail(path.clone(), std::time::Duration::from_millis(20))
                .await
                .unwrap(),
        );

        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            writeln!(f, "new line 1").unwrap();
            writeln!(f, "new line 2").unwrap();
        }

        let first = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let second = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(first, "new line 1");
        assert_eq!(second, "new line 2");
    }

    #[tokio::test]
    async fn waits_across_multiple_write_bursts_instead_of_ending_at_eof() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.log");
        std::fs::File::create(&path).unwrap();

        let mut stream = Box::pin(
            tail(path.clone(), std::time::Duration::from_millis(20))
                .await
                .unwrap(),
        );

        tokio::spawn({
            let path = path.clone();
            async move {
                for i in 0..3 {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    let mut f = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap();
                    writeln!(f, "burst-{i}").unwrap();
                }
            }
        });

        for i in 0..3 {
            let line = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            assert_eq!(line, format!("burst-{i}"));
        }
    }
}
