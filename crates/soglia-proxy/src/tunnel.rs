// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The byte pipe behind an authorized `CONNECT`.
//!
//! A tunnel ends when either side closes, when it has been silent for the idle limit, when it has
//! carried its byte limit, or when its Execution starts tearing down — whichever comes first.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

use crate::attribution::Binding;

/// The limits of one tunnel.
#[derive(Debug, Clone, Copy)]
pub struct TunnelLimits {
    /// How long the tunnel may carry nothing in either direction.
    pub idle: Duration,
    /// How many bytes it may carry in total, both directions together.
    pub max_bytes: u64,
}

/// Why a tunnel ended.
#[derive(Debug)]
pub enum TunnelEnd {
    /// Both sides finished, or one failed.
    Closed(io::Result<(u64, u64)>),
    /// Nothing moved for the idle limit.
    Idle,
    /// The byte limit was reached.
    ByteLimit,
    /// The Execution started tearing down.
    Revoked,
}

/// Copies bytes between `client` and `server` until the tunnel ends.
pub async fn run<A, B>(
    client: A,
    server: B,
    limits: TunnelLimits,
    mut binding: Binding,
) -> TunnelEnd
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Arc::new(Activity::new());
    let mut client = Tracked::new(client, Arc::clone(&activity));
    let mut server = Tracked::new(server, Arc::clone(&activity));
    let tick = (limits.idle / 4).clamp(Duration::from_millis(10), Duration::from_secs(1));

    let watchdog = async {
        loop {
            tokio::time::sleep(tick).await;
            if activity.bytes() > limits.max_bytes {
                return TunnelEnd::ByteLimit;
            }
            if activity.idle_for() >= limits.idle {
                return TunnelEnd::Idle;
            }
        }
    };

    tokio::select! {
        result = tokio::io::copy_bidirectional(&mut client, &mut server) => TunnelEnd::Closed(result),
        end = watchdog => end,
        () = binding.revoked() => TunnelEnd::Revoked,
    }
}

/// When the tunnel last moved a byte, and how many it moved.
struct Activity {
    origin: Instant,
    last_millis: AtomicU64,
    bytes: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            last_millis: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }

    fn record(&self, bytes: usize) {
        let now = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_millis.store(now, Ordering::Relaxed);
        self.bytes
            .fetch_add(u64::try_from(bytes).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    fn idle_for(&self) -> Duration {
        let last = Duration::from_millis(self.last_millis.load(Ordering::Relaxed));
        self.origin.elapsed().saturating_sub(last)
    }
}

/// A stream that reports every byte it reads to the tunnel's [`Activity`].
struct Tracked<S> {
    inner: S,
    activity: Arc<Activity>,
}

impl<S> Tracked<S> {
    fn new(inner: S, activity: Arc<Activity>) -> Self {
        Self { inner, activity }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(context, buffer);
        let read = buffer.filled().len() - before;
        if read > 0 {
            self.activity.record(read);
        }

        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attribution::AttributionTable;
    use soglia_core::ExecutionId;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn binding() -> (AttributionTable, Binding) {
        let table = AttributionTable::new();
        let address = "10.201.0.1".parse().unwrap();
        table
            .bind(address, ExecutionId::generate().unwrap())
            .unwrap();
        let binding = table.lookup(address).unwrap();
        (table, binding)
    }

    fn limits() -> TunnelLimits {
        TunnelLimits {
            idle: Duration::from_millis(200),
            max_bytes: 1024,
        }
    }

    #[tokio::test]
    async fn bytes_flow_both_ways_until_both_sides_close() {
        let (_table, binding) = binding();
        let (client, mut client_far) = duplex(64);
        let (server, mut server_far) = duplex(64);
        let tunnel = tokio::spawn(run(client, server, limits(), binding));

        client_far.write_all(b"ping").await.unwrap();
        let mut received = [0_u8; 4];
        server_far.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"ping");
        server_far.write_all(b"pong").await.unwrap();
        client_far.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"pong");

        drop(client_far);
        drop(server_far);
        assert!(matches!(tunnel.await.unwrap(), TunnelEnd::Closed(_)));
    }

    #[tokio::test]
    async fn a_silent_tunnel_is_closed() {
        let (_table, binding) = binding();
        let (client, _client_far) = duplex(64);
        let (server, _server_far) = duplex(64);
        assert!(matches!(
            run(client, server, limits(), binding).await,
            TunnelEnd::Idle
        ));
    }

    #[tokio::test]
    async fn a_tunnel_stops_at_its_byte_limit() {
        let (_table, binding) = binding();
        let (client, mut client_far) = duplex(4096);
        let (server, mut server_far) = duplex(4096);
        let tunnel = tokio::spawn(run(client, server, limits(), binding));
        let drain = tokio::spawn(async move {
            let mut sink = Vec::new();
            let _ = server_far.read_to_end(&mut sink).await;
        });

        client_far.write_all(&[0_u8; 2048]).await.unwrap();
        assert!(matches!(tunnel.await.unwrap(), TunnelEnd::ByteLimit));
        drop(client_far);
        drain.await.unwrap();
    }

    #[tokio::test]
    async fn teardown_closes_the_tunnel() {
        let (table, binding) = binding();
        let (client, _client_far) = duplex(64);
        let (server, _server_far) = duplex(64);
        let long = TunnelLimits {
            idle: Duration::from_secs(60),
            max_bytes: 1024,
        };
        let tunnel = tokio::spawn(run(client, server, long, binding));

        table.revoke("10.201.0.1".parse().unwrap());
        let end = tokio::time::timeout(Duration::from_secs(1), tunnel)
            .await
            .expect("the tunnel ends promptly")
            .unwrap();
        assert!(matches!(end, TunnelEnd::Revoked));
    }
}
