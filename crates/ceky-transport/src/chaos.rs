//! Chaos engineering middleware for testing network resilience.
//! 
//! Only compiled when the `chaos` feature is enabled.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use rand::Rng;
use tracing::debug;

/// Wraps an AsyncRead + AsyncWrite stream and injects chaos (latency, corruption, drops).
pub struct ChaosStream<S> {
    inner: S,
    drop_probability: f64,
    corrupt_probability: f64,
    latency_probability: f64,
}

impl<S> ChaosStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            drop_probability: 0.005,      // 0.5% chance to drop connection entirely
            corrupt_probability: 0.001,   // 0.1% chance to corrupt a read
            latency_probability: 0.05,    // 5% chance to inject artificial Pending (latency)
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ChaosStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut rng = rand::thread_rng();

        // 1. Simulate connection drop
        if rng.gen_bool(self.drop_probability) {
            debug!("Chaos: Simulating connection drop (EOF)");
            return Poll::Ready(Ok(())); // EOF
        }

        // 2. Simulate latency (spurious Pending)
        if rng.gen_bool(self.latency_probability) {
            // We return Pending but must wake the waker soon to not hang forever.
            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                waker.wake();
            });
            return Poll::Pending;
        }

        let pre_len = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);

        if let Poll::Ready(Ok(())) = &poll {
            let post_len = buf.filled().len();
            if post_len > pre_len {
                // 3. Simulate data corruption
                if rng.gen_bool(self.corrupt_probability) {
                    debug!("Chaos: Simulating bit corruption");
                    let data = buf.filled_mut();
                    let idx = rng.gen_range(pre_len..post_len);
                    data[idx] ^= 0xFF; // Flip bits
                }
            }
        }

        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ChaosStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut rng = rand::thread_rng();

        // 1. Simulate connection drop
        if rng.gen_bool(self.drop_probability) {
            debug!("Chaos: Simulating connection reset on write");
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "Chaos reset")));
        }

        // 2. Simulate latency (spurious Pending)
        if rng.gen_bool(self.latency_probability) {
            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                waker.wake();
            });
            return Poll::Pending;
        }

        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Wraps a UdpSocket (or similar) to inject chaos.
/// Note: Since UdpSocket doesn't implement AsyncRead/AsyncWrite directly in Tokio,
/// we provide an async method wrapper instead.
pub struct ChaosSocket {
    inner: tokio::net::UdpSocket,
    drop_probability: f64,
}

impl ChaosSocket {
    pub fn new(inner: tokio::net::UdpSocket) -> Self {
        Self {
            inner,
            drop_probability: 0.10, // 10% packet loss for UDP
        }
    }

    pub fn inner(&self) -> &tokio::net::UdpSocket {
        &self.inner
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        loop {
            let res = self.inner.recv_from(buf).await;
            let mut rng = rand::thread_rng();
            if res.is_ok() && rng.gen_bool(self.drop_probability) {
                debug!("Chaos: Simulating UDP packet drop on receive");
                continue; // drop packet, try next
            }
            return res;
        }
    }

    pub async fn send_to(&self, buf: &[u8], target: std::net::SocketAddr) -> io::Result<usize> {
        let drop = {
            let mut rng = rand::thread_rng();
            rng.gen_bool(self.drop_probability)
        };
        if drop {
            debug!("Chaos: Simulating UDP packet drop on send");
            return Ok(buf.len()); // Pretend it was sent
        }
        self.inner.send_to(buf, target).await
    }
    
    pub fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }
}
