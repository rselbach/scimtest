use super::*;
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::{CancellationToken, WaitForCancellationFutureOwned};

pub(super) struct Listener {
    inner: tokio::net::TcpListener,
    force: CancellationToken,
}
pub(super) fn listener(inner: tokio::net::TcpListener, force: CancellationToken) -> Listener {
    Listener { inner, force }
}
impl axum::serve::Listener for Listener {
    type Io = Connection;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Connection, SocketAddr) {
        let (inner, address) = axum::serve::Listener::accept(&mut self.inner).await;
        (
            Connection {
                inner,
                cancelled: Box::pin(self.force.clone().cancelled_owned()),
            },
            address,
        )
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}
pub(super) struct Connection {
    inner: tokio::net::TcpStream,
    cancelled: Pin<Box<WaitForCancellationFutureOwned>>,
}
impl Connection {
    fn cancelled(&mut self, cx: &mut TaskContext<'_>) -> bool {
        self.cancelled.as_mut().poll(cx).is_ready()
    }
}
fn closed() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::ConnectionAborted,
        "scimtest is shutting down",
    )
}
impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.cancelled(cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.cancelled(cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        if self.cancelled(cx) {
            return Poll::Ready(Err(closed()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.cancelled(cx) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(super) async fn server(
    task: Option<JoinHandle<std::io::Result<()>>>,
    name: &str,
    deadline: tokio::time::Instant,
    force: &CancellationToken,
) -> Result<()> {
    let Some(mut task) = task else {
        return Ok(());
    };
    match tokio::time::timeout_at(deadline, &mut task).await {
        Ok(result) => {
            return result
                .with_context(|| format!("Join {name}"))?
                .with_context(|| format!("Serve {name}"));
        }
        Err(_) => force.cancel(),
    }
    match tokio::time::timeout(std::time::Duration::from_secs(1), &mut task).await {
        Ok(result) => result
            .with_context(|| format!("Join {name}"))?
            .with_context(|| format!("Serve {name}")),
        Err(_) => {
            task.abort();
            match task.await {
                Err(error) if error.is_cancelled() => Ok(()),
                result => result
                    .with_context(|| format!("Join {name}"))?
                    .with_context(|| format!("Serve {name}")),
            }
        }
    }
}
pub(super) async fn wait_server(
    task: &mut Option<JoinHandle<std::io::Result<()>>>,
    name: &str,
) -> Result<()> {
    match task {
        Some(task) => task
            .await
            .with_context(|| format!("Join {name}"))?
            .with_context(|| format!("Serve {name}")),
        None => std::future::pending().await,
    }
}
pub(super) async fn signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("Listen for termination")?;
        tokio::select! {
            result=tokio::signal::ctrl_c()=>result.context("Wait for interrupt"),
            _=terminate.recv()=>Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.context("Wait for interrupt")
    }
}
