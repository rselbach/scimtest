use crate::lock;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{Instant, Sleep},
};

#[derive(Default)]
pub(crate) struct WriteDeadline(Mutex<Option<Instant>>);

impl WriteDeadline {
    pub fn start(&self) {
        *lock(&self.0) = Some(Instant::now() + Duration::from_secs(130));
    }
    pub fn clear(&self) {
        *lock(&self.0) = None;
    }
}

pub(crate) struct DeadlineIo<S> {
    inner: S,
    deadline: Arc<WriteDeadline>,
    current: Option<Instant>,
    timer: Option<Pin<Box<Sleep>>>,
}

impl<S> DeadlineIo<S> {
    pub fn new(inner: S, deadline: Arc<WriteDeadline>) -> Self {
        Self {
            inner,
            deadline,
            current: None,
            timer: None,
        }
    }

    fn check(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        let next = *lock(&self.deadline.0);
        if next != self.current {
            self.current = next;
            self.timer = next.map(|deadline| Box::pin(tokio::time::sleep_until(deadline)));
        }
        if let Some(timer) = &mut self.timer
            && timer.as_mut().poll(cx).is_ready()
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "HTTP response write timed out",
            ));
        }
        Ok(())
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DeadlineIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DeadlineIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_write(cx, buffer)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_write_vectored(cx, buffers)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.check(cx)?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn blocked_response_write_expires_and_websocket_upgrade_can_clear_the_deadline() {
        let (writer, mut reader) = tokio::io::duplex(16);
        let deadline = Arc::new(WriteDeadline::default());
        *lock(&deadline.0) = Some(Instant::now() + Duration::from_millis(20));
        let mut writer = DeadlineIo::new(writer, deadline.clone());
        let error = tokio::time::timeout(Duration::from_secs(1), writer.write_all(&[42; 32]))
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let mut accepted = [0; 16];
        reader.read_exact(&mut accepted).await.unwrap();
        assert_eq!(accepted, [42; 16]);
        deadline.clear();
        writer.write_all(b"Greendale").await.unwrap();
        let mut accepted = [0; 9];
        reader.read_exact(&mut accepted).await.unwrap();
        assert_eq!(&accepted, b"Greendale");
    }
}
