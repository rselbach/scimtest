use crate::Server;
use anyhow::Result;
use axum::{Extension, extract::ConnectInfo};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::time::Duration;
use tokio::{net::TcpListener, task::JoinSet};
use tokio_util::sync::CancellationToken;

pub(crate) mod deadline;

impl Server {
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        let address = if self.0.config.addr.starts_with(':') {
            format!("[::]{}", self.0.config.addr)
        } else {
            self.0.config.addr.clone()
        };
        let listener = TcpListener::bind(&address).await?;
        self.serve(listener, shutdown).await
    }

    pub async fn serve(self, listener: TcpListener, shutdown: CancellationToken) -> Result<()> {
        let _shutdown_guard = self.0.shutdown.clone().drop_guard();
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => break,
                accepted = listener.accept() => {
                    let (stream,peer) = accepted?;
                    let deadline = std::sync::Arc::new(deadline::WriteDeadline::default());
                    let router = self.router().layer(Extension(ConnectInfo(peer))).layer(Extension(deadline.clone()));
                    let stream = deadline::DeadlineIo::new(stream,deadline);
                    let shutdown = self.0.shutdown.clone();
                    let grace = self.0.config.shutdown_timeout;
                    let logs = self.0.config.logs;
                    connections.spawn(async move {
                        let mut builder = hyper::server::conn::http1::Builder::new();
                        builder.timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(30))
                            .max_buf_size((1 << 20)+4096).max_headers(500);
                        let connection = builder.serve_connection(TokioIo::new(stream),TowerToHyperService::new(router)).with_upgrades();
                        tokio::pin!(connection);
                        tokio::select! {
                            result = &mut connection => { if let Err(error) = result && logs { eprintln!("HTTP connection ended: {error}"); } }
                            _ = shutdown.cancelled() => {
                                connection.as_mut().graceful_shutdown();
                                let _ = tokio::time::timeout(grace,connection).await;
                            }
                        }
                    });
                }
                Some(result) = connections.join_next(), if !connections.is_empty() => {
                    if let Err(error) = result { eprintln!("HTTP connection task ended: {error}"); }
                }
            }
        }
        drop(listener);
        self.0.shutdown.cancel();
        self.0.tasks.close();
        let grace = self.0.config.shutdown_timeout;
        tokio::time::timeout(grace, async {
            while connections.join_next().await.is_some() {}
            self.0.tasks.wait().await;
        })
        .await
        .map_err(|_| anyhow::anyhow!("server shutdown timed out"))?;
        Ok(())
    }
}
