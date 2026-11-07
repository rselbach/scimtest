use anyhow::Result;
use clap::Parser;
use scimtest_server::{Config, Server};
use tokio_util::sync::CancellationToken;

#[derive(Parser)]
#[command(name = "scimtest-server", about = "Public tunnel service for scimtest")]
struct Arguments {
    #[arg(long, default_value = ":7000")]
    addr: String,
    #[arg(long, default_value = "localhost:7000")]
    domain: String,
    #[arg(long, default_value = "")]
    dashboard_domain: String,
    #[arg(long, default_value = "http")]
    scheme: String,
    #[arg(long,action=clap::ArgAction::Set,num_args=0..=1,default_missing_value="true",default_value="false")]
    behind_proxy: bool,
    #[arg(long, default_value = "127.0.0.0/8,::1/128")]
    trusted_proxy_cidrs: String,
    #[arg(long, default_value = "/api/connect")]
    connect_path: String,
    #[arg(long, default_value = "scimtest-server.json")]
    data: std::path::PathBuf,
    #[arg(long, env = "SCIMTEST_GITHUB_CLIENT_ID", default_value = "")]
    github_client_id: String,
    #[arg(
        long,
        env = "SCIMTEST_GITHUB_CLIENT_SECRET",
        default_value = "",
        hide_env_values = true
    )]
    github_client_secret: String,
    #[arg(long,default_value_t=32<<20,allow_hyphen_values=true)]
    max_body: i64,
    #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
    max_tunnels_per_application: i64,
    #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
    max_installations_per_user: i64,
    #[arg(long,action=clap::ArgAction::Set,num_args=0..=1,default_missing_value="true",default_value="false")]
    logs: bool,
    #[arg(long, default_value = "text")]
    log_format: String,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = std::env::args_os().map(|argument| {
        let Some(value) = argument.to_str() else {
            return argument;
        };
        let key = value.split('=').next().unwrap_or(value);
        if key.starts_with('-') && !key.starts_with("--") && key.len() > 2 {
            format!("-{value}").into()
        } else {
            argument
        }
    });
    let args = Arguments::parse_from(args);
    let config = Config {
        addr: args.addr,
        domain: args.domain,
        dashboard_domain: args.dashboard_domain,
        public_scheme: args.scheme,
        behind_proxy: args.behind_proxy,
        trusted_proxy_cidrs: vec![args.trusted_proxy_cidrs],
        connect_path: args.connect_path,
        data_path: args.data,
        github_client_id: args.github_client_id,
        github_client_secret: args.github_client_secret,
        max_body_bytes: args.max_body,
        max_tunnels_per_application: args.max_tunnels_per_application.try_into().unwrap_or(0),
        max_installations_per_user: args.max_installations_per_user.try_into().unwrap_or(0),
        logs: args.logs,
        log_format: args.log_format,
        ..Config::default()
    };
    let server = Server::new(config)?;
    let shutdown = CancellationToken::new();
    let signal_shutdown = shutdown.clone();
    let signal = tokio::spawn(async move {
        let result = shutdown_signal().await;
        signal_shutdown.cancel();
        result
    });
    let result = server.run(shutdown).await;
    signal.abort();
    match signal.await {
        Ok(result) => result?,
        Err(error) if error.is_cancelled() => {}
        Err(error) => return Err(error.into()),
    }
    result
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result=tokio::signal::ctrl_c()=>result?, _=terminate.recv()=>{} }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
