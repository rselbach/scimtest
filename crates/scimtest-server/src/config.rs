use crate::application::validate_path;
use anyhow::{Result, bail};
use ipnet::IpNet;
use std::{path::PathBuf, time::Duration};

#[derive(Clone)]
pub struct Config {
    pub addr: String,
    pub domain: String,
    pub dashboard_domain: String,
    pub public_scheme: String,
    pub behind_proxy: bool,
    pub trusted_proxy_cidrs: Vec<String>,
    pub connect_path: String,
    pub data_path: PathBuf,
    pub github_client_id: String,
    pub github_client_secret: String,
    pub max_body_bytes: i64,
    pub max_tunnels_per_application: usize,
    pub max_installations_per_user: usize,
    pub shutdown_timeout: Duration,
    pub logs: bool,
    pub log_format: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            addr: ":7000".into(),
            domain: "localhost:7000".into(),
            dashboard_domain: String::new(),
            public_scheme: "http".into(),
            behind_proxy: false,
            trusted_proxy_cidrs: Vec::new(),
            connect_path: "/api/connect".into(),
            data_path: "scimtest-server.json".into(),
            github_client_id: String::new(),
            github_client_secret: String::new(),
            max_body_bytes: scimtest_protocol::MAX_BODY as i64,
            max_tunnels_per_application: 5,
            max_installations_per_user: 5,
            shutdown_timeout: Duration::from_secs(30),
            logs: false,
            log_format: "text".into(),
        }
    }
}

pub(crate) const MANAGEMENT_PATHS: &[&str] = &[
    "/",
    "/healthz",
    "/ready",
    "/api/metrics",
    "/api/enroll/status",
    "/login/github",
    "/auth/github/callback",
    "/enroll",
    "/enroll/browser",
    "/enroll/replace",
    "/logout",
    "/dashboard",
    "/dashboard/app.js",
    "/dashboard/tunnels",
    "/dashboard/applications/create",
    "/dashboard/applications/update",
    "/dashboard/applications/delete",
    "/dashboard/applications/reservations/delete",
    "/dashboard/applications/instances/revoke",
    "/dashboard/tunnels/disconnect",
];

impl Config {
    pub(crate) fn normalize(mut self) -> Result<(Self, Vec<IpNet>)> {
        if self.addr.is_empty() {
            self.addr = ":7000".into();
        }
        if self.domain.is_empty() {
            self.domain = "localhost:7000".into();
        }
        if self.public_scheme.is_empty() {
            self.public_scheme = "http".into();
        }
        if self.behind_proxy {
            self.public_scheme = "https".into();
        }
        if self.connect_path.is_empty() {
            self.connect_path = "/api/connect".into();
        }
        validate_path(&self.connect_path)
            .map_err(|error| anyhow::anyhow!("invalid connect path: {error}"))?;
        if !self
            .connect_path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/-._~".contains(&byte))
        {
            bail!("invalid connect path: only literal URL path characters are allowed");
        }
        if MANAGEMENT_PATHS.contains(&self.connect_path.as_str()) {
            bail!(
                "connect path {:?} conflicts with a server route",
                self.connect_path
            );
        }
        if self.data_path.as_os_str().is_empty() {
            self.data_path = "scimtest-server.json".into();
        }
        if self.max_body_bytes <= 0 {
            self.max_body_bytes = scimtest_protocol::MAX_BODY as i64;
        }
        self.domain = normalize_domain(&self.domain);
        if self.dashboard_domain.is_empty() {
            self.dashboard_domain = self.domain.clone();
        }
        self.dashboard_domain = normalize_domain(&self.dashboard_domain);
        if self.github_client_id.is_empty() != self.github_client_secret.is_empty() {
            bail!("both GitHub client ID and secret are required");
        }
        if !self.github_client_id.is_empty()
            && crate::network::same_host(&self.domain, &self.dashboard_domain)
        {
            bail!("dashboard domain must differ from the public tunnel domain");
        }
        if self.max_tunnels_per_application == 0 {
            self.max_tunnels_per_application = 5;
        }
        if self.max_installations_per_user == 0 {
            self.max_installations_per_user = 5;
        }
        if self.shutdown_timeout.is_zero() {
            self.shutdown_timeout = Duration::from_secs(30);
        }
        if self.logs && !matches!(self.log_format.as_str(), "text" | "json") {
            bail!("invalid log format {:?}: use text or json", self.log_format);
        }
        let mut trusted = Vec::new();
        if self.trusted_proxy_cidrs.is_empty() {
            self.trusted_proxy_cidrs = vec!["127.0.0.0/8".into(), "::1/128".into()];
        }
        for raw in &self.trusted_proxy_cidrs {
            for part in raw
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
            {
                trusted.push(part.parse().map_err(|error| {
                    anyhow::anyhow!("invalid trusted proxy CIDR {part:?}: {error}")
                })?);
            }
        }
        Ok((self, trusted))
    }
}

fn normalize_domain(value: &str) -> String {
    let value = value.strip_prefix("https://").unwrap_or(value);
    value
        .strip_prefix("http://")
        .unwrap_or(value)
        .trim_end_matches('/')
        .into()
}
