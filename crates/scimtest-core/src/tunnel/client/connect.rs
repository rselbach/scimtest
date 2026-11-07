use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Default)]
pub(super) struct ProxyConfig {
    http: String,
    https: String,
    no_proxy: String,
    cgi: bool,
}
impl ProxyConfig {
    pub(super) fn from_env() -> Self {
        fn value(upper: &str, lower: &str) -> String {
            std::env::var(upper)
                .ok()
                .filter(|value| !value.is_empty())
                .or_else(|| std::env::var(lower).ok())
                .unwrap_or_default()
        }
        Self {
            http: value("HTTP_PROXY", "http_proxy"),
            https: value("HTTPS_PROXY", "https_proxy"),
            no_proxy: value("NO_PROXY", "no_proxy"),
            cgi: std::env::var("REQUEST_METHOD").is_ok_and(|value| !value.is_empty()),
        }
    }
    fn proxy(&self, server: &Url) -> Result<Option<Url>, Failure> {
        let raw = if server.scheme() == "wss" {
            &self.https
        } else {
            &self.http
        };
        let parse = |value: &str| {
            Url::parse(value)
                .ok()
                .filter(|url| url.host_str().is_some())
        };
        let Some(proxy) = parse(raw).or_else(|| parse(&format!("http://{raw}"))) else {
            return Ok(None);
        };
        if server.scheme() == "ws" && self.cgi {
            return Err(Failure::terminal(
                "refusing to use HTTP_PROXY value in CGI environment",
            ));
        }
        let host = server
            .host_str()
            .unwrap_or_default()
            .trim_matches(['[', ']'])
            .to_ascii_lowercase();
        let ip = host.parse::<IpAddr>().ok().map(|ip| ip.to_canonical());
        if host == "localhost" || ip.is_some_and(|ip| ip.is_loopback()) {
            return Ok(None);
        }
        let port = server.port_or_known_default().unwrap_or(80);
        if self
            .no_proxy
            .split(',')
            .any(|rule| bypass(rule, &host, port, ip))
        {
            return Ok(None);
        }
        Ok(Some(proxy))
    }
}
fn bypass(rule: &str, host: &str, port: u16, ip: Option<IpAddr>) -> bool {
    let rule = rule.trim().to_ascii_lowercase();
    if rule == "*" {
        return true;
    }
    if rule.is_empty() {
        return false;
    }
    if let Ok(network) = rule.parse::<ipnet::IpNet>() {
        return ip.is_some_and(|ip| network.contains(&ip));
    }
    let (rule, rule_port) = if let Some((host, port)) = rule
        .rsplit_once(':')
        .filter(|(host, _)| !host.contains(':') || host.starts_with('[') && host.ends_with(']'))
    {
        (host, Some(port))
    } else {
        (rule.as_str(), None)
    };
    if rule_port.is_some_and(|value| value != port.to_string()) {
        return false;
    }
    let rule = rule.trim_matches(['[', ']']);
    if let Ok(rule) = rule.parse::<IpAddr>() {
        return ip == Some(rule.to_canonical());
    }
    let rule = rule
        .strip_prefix("*.")
        .map(|rule| format!(".{rule}"))
        .unwrap_or_else(|| rule.to_owned());
    let subdomains_only = rule.starts_with('.');
    let rule = rule.trim_start_matches('.');
    let rule = url::Host::parse(rule)
        .map(|host| host.to_string())
        .unwrap_or_default();
    !rule.is_empty() && ((!subdomains_only && host == rule) || host.ends_with(&format!(".{rule}")))
}
pub(super) async fn socket(server: &Url, proxy: &ProxyConfig) -> Result<Socket, Failure> {
    tokio::time::timeout(Duration::from_secs(45), async {
        let proxy = proxy.proxy(server)?;
        let host = server.host_str().unwrap_or_default();
        let port = server.port_or_known_default().unwrap_or(80);
        let stream = match proxy {
            Some(proxy) => proxied(&proxy, host, port).await?,
            None => TcpStream::connect((host.trim_matches(['[', ']']), port))
                .await
                .map_err(|error| Failure::retry(error.to_string()))?,
        };
        let (socket, _) = tokio_tungstenite::client_async_tls_with_config(
            server.as_str(),
            stream,
            Some(
                WebSocketConfig::default()
                    .max_message_size(Some(MAX_MESSAGE))
                    .max_frame_size(Some(MAX_MESSAGE)),
            ),
            None,
        )
        .await?;
        Ok(socket)
    })
    .await
    .map_err(|_| Failure::retry("tunnel handshake timeout"))?
}
async fn proxied(proxy: &Url, host: &str, port: u16) -> Result<TcpStream, Failure> {
    let proxy_host = proxy
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    let proxy_port = proxy
        .port_or_known_default()
        .or_else(|| (proxy.scheme() == "socks5").then_some(1080))
        .ok_or_else(|| Failure::terminal("proxy has no port"))?;
    let username = percent_encoding::percent_decode_str(proxy.username())
        .decode_utf8()
        .map_err(|_| Failure::terminal("invalid proxy credentials"))?;
    let password = percent_encoding::percent_decode_str(proxy.password().unwrap_or_default())
        .decode_utf8()
        .map_err(|_| Failure::terminal("invalid proxy credentials"))?;
    match proxy.scheme() {
        "socks5" => {
            let proxy_addr = (proxy_host, proxy_port);
            let destination = (host.trim_matches(['[', ']']), port);
            let stream = if proxy.username().is_empty() {
                tokio_socks::tcp::Socks5Stream::connect(proxy_addr, destination).await
            } else {
                tokio_socks::tcp::Socks5Stream::connect_with_password(
                    proxy_addr,
                    destination,
                    &username,
                    &password,
                )
                .await
            }
            .map_err(|error| Failure::retry(format!("SOCKS proxy connection failed: {error}")))?;
            Ok(stream.into_inner())
        }
        "http" => {
            let mut stream = TcpStream::connect((proxy_host, proxy_port))
                .await
                .map_err(|error| Failure::retry(error.to_string()))?;
            let authority = format!("{host}:{port}");
            let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
            if !proxy.username().is_empty() && proxy.password().is_some() {
                request.push_str(&format!(
                    "Proxy-Authorization: Basic {}\r\n",
                    STANDARD.encode(format!("{username}:{password}"))
                ));
            }
            request.push_str("\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|error| Failure::retry(error.to_string()))?;
            let mut response = Vec::new();
            while !response.ends_with(b"\r\n\r\n") {
                if response.len() >= 32 << 10 {
                    return Err(Failure::retry("proxy CONNECT headers too large"));
                }
                response.push(
                    stream
                        .read_u8()
                        .await
                        .map_err(|error| Failure::retry(error.to_string()))?,
                );
            }
            let status = std::str::from_utf8(&response)
                .ok()
                .and_then(|value| value.lines().next())
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|status| status.parse::<u16>().ok())
                .unwrap_or_default();
            if status != 200 {
                return Err(Failure::retry(format!("proxy CONNECT returned {status}")));
            }
            Ok(stream)
        }
        _ => Err(Failure::terminal(format!(
            "proxy: unknown scheme: {}",
            proxy.scheme()
        ))),
    }
}

#[cfg(test)]
#[path = "connect_tests.rs"]
mod tests;
