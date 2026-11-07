use axum::http::HeaderMap;
use ipnet::IpNet;
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
};

pub(crate) fn hostname(value: &str) -> String {
    let value = value.trim().to_lowercase();
    let host = if let Some(rest) = value.strip_prefix('[') {
        rest.split_once("]:")
            .filter(|(host, port)| !host.contains(['[', ']']) && !port.contains([':', '[', ']']))
            .map_or(value.as_str(), |(host, _)| host)
    } else if value.matches(':').count() == 1 && !value.contains(['[', ']']) {
        value
            .split_once(':')
            .map_or(value.as_str(), |(host, _)| host)
    } else {
        &value
    };
    let host = host.trim_matches(['[', ']']);
    host.strip_suffix('.').unwrap_or(host).into()
}

pub(crate) fn same_host(a: &str, b: &str) -> bool {
    hostname(a) == hostname(b)
}

pub(crate) fn host_allowed(host: &str, configured: &str) -> bool {
    if same_host(host, configured) {
        return true;
    }
    let host = hostname(host);
    host == "localhost"
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| canonical_ip(ip).is_loopback())
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip => ip,
    }
}

pub(crate) fn enrollment_ip(value: &str) -> String {
    match value.trim().parse::<IpAddr>().map(canonical_ip) {
        Ok(IpAddr::V4(ip)) => ip.to_string(),
        Ok(IpAddr::V6(ip)) => format!("{}/64", Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64))),
        Err(_) => value.trim().to_lowercase(),
    }
}

pub(crate) fn client_ip(
    peer: SocketAddr,
    headers: &HeaderMap,
    behind: bool,
    trusted: &[IpNet],
) -> String {
    let remote = canonical_ip(peer.ip());
    if !behind || !trusted.iter().any(|net| net.contains(&remote)) {
        return remote.to_string();
    }
    let all: Vec<_> = headers
        .get_all("x-forwarded-for")
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .collect();
    for entry in all.into_iter().rev() {
        let Ok(entry) = std::str::from_utf8(entry) else {
            return remote.to_string();
        };
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Ok(ip) = entry.parse::<IpAddr>() else {
            return remote.to_string();
        };
        if !trusted.iter().any(|net| net.contains(&canonical_ip(ip))) {
            return entry.into();
        }
    }
    remote.to_string()
}

pub(crate) fn scheme(
    peer: SocketAddr,
    headers: &HeaderMap,
    behind: bool,
    trusted: &[IpNet],
) -> String {
    if behind
        && trusted
            .iter()
            .any(|net| net.contains(&canonical_ip(peer.ip())))
        && let Some(value) = headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .filter(|value| !value.is_empty())
    {
        return value.into();
    }
    "http".into()
}

pub(crate) fn remove_hop_headers(headers: &mut HeaderMap) {
    let dynamic: Vec<_> = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(',').map(str::trim))
        .map(str::to_owned)
        .collect();
    for name in dynamic {
        headers.remove(name.as_str());
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

pub(crate) fn wire_headers(headers: &HeaderMap) -> BTreeMap<String, Vec<String>> {
    let mut result = BTreeMap::new();
    for name in headers.keys() {
        let mut upper = true;
        let canonical: String = name
            .as_str()
            .chars()
            .map(|ch| {
                let result = if upper { ch.to_ascii_uppercase() } else { ch };
                upper = ch == '-';
                result
            })
            .collect();
        result.insert(
            canonical,
            headers
                .get_all(name)
                .iter()
                .map(|value| String::from_utf8_lossy(value.as_bytes()).into())
                .collect(),
        );
    }
    result
}
