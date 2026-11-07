use super::protocol::Message;
use serde::Serialize;
use std::time::Duration;
use url::Url;

#[derive(Clone, Serialize)]
pub struct Enrollment {
    pub url: String,
    pub browser_handoff_url: String,
    pub verification_code: String,
    #[serde(skip)]
    pub(super) status_url: Url,
    #[serde(skip)]
    pub(super) device_code: String,
    #[serde(skip)]
    pub(super) poll_interval: Duration,
}
impl Enrollment {
    pub(super) fn parse(server: &Url, message: Message) -> Result<Self, String> {
        if [
            &message.enrollment_url,
            &message.enrollment_browser_handoff_url,
            &message.enrollment_status_url,
        ]
        .iter()
        .any(|value| value.len() > 2048)
        {
            return Err("enrollment URL is too long".into());
        }
        let url = http_url(&message.enrollment_url, "enrollment URL")?;
        if server.scheme() == "wss" && url.scheme() != "https" {
            return Err("enrollment URL must use HTTPS with a secure tunnel server".into());
        }
        let browser = message.enrollment_browser_handoff_url.trim();
        if !browser.is_empty() {
            let handoff = http_url(browser, "browser handoff URL")?;
            if server.scheme() == "wss" && handoff.scheme() != "https" {
                return Err(
                    "browser handoff URL must use HTTPS with a secure tunnel server".into(),
                );
            }
            if origin(&handoff)? != origin(&url)? {
                return Err("browser handoff URL must use the enrollment page origin".into());
            }
        }
        let status = http_url(&message.enrollment_status_url, "enrollment status URL")?;
        if status.query().is_some() || status.fragment().is_some() {
            return Err(
                "enrollment status URL must not contain user information, a query, or a fragment"
                    .into(),
            );
        }
        let mut expected = server.clone();
        let scheme = match server.scheme() {
            "ws" => "http",
            "wss" => "https",
            _ => return Err("tunnel server URL must use WS or WSS".into()),
        };
        expected
            .set_scheme(scheme)
            .map_err(|_| "invalid tunnel server scheme")?;
        if origin(&status)? != origin(&expected)? {
            return Err("enrollment status URL must use the tunnel server origin".into());
        }
        let code = message.enrollment_verification_code.trim();
        if message.enrollment_device_code.len() > 256
            || !valid_bearer(&message.enrollment_device_code)
        {
            return Err("enrollment device code is invalid".into());
        }
        if code.len() > 64 || !valid_bearer(code) {
            return Err("enrollment verification code is invalid".into());
        }
        Ok(Self {
            url: message.enrollment_url,
            browser_handoff_url: browser.into(),
            verification_code: code.into(),
            status_url: status,
            device_code: message.enrollment_device_code,
            poll_interval: Duration::from_secs(if message.enrollment_poll_seconds <= 0 {
                2
            } else {
                message.enrollment_poll_seconds.min(60) as u64
            }),
        })
    }
    pub fn authorization_url(&self) -> String {
        if !self.browser_handoff_url.is_empty() {
            return self.browser_handoff_url.clone();
        }
        let Ok(mut url) = Url::parse(&self.url) else {
            return self.url.clone();
        };
        let mut query = url
            .query_pairs()
            .filter(|(key, _)| key != "presentation")
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        query.push(("presentation".into(), "desktop".into()));
        url.query_pairs_mut().clear().extend_pairs(query);
        url.into()
    }
}
fn http_url(value: &str, label: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| format!("{label} must be absolute"))?;
    if url.host_str().is_none() {
        return Err(format!("{label} must be absolute"));
    }
    if !["http", "https"].contains(&url.scheme()) {
        return Err(format!("{label} must use HTTP or HTTPS"));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || value.split_once("://").is_some_and(|(_, rest)| {
            rest.split(['/', '?', '#'])
                .next()
                .is_some_and(|authority| authority.contains('@'))
        })
    {
        return Err(format!("{label} must not contain user information"));
    }
    Ok(url)
}
fn origin(url: &Url) -> Result<(String, String, u16), String> {
    if !["http", "https"].contains(&url.scheme()) {
        return Err("URL must use HTTP or HTTPS".into());
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or("URL host is required")?;
    Ok((
        url.scheme().into(),
        host.trim_end_matches('.').to_lowercase(),
        url.port_or_known_default().ok_or("URL port is required")?,
    ))
}
fn valid_bearer(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte > b' ' && byte < 0x7f)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn message() -> Message {
        Message {
            enrollment_url: "https://accounts.greendale.example/enroll".into(),
            enrollment_browser_handoff_url:
                "https://accounts.greendale.example/enroll/browser?handoff=one-use".into(),
            enrollment_status_url: "https://identity.greendale.example/status".into(),
            enrollment_device_code: "greendale-private-device-code".into(),
            enrollment_verification_code: "GREEN-DALE".into(),
            ..Default::default()
        }
    }
    #[test]
    fn enrollment_urls_keep_the_poll_credential_on_the_server_origin() {
        let server = Url::parse("wss://identity.greendale.example/api/connect").unwrap();
        let enrollment = Enrollment::parse(&server, message()).unwrap();
        assert_eq!(enrollment.poll_interval, Duration::from_secs(2));
        assert!(
            !serde_json::to_string(&enrollment)
                .unwrap()
                .contains("greendale-private-device-code")
        );
        for (field, value) in [
            ("enrollment_url", "http://accounts.greendale.example/enroll"),
            (
                "enrollment_url",
                "https://@accounts.greendale.example/enroll",
            ),
            (
                "enrollment_browser_handoff_url",
                "https://citycollege.example/handoff",
            ),
            (
                "enrollment_status_url",
                "https://citycollege.example/status",
            ),
            (
                "enrollment_status_url",
                "https://identity.greendale.example/status?device=greendale",
            ),
            (
                "enrollment_status_url",
                "https://identity.greendale.example/status#fragment",
            ),
            ("enrollment_device_code", "greendale\r\nsecret"),
            ("enrollment_verification_code", "GREEN DALE"),
        ] {
            let mut values = serde_json::to_value(message()).unwrap();
            values[field] = serde_json::json!(value);
            let input = serde_json::from_value(values).unwrap();
            assert!(
                Enrollment::parse(&server, input).is_err(),
                "{field}: {value}"
            );
        }
        let mut input = message();
        input.enrollment_browser_handoff_url.clear();
        input
            .enrollment_url
            .push_str("?presentation=embedded&code=greendale");
        input.enrollment_poll_seconds = 100;
        let legacy = Enrollment::parse(&server, input).unwrap();
        assert_eq!(legacy.poll_interval, Duration::from_secs(60));
        let url = Url::parse(&legacy.authorization_url()).unwrap();
        assert_eq!(
            url.query_pairs()
                .filter(|(key, _)| key == "presentation")
                .map(|(_, value)| value.into_owned())
                .collect::<Vec<_>>(),
            vec!["desktop"]
        );
    }
}
