use super::*;

#[test]
fn proxy_rules_follow_scheme_no_proxy_ports_networks_and_loopback_exceptions() {
    let config = ProxyConfig {
        http: "http://proxy.greendale.example:3128".into(),
        https: "socks5://proxy.greendale.example:1080".into(),
        no_proxy: "greendale.edu,.study-group.example,*.airconditioning.example,203.0.113.0/24,192.0.2.7:8080,[2001:db8::7]:443,service.example:443,bücher.example".into(),
        cgi: false,
    };
    for (target, want) in [
        ("ws://scimtest.example", Some("http")),
        ("wss://scimtest.example", Some("socks5")),
        ("ws://localhost:7000", None),
        ("ws://127.0.0.2:7000", None),
        ("wss://[::1]", None),
        ("wss://greendale.edu", None),
        ("wss://www.greendale.edu", None),
        ("wss://citygreendale.edu", Some("socks5")),
        ("wss://study-group.example", Some("socks5")),
        ("wss://troy.study-group.example", None),
        ("ws://airconditioning.example", Some("http")),
        ("ws://troy.airconditioning.example", None),
        ("wss://203.0.113.9", None),
        ("wss://203.0.112.9", Some("socks5")),
        ("ws://192.0.2.7:8080", None),
        ("ws://192.0.2.7", Some("http")),
        ("wss://[2001:db8::7]", None),
        ("ws://[2001:db8::7]", Some("http")),
        ("wss://service.example", None),
        ("ws://service.example", Some("http")),
        ("wss://BÜCHER.example", None),
    ] {
        assert_eq!(
            config
                .proxy(&Url::parse(target).unwrap())
                .unwrap()
                .map(|url| url.scheme().to_owned())
                .as_deref(),
            want,
            "{target}"
        );
    }
    let wildcard = ProxyConfig {
        no_proxy: "*".into(),
        ..config
    };
    assert!(
        wildcard
            .proxy(&Url::parse("wss://scimtest.example").unwrap())
            .unwrap()
            .is_none()
    );
    let cgi = ProxyConfig {
        http: "proxy.greendale.example:3128".into(),
        cgi: true,
        ..Default::default()
    };
    assert!(
        cgi.proxy(&Url::parse("ws://scimtest.example").unwrap())
            .unwrap_err()
            .message
            .contains("CGI")
    );
    let host_only = ProxyConfig {
        http: "proxy.greendale.example:3128".into(),
        ..Default::default()
    };
    assert_eq!(
        host_only
            .proxy(&Url::parse("ws://scimtest.example").unwrap())
            .unwrap()
            .unwrap()
            .as_str(),
        "http://proxy.greendale.example:3128/"
    );
}

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn websocket_uses_authenticated_connect_without_leaking_proxy_credentials_to_the_server() {
    for code in [200, 407] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = ProxyConfig {
            http: format!("http://troy:p%40ss@{}", listener.local_addr().unwrap()),
            ..Default::default()
        };
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT scimtest.greendale.invalid:7000 HTTP/1.1\r\n"));
            assert!(request.contains(&format!(
                "Proxy-Authorization: Basic {}\r\n",
                STANDARD.encode("troy:p@ss")
            )));
            stream
                .write_all(format!("HTTP/1.1 {code} Greendale\r\n\r\n").as_bytes())
                .await
                .unwrap();
            if code != 200 {
                return;
            }
            let mut socket = tokio_tungstenite::accept_hdr_async(
                stream,
                |request: &tungstenite::handshake::server::Request, response| {
                    assert_eq!(request.uri(), "/api/connect");
                    assert!(!request.headers().contains_key("proxy-authorization"));
                    Ok(response)
                },
            )
            .await
            .unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap(),
                tungstenite::Message::Text("Greendale".into())
            );
        });
        let result = socket(
            &Url::parse("ws://scimtest.greendale.invalid:7000/api/connect").unwrap(),
            &proxy,
        )
        .await;
        if code == 200 {
            result
                .unwrap()
                .send(tungstenite::Message::Text("Greendale".into()))
                .await
                .unwrap();
        } else {
            assert!(result.unwrap_err().message.contains("407"));
        }
        task.await.unwrap();
    }
}

#[tokio::test]
async fn socks_proxy_resolves_the_destination_and_supports_optional_password_authentication() {
    for authenticated in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let auth = if authenticated { "troy:greendale@" } else { "" };
        let proxy = ProxyConfig {
            http: format!("socks5://{auth}{}", listener.local_addr().unwrap()),
            ..Default::default()
        };
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(stream.read_u8().await.unwrap(), 5);
            let mut methods = vec![0; stream.read_u8().await.unwrap() as usize];
            stream.read_exact(&mut methods).await.unwrap();
            let method = if authenticated { 2 } else { 0 };
            assert!(methods.contains(&method));
            stream.write_all(&[5, method]).await.unwrap();
            if authenticated {
                assert_eq!(stream.read_u8().await.unwrap(), 1);
                let mut username = vec![0; stream.read_u8().await.unwrap() as usize];
                stream.read_exact(&mut username).await.unwrap();
                let mut password = vec![0; stream.read_u8().await.unwrap() as usize];
                stream.read_exact(&mut password).await.unwrap();
                assert_eq!(username, b"troy");
                assert_eq!(password, b"greendale");
                stream.write_all(&[1, 0]).await.unwrap();
            }
            let mut request = [0; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 3]);
            let mut hostname = vec![0; stream.read_u8().await.unwrap() as usize];
            stream.read_exact(&mut hostname).await.unwrap();
            assert_eq!(hostname, b"scimtest.greendale.invalid");
            assert_eq!(stream.read_u16().await.unwrap(), 7000);
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            assert_eq!(
                socket.next().await.unwrap().unwrap(),
                tungstenite::Message::Text("Greendale".into())
            );
        });
        let mut socket = socket(
            &Url::parse("ws://scimtest.greendale.invalid:7000/api/connect").unwrap(),
            &proxy,
        )
        .await
        .unwrap();
        socket
            .send(tungstenite::Message::Text("Greendale".into()))
            .await
            .unwrap();
        task.await.unwrap();
    }
}
