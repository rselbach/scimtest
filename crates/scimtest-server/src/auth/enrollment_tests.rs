use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn actual_go_client_enrolls_polls_reconnects_and_forwards_through_the_rust_service() {
    let go = support::GoFixture::new();
    let mut app = Running::configured(false, 5, true).await;
    let enrollment_path = app.directory.path().join("enrollment.json");
    let ready = app.directory.path().join("client-ready.json");
    let stop = app.directory.path().join("stop");
    let input = json!({"kind":"client","client":{"server_url":app.base.replacen("http","ws",1)+"/api/connect","profile_id":app.profile,"ready_path":ready,"stop_path":stop,"enrollment_path":enrollment_path}});
    let peer = tokio::task::spawn_blocking(move || go.run(input));
    let required = wait_json(&enrollment_path).await;
    let required: Message = serde_json::from_value(required).unwrap();
    assert_eq!(app.approve(&required).await.status(), StatusCode::OK);
    let registered = wait_json(&ready).await;
    assert_eq!(registered["github_user_id"], 101);
    assert_eq!(registered["github_login"], "troy-barnes");
    let public = registered["public_url"].as_str().unwrap();
    let response = app
        .client
        .get(format!("{public}/oidc/greendale/jwks"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-greendale-client"], "Go");
    assert_eq!(response.json::<Value>().await.unwrap()["method"], "GET");
    std::fs::write(&stop, "stop").unwrap();
    assert_eq!(
        tokio::time::timeout(StdDuration::from_secs(5), peer)
            .await
            .unwrap()
            .unwrap(),
        json!({"stopped":true})
    );
    app.wait_disconnected().await;
    app.stop().await;
}

async fn wait_json(path: &std::path::Path) -> Value {
    tokio::time::timeout(StdDuration::from_secs(8), async {
        loop {
            match std::fs::read(path) {
                Ok(bytes) => return serde_json::from_slice(&bytes).unwrap(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::time::sleep(StdDuration::from_millis(10)).await
                }
                Err(error) => panic!("{error}"),
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn enrollment_status_credentials_methods_and_ip_grouping_match_go() {
    let mut app = Running::new(false, 5).await;
    let mut cases = Vec::new();
    for method in ["POST", "GET", "PUT"] {
        for credential in [
            String::new(),
            "Bearer ".into(),
            "Basic troy".into(),
            format!("Bearer {}", "a".repeat(64)),
            format!("bEaReR {}", "a".repeat(64)),
            format!("Bearer {}", "A".repeat(64)),
            format!("Bearer {} ", "a".repeat(64)),
            format!("Bearer  {}", "a".repeat(64)),
            format!("Bearer {}", "a".repeat(63)),
            format!("Bearer {}", "a".repeat(65)),
        ] {
            cases.push(json!({"kind":"enrollment_status","method":method,"value":credential}));
        }
    }
    for ip in [
        "192.0.2.10",
        "::ffff:192.0.2.10",
        "2001:db8:1234:5678:abcd::1",
        "2001:db8:1234:5678::ffff",
        "TROY-NETWORK",
        " 192.0.2.10 ",
    ] {
        cases.push(json!({"kind":"enrollment_ip","value":ip}));
    }
    let reference = support::GoFixture::new().run(json!({"kind":"policy","policies":cases}));
    for (case, want) in cases.iter().zip(reference.as_array().unwrap()) {
        let got = if case["kind"] == "enrollment_ip" {
            json!(network::enrollment_ip(case["value"].as_str().unwrap()))
        } else {
            let request = Request::builder()
                .method(case["method"].as_str().unwrap())
                .uri("/api/enroll/status")
                .header("authorization", case["value"].as_str().unwrap())
                .body(Body::empty())
                .unwrap();
            let response = app.server.0.enrollment_status(&request);
            let status = response.status().as_u16();
            let headers = response.headers().clone();
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            json!({"status":status,"body":String::from_utf8(body.to_vec()).unwrap(),"content_type":header(&headers,"content-type"),"cache":header(&headers,"cache-control"),"allow":header(&headers,"allow"),"authenticate":header(&headers,"www-authenticate")})
        };
        assert_eq!(got, *want, "{case}");
    }
    println!(
        "Compared {} enrollment status and network cases with Go",
        cases.len()
    );
    app.stop().await;
}

#[tokio::test]
async fn replacement_revokes_only_the_selected_account_installation_and_closes_its_socket() {
    let mut app = Running::new(false, 1).await;
    let first = app.pending(24, "192.0.2.10");
    assert_eq!(app.approve(&first).await.status(), StatusCode::OK);
    let (socket, reply) = app.dial(24, "", &first.enrollment_device_code, 24).await;
    assert_eq!(decode(reply).kind, "tunnel_registered");
    let foreign = app.binding(26, "");
    app.server
        .store()
        .enroll_instance(
            &app.profile,
            &foreign.instance,
            &foreign.key,
            EnrollmentActor {
                github_user_id: 202,
                github_login: "abed-nadir".into(),
            },
        )
        .unwrap();
    let second = app.pending(25, "192.0.2.11");
    let chooser = app.approve(&second).await;
    assert_eq!(chooser.status(), StatusCode::OK);
    let cookie = response_cookie(&chooser, "scimtest_enrollment_replacement");
    let html = chooser.text().await.unwrap();
    assert!(html.contains("Disconnect and continue"));
    assert!(!html.contains(&foreign.instance));
    assert_eq!(
        app.poll(&second.enrollment_device_code)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"status":"pending"})
    );
    let denied_origin = app
        .request(Method::POST, "/enroll/replace")
        .header("origin", "http://evil.greendale.test")
        .header("cookie", &cookie)
        .form(&[
            ("instance_id", app.binding(24, "").instance.as_str()),
            ("csrf_token", csrf(&html)),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(denied_origin.status(), StatusCode::FORBIDDEN);
    let denied_csrf = app
        .request(Method::POST, "/enroll/replace")
        .header("origin", "http://admin.greendale.test")
        .header("cookie", &cookie)
        .form(&[
            ("instance_id", app.binding(24, "").instance.as_str()),
            ("csrf_token", "wrong"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(denied_csrf.status(), StatusCode::BAD_REQUEST);
    let forbidden = app
        .request(Method::POST, "/enroll/replace")
        .header("origin", "http://admin.greendale.test")
        .header("cookie", &cookie)
        .form(&[
            ("instance_id", foreign.instance.as_str()),
            ("csrf_token", csrf(&html)),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(forbidden.status(), StatusCode::OK);
    let refreshed_cookie = response_cookie(&forbidden, "scimtest_enrollment_replacement");
    assert_ne!(cookie, refreshed_cookie);
    let refreshed = forbidden.text().await.unwrap();
    assert!(refreshed.contains("no longer available"));
    assert!(
        !app.server
            .store()
            .instance(&app.profile, &foreign.instance)
            .unwrap()
            .unwrap()
            .revoked
    );
    let replaced = app
        .request(Method::POST, "/enroll/replace")
        .header("origin", "http://admin.greendale.test")
        .header("cookie", &refreshed_cookie)
        .form(&[
            ("instance_id", app.binding(24, "").instance.as_str()),
            ("csrf_token", csrf(&refreshed)),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replaced.status(), StatusCode::OK);
    assert!(
        replaced
            .text()
            .await
            .unwrap()
            .contains("Installation authorized")
    );
    app.server_closed(socket).await;
    assert!(
        app.server
            .store()
            .instance(&app.profile, &app.binding(24, "").instance)
            .unwrap()
            .unwrap()
            .revoked
    );
    let replay = app
        .request(Method::POST, "/enroll/replace")
        .header("origin", "http://admin.greendale.test")
        .header("cookie", refreshed_cookie)
        .form(&[
            ("instance_id", app.binding(24, "").instance.as_str()),
            ("csrf_token", csrf(&refreshed)),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::GONE);
    let (denied, reply) = app.dial(24, "", "", 24).await;
    closed(reply, "installation revoked");
    drop(denied);
    let (socket, reply) = app.dial(25, "", &second.enrollment_device_code, 25).await;
    assert_eq!(decode(reply).kind, "tunnel_registered");
    app.disconnect(socket).await;
    app.stop().await;
}

#[tokio::test]
async fn replacement_can_cancel_an_approved_setup_that_never_connected() {
    let mut app = Running::new(false, 1).await;
    let first = app.pending(24, "192.0.2.10");
    assert_eq!(app.approve(&first).await.status(), StatusCode::OK);
    let second = app.pending(25, "192.0.2.11");
    let chooser = app.approve(&second).await;
    let cookie = response_cookie(&chooser, "scimtest_enrollment_replacement");
    let html = chooser.text().await.unwrap();
    assert!(html.contains("Authorization approved; never connected"));
    assert!(html.contains(&format!(
        "name=\"instance_id\" value=\"{}\"",
        app.binding(24, "").instance
    )));
    let response = app
        .request(Method::POST, "/enroll/replace")
        .header("origin", "http://admin.greendale.test")
        .header("cookie", cookie)
        .form(&[
            ("instance_id", app.binding(24, "").instance.as_str()),
            ("csrf_token", csrf(&html)),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        app.poll(&first.enrollment_device_code).await.status(),
        StatusCode::NOT_FOUND
    );
    assert!(
        app.server
            .0
            .consume_grant(&first.enrollment_device_code, app.binding(24, ""))
            .is_err()
    );
    assert_eq!(
        app.poll(&second.enrollment_device_code)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"status":"approved"})
    );
    app.stop().await;
}

#[tokio::test]
async fn network_login_and_pending_limits_expire_and_repeated_bindings_replace_all_indices() {
    let mut app = Running::new(false, 5).await;
    let first = app.pending(24, "2001:db8:1234:5678::1");
    let second = app.pending(24, "2001:db8:1234:5678::2");
    assert_eq!(
        app.poll(&first.enrollment_device_code).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.poll(&second.enrollment_device_code).await.status(),
        StatusCode::OK
    );
    for seed in 25..34 {
        app.pending(seed, "2001:db8:1234:5678::3");
    }
    assert!(
        app.server
            .0
            .begin_enrollment(app.binding(34, ""), "2001:db8:1234:5678::4")
            .is_err()
    );
    assert!(
        app.server
            .0
            .begin_enrollment(app.binding(34, ""), "2001:db8:1234:5679::1")
            .is_ok()
    );
    for _ in 0..20 {
        assert_eq!(
            app.request(Method::GET, "/login/github")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FOUND
        );
    }
    assert_eq!(
        app.request(Method::GET, "/login/github")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    {
        let mut pending = lock(&app.server.0.enrollment);
        for item in pending.pending.values_mut() {
            item.expires_at = Utc::now() - Duration::seconds(1);
        }
        for item in pending.oauth.values_mut() {
            item.expires_at = Utc::now() - Duration::seconds(1);
        }
        pending.prune(Utc::now());
        assert!(pending.pending.is_empty());
        assert!(pending.oauth.is_empty());
    }
    assert_eq!(
        app.poll(&second.enrollment_device_code).await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        app.request(Method::GET, "/login/github")
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::FOUND
    );
    app.stop().await;
}

#[tokio::test]
async fn grants_are_atomic_under_concurrent_redemption_and_do_not_survive_server_restart() {
    let mut app = Running::new(false, 5).await;
    let approved = app.pending(24, "192.0.2.10");
    assert_eq!(app.approve(&approved).await.status(), StatusCode::OK);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let server = app.server.clone();
        let binding = app.binding(24, "");
        let grant = approved.enrollment_device_code.clone();
        tasks.spawn_blocking(move || server.0.consume_grant(&grant, binding).is_ok());
    }
    let mut succeeded = 0;
    while let Some(result) = tasks.join_next().await {
        succeeded += usize::from(result.unwrap());
    }
    assert_eq!(succeeded, 1);
    let waiting = app.pending(25, "192.0.2.11");
    assert_eq!(app.approve(&waiting).await.status(), StatusCode::OK);
    let config = app.server.0.config.clone();
    app.stop().await;
    let restarted = Server::new(config).unwrap();
    assert!(
        restarted
            .0
            .consume_grant(&waiting.enrollment_device_code, app.binding(25, ""))
            .is_err()
    );
    assert!(
        restarted
            .store()
            .instance(&app.profile, &app.binding(24, "").instance)
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn new_installation_enrolls_via_real_http_and_signed_socket_without_claiming_legacy_name() {
    let mut app = Running::new(false, 5).await;
    app.server
        .store()
        .remember_tunnel(
            &app.profile,
            "legacy-greendale",
            "human-timeline-club",
            false,
        )
        .unwrap();
    let (socket, reply) = app.dial(24, "legacy-greendale", "", 24).await;
    let required = decode(reply);
    assert_eq!(required.kind, "enrollment_required");
    assert!(
        !required
            .enrollment_url
            .contains(&required.enrollment_device_code)
    );
    drop(socket);
    assert_eq!(
        app.poll(&required.enrollment_device_code)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"status":"pending"})
    );
    let approved = app.approve(&required).await;
    assert_eq!(approved.status(), StatusCode::OK);
    assert!(
        !approved
            .headers()
            .get_all("set-cookie")
            .iter()
            .any(|value| value.to_str().unwrap().contains("scimtest_session="))
    );
    assert!(
        approved
            .text()
            .await
            .unwrap()
            .contains("Installation authorized")
    );
    assert_eq!(
        app.poll(&required.enrollment_device_code)
            .await
            .json::<Value>()
            .await
            .unwrap(),
        json!({"status":"approved"})
    );
    let (bad, reply) = app
        .dial(25, "legacy-greendale", &required.enrollment_device_code, 25)
        .await;
    closed(reply, "does not match");
    drop(bad);
    let (bad, reply) = app
        .dial(24, "different-legacy", &required.enrollment_device_code, 24)
        .await;
    closed(reply, "does not match");
    drop(bad);
    let (socket, reply) = app
        .dial(24, "legacy-greendale", &required.enrollment_device_code, 24)
        .await;
    let registered = decode(reply);
    assert_eq!(registered.kind, "tunnel_registered");
    assert_eq!(registered.github_user_id, 101);
    assert_eq!(registered.github_login, "troy-barnes");
    assert_ne!(registered.tunnel_id, "human-timeline-club");
    assert_eq!(
        app.poll(&required.enrollment_device_code).await.status(),
        StatusCode::NOT_FOUND
    );
    assert!(
        app.server
            .0
            .consume_grant(
                &required.enrollment_device_code,
                app.binding(24, "legacy-greendale")
            )
            .is_err()
    );
    app.disconnect(socket).await;
    let (socket, reply) = app.dial(24, "", "", 24).await;
    assert_eq!(decode(reply).public_url, registered.public_url);
    app.disconnect(socket).await;
    let stored = Store::open(app.directory.path().join("server.json")).unwrap();
    assert_eq!(
        stored.tunnel_id(&app.profile, "legacy-greendale").unwrap(),
        "human-timeline-club"
    );
    assert_eq!(
        stored
            .instance(&app.profile, &app.binding(24, "").instance)
            .unwrap()
            .unwrap()
            .github_user_id,
        101
    );
    let disk = std::fs::read_to_string(app.directory.path().join("server.json")).unwrap();
    for secret in [
        &required.enrollment_device_code,
        &required.enrollment_verification_code,
        "github-secret-stays-on-server",
    ] {
        assert!(!disk.contains(secret));
    }
    app.stop().await;
}

#[tokio::test]
async fn enrollment_requires_valid_signatures_and_grants_survive_failed_store_writes() {
    let mut app = Running::new(false, 5).await;
    let (socket, reply) = app.dial(24, "", "", 25).await;
    closed(reply, "invalid instance signature");
    drop(socket);
    assert!(lock(&app.server.0.enrollment).pending.is_empty());
    let required = app.pending(24, "192.0.2.10");
    assert_eq!(app.approve(&required).await.status(), StatusCode::OK);
    let (socket, reply) = app.dial(24, "", &required.enrollment_device_code, 25).await;
    closed(reply, "invalid instance signature");
    drop(socket);
    assert_eq!(
        app.poll(&required.enrollment_device_code).await.status(),
        StatusCode::OK
    );
    let path = app.directory.path().join("server.json");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(
        app.server
            .0
            .consume_grant(&required.enrollment_device_code, app.binding(24, ""))
            .is_err()
    );
    assert!(
        app.server
            .store()
            .instance(&app.profile, &app.binding(24, "").instance)
            .unwrap()
            .is_none()
    );
    assert!(
        lock(&app.server.0.enrollment)
            .pending
            .contains_key(&hash(&required.enrollment_device_code))
    );
    std::fs::remove_dir(&path).unwrap();
    std::fs::write(&path, bytes).unwrap();
    let (socket, reply) = app.dial(24, "", &required.enrollment_device_code, 24).await;
    assert_eq!(decode(reply).kind, "tunnel_registered");
    app.disconnect(socket).await;
    app.stop().await;
}

#[tokio::test]
async fn confirmation_requires_code_cookie_origin_and_bounded_form_and_handoff_is_single_use() {
    let mut app = Running::new(true, 5).await;
    let required = app.pending(24, "192.0.2.10");
    let path = format!("/enroll?code={}", required.enrollment_verification_code);
    let page = app.request(Method::GET, &path).send().await.unwrap();
    let confirm = response_cookie(&page, "__Host-scimtest_enroll_confirm");
    let html = page.text().await.unwrap();
    assert!(html.contains(&required.enrollment_verification_code));
    assert!(!html.contains(&required.enrollment_device_code));
    let token = csrf(&html);
    for (origin, cookie_value, token_value, want) in [
        (
            "https://evil.greendale.test",
            confirm.as_str(),
            token,
            StatusCode::FORBIDDEN,
        ),
        (
            "https://admin.greendale.test",
            "",
            token,
            StatusCode::BAD_REQUEST,
        ),
        (
            "https://admin.greendale.test",
            confirm.as_str(),
            "wrong",
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = app
            .request(Method::POST, "/enroll")
            .header("origin", origin)
            .header("cookie", cookie_value)
            .form(&[
                ("code", required.enrollment_verification_code.as_str()),
                ("csrf_token", token_value),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), want);
    }
    let oversized = app
        .request(Method::POST, "/enroll")
        .header("origin", "https://admin.greendale.test")
        .header("cookie", &confirm)
        .form(&[
            ("code", required.enrollment_verification_code.clone()),
            ("csrf_token", token.into()),
            ("extra", "x".repeat(5000)),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
    let start = app
        .request(Method::POST, "/enroll")
        .header("origin", "https://admin.greendale.test")
        .header("cookie", confirm)
        .form(&[
            ("code", required.enrollment_verification_code.as_str()),
            ("csrf_token", token),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(app.oauth(start, "paintball").await.status(), StatusCode::OK);
    let other = app.pending(25, "192.0.2.11");
    let handoff = Url::parse(&other.enrollment_browser_handoff_url).unwrap();
    let handoff_path = format!("{}?{}", handoff.path(), handoff.query().unwrap());
    let first = app
        .request(Method::GET, &handoff_path)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::FOUND);
    assert_eq!(first.headers()["referrer-policy"], "no-referrer");
    assert_eq!(
        app.request(Method::GET, &handoff_path)
            .send()
            .await
            .unwrap()
            .status(),
        StatusCode::GONE
    );
    app.stop().await;
}
