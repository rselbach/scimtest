use super::*;

#[tokio::test]
async fn public_host_root_redirects_to_the_download_page() {
    let app = Running::new(false, 5).await;
    let public = |path: &str| {
        app.client
            .get(format!("{}{path}", app.base))
            .header("host", "public.greendale.test")
            .send()
    };
    let page = public("/").await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()["content-type"], "text/html; charset=utf-8");
    assert!(
        page.text()
            .await
            .unwrap()
            .contains(r#"content="0; url=https://rselbach.com/scimtest/""#)
    );
    for path in ["/site.js", "/screenshot.webp", "/icon.png"] {
        assert_eq!(
            public(path).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

#[tokio::test]
async fn dashboard_controls_profiles_reservations_revocation_disconnect_and_logout() {
    let mut app = Running::new(false, 5).await;
    let session = app.server.store().create_session("rselbach", true).unwrap();
    let cookie = format!("scimtest_session={}", session.id);
    for path in ["/dashboard", "/dashboard/tunnels", "/dashboard/app.js"] {
        assert_eq!(
            app.request(Method::GET, path)
                .send()
                .await
                .unwrap()
                .headers()["location"],
            "/login/github"
        );
        assert_eq!(
            app.client
                .get(format!("{}{path}", app.base))
                .header("host", "public.greendale.test")
                .header("cookie", &cookie)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.request(Method::GET, path)
                .header("cookie", &cookie)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    let values = [
        ("name", "<script>Troy & Abed</script>"),
        ("public_key", &support::public_key(41)),
        ("routes", "GET /oidc/{slug}/jwks"),
        ("requests_per_minute", "60"),
        ("request_burst", "10"),
        ("concurrent_requests", "4"),
    ];
    let missing_csrf = app
        .request(Method::POST, "/dashboard/applications/create")
        .header("cookie", &cookie)
        .form(&values)
        .send()
        .await
        .unwrap();
    assert_eq!(missing_csrf.status(), StatusCode::FORBIDDEN);
    assert_eq!(app.server.store().profiles().unwrap().len(), 1);
    let mut create = values.to_vec();
    create.push(("csrf_token", &session.csrf_token));
    let response = app
        .request(Method::POST, "/dashboard/applications/create")
        .header("cookie", &cookie)
        .form(&create)
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["location"], "/dashboard#applications");
    let profiles = app.server.store().profiles().unwrap();
    let created = profiles
        .iter()
        .find(|profile| profile.id != app.profile)
        .unwrap();
    let page = app
        .request(Method::GET, "/dashboard")
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!page.contains("<script>Troy & Abed</script>"));
    assert!(
        page.contains("&lt;script&gt;Troy &amp; Abed&lt;&#x2f;script&gt;")
            || page.contains("&lt;script&gt;Troy &amp; Abed&lt;/script&gt;"),
        "{page}"
    );
    for path in [
        "/logout",
        "/dashboard/applications/create",
        "/dashboard/applications/update",
        "/dashboard/applications/delete",
        "/dashboard/applications/reservations/delete",
        "/dashboard/applications/instances/revoke",
        "/dashboard/tunnels/disconnect",
    ] {
        let response = app
            .request(Method::GET, path)
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(response.headers()["allow"], "POST");
    }
    let required = app.pending(24, "192.0.2.10");
    assert_eq!(app.approve(&required).await.status(), StatusCode::OK);
    let (socket, reply) = app.dial(24, "", &required.enrollment_device_code, 24).await;
    let registration = decode(reply);
    let partial = app
        .request(Method::GET, "/dashboard/tunnels")
        .header("cookie", &cookie)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(partial.contains("Greendale Community College"));
    assert!(
        partial
            .replace("&#x2f;", "/")
            .contains(&registration.public_url)
    );
    assert!(partial.contains("4321"));
    let response = app
        .request(Method::POST, "/dashboard/applications/instances/revoke")
        .header("cookie", &cookie)
        .form(&[
            ("csrf_token", session.csrf_token.as_str()),
            ("profile_id", &app.profile),
            ("instance_id", &app.binding(24, "").instance),
            ("revoked", "true"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    app.server_closed(socket).await;
    let (denied, reply) = app.dial(24, "", "", 24).await;
    closed(reply, "installation revoked");
    drop(denied);
    for (path, fields) in [
        (
            "/dashboard/applications/instances/revoke",
            vec![
                ("profile_id", app.profile.clone()),
                ("instance_id", app.binding(24, "").instance.clone()),
                ("revoked", "false".into()),
            ],
        ),
        (
            "/dashboard/applications/reservations/delete",
            vec![
                ("profile_id", app.profile.clone()),
                ("instance_id", app.binding(24, "").instance.clone()),
            ],
        ),
        (
            "/dashboard/applications/delete",
            vec![("id", created.id.clone())],
        ),
    ] {
        let mut values = fields;
        values.push(("csrf_token", session.csrf_token.clone()));
        assert_eq!(
            app.request(Method::POST, path)
                .header("cookie", &cookie)
                .form(&values)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::FOUND
        );
    }
    assert!(
        app.server
            .store()
            .tunnel_id(&app.profile, &app.binding(24, "").instance)
            .unwrap()
            .is_empty()
    );
    assert!(
        !app.server
            .store()
            .instance(&app.profile, &app.binding(24, "").instance)
            .unwrap()
            .unwrap()
            .revoked
    );
    assert!(app.server.store().profile(&created.id).unwrap().is_none());
    let logout = app
        .request(Method::POST, "/logout")
        .header("cookie", &cookie)
        .form(&[("csrf_token", &session.csrf_token)])
        .send()
        .await
        .unwrap();
    assert_eq!(logout.headers()["location"], "/");
    assert!(
        logout.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        app.request(Method::GET, "/dashboard")
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap()
            .headers()["location"],
        "/login/github"
    );
    app.stop().await;
}

#[tokio::test]
async fn profile_updates_and_dashboard_disconnect_close_live_tunnels_and_keep_reservations() {
    let mut app = Running::new(false, 5).await;
    let session = app.server.store().create_session("rselbach", true).unwrap();
    let cookie = format!("scimtest_session={}", session.id);
    let required = app.pending(24, "192.0.2.10");
    assert_eq!(app.approve(&required).await.status(), StatusCode::OK);
    app.server
        .0
        .consume_grant(&required.enrollment_device_code, app.binding(24, ""))
        .unwrap();
    for update in [true, false] {
        let (socket, reply) = app.dial(24, "", "", 24).await;
        let registration = decode(reply);
        let response = if update {
            app.request(Method::POST, "/dashboard/applications/update")
                .header("cookie", &cookie)
                .form(&[
                    ("id", app.profile.as_str()),
                    ("csrf_token", &session.csrf_token),
                    ("name", "Greendale Study Group"),
                    ("public_key", &support::public_key(42)),
                    ("routes", "GET /oidc/{slug}/jwks"),
                    ("requests_per_minute", "90"),
                    ("request_burst", "20"),
                    ("concurrent_requests", "3"),
                ])
                .send()
                .await
                .unwrap()
        } else {
            app.request(Method::POST, "/dashboard/tunnels/disconnect")
                .header("cookie", &cookie)
                .form(&[
                    ("id", registration.tunnel_id.as_str()),
                    ("csrf_token", &session.csrf_token),
                ])
                .send()
                .await
                .unwrap()
        };
        assert_eq!(response.status(), StatusCode::FOUND);
        app.server_closed(socket).await;
        assert_eq!(
            app.server
                .store()
                .tunnel_id(&app.profile, &app.binding(24, "").instance)
                .unwrap(),
            registration.tunnel_id
        );
    }
    assert_eq!(
        app.server
            .store()
            .profile(&app.profile)
            .unwrap()
            .unwrap()
            .settings
            .name,
        "Greendale Study Group"
    );
    app.stop().await;
}

#[tokio::test]
async fn invalid_or_expired_sessions_are_cleared_and_configuration_disables_github() {
    let directory = tempfile::tempdir().unwrap();
    let server = Server::new(Config {
        data_path: directory.path().join("server.json"),
        ..Config::default()
    })
    .unwrap();
    let request = Request::builder()
        .uri("/login/github")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        server
            .0
            .begin_oauth(&request, "127.0.0.1:7000".parse().unwrap(), None)
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        server
            .0
            .begin_enrollment(
                Binding {
                    profile: "x".into(),
                    instance: "troy".into(),
                    key: "x".into(),
                    legacy: String::new()
                },
                "192.0.2.10"
            )
            .is_err()
    );
    let mut app = Running::new(true, 5).await;
    let response = app
        .request(Method::GET, "/dashboard")
        .header("cookie", "__Host-scimtest_session=expired")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    assert!(
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    app.stop().await;
}
