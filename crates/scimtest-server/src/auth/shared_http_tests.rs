use super::*;

#[tokio::test]
async fn shared_full_router_http_errors_methods_forms_and_privacy_headers() {
    let fixture = support::GoFixture::new();
    let mut observations = Vec::new();
    for backend in ["Go", "Rust"] {
        let mut app = Running::new(false, 5).await;
        let session = app.server.store().create_session("rselbach", true).unwrap();
        let mut go = if backend == "Go" {
            Some(GoService::start(&mut app, &fixture).await)
        } else {
            None
        };
        let mut cases = Vec::new();
        for host in [
            "admin.greendale.test",
            "public.greendale.test",
            "citycollege.test",
            "127.0.0.1:7000",
        ] {
            for (method, path) in [
                ("GET", "/"),
                ("GET", "/healthz"),
                ("POST", "/ready"),
                ("GET", "/dashboard"),
                ("GET", "/dashboard/app.js"),
                ("GET", "/dashboard/tunnels"),
                ("GET", "/api/enroll/status"),
                ("POST", "/api/enroll/status"),
                ("GET", "/enroll"),
                ("GET", "/enroll/browser?handoff=invalid"),
                ("POST", "/enroll/browser"),
                ("GET", "/enroll/replace"),
                ("POST", "/enroll/replace"),
                ("GET", "/logout"),
                ("POST", "/logout"),
                ("GET", "/auth/github/callback"),
                ("GET", "/unknown-greendale-route"),
            ] {
                cases.push((
                    format!("{host} {method} {path}"),
                    method,
                    host,
                    path,
                    false,
                    String::new(),
                    String::new(),
                ));
            }
        }
        let form = serde_urlencoded::to_string([
            ("csrf_token", session.csrf_token.as_str()),
            ("name", "Greendale"),
            ("public_key", &support::public_key(41)),
            ("routes", "GET /oidc/{slug}/jwks"),
            ("requests_per_minute", "not-a-number"),
            ("request_burst", "10"),
            ("concurrent_requests", "4"),
        ])
        .unwrap();
        for (name, content_type, body) in [
            (
                "invalid-limit",
                "application/x-www-form-urlencoded",
                form.clone(),
            ),
            (
                "mixed-case-type",
                "Application/X-WWW-Form-Urlencoded; charset=UTF-8",
                form.clone(),
            ),
            (
                "invalid-escape",
                "application/x-www-form-urlencoded",
                format!("{}&extra=%zz", form.replace("not-a-number", "60")),
            ),
            (
                "incomplete-escape",
                "application/x-www-form-urlencoded",
                format!("{}&extra=%", form.replace("not-a-number", "60")),
            ),
            (
                "semicolon",
                "application/x-www-form-urlencoded",
                format!("{}&extra=troy;abed", form.replace("not-a-number", "60")),
            ),
            (
                "encoded-semicolon",
                "application/x-www-form-urlencoded",
                format!("{form}&extra=troy%3Babed"),
            ),
            ("not-a-form", "application/json", "{}".into()),
        ] {
            cases.push((
                name.into(),
                "POST",
                "admin.greendale.test",
                "/dashboard/applications/create",
                true,
                content_type.into(),
                body,
            ));
        }
        let mut values = BTreeMap::new();
        for (name, method, host, path, authenticated, content_type, body) in cases {
            let mut request = app
                .client
                .request(
                    Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("{}{path}", app.base),
                )
                .header("host", host);
            if authenticated {
                request = request.header("cookie", format!("scimtest_session={}", session.id));
            }
            if !content_type.is_empty() {
                request = request.header("content-type", content_type);
            }
            let response = request.body(body).send().await.unwrap();
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.text().await.unwrap();
            let mut observed = json!({"status":status.as_u16(),"headers":{}});
            for key in [
                "location",
                "allow",
                "www-authenticate",
                "cache-control",
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
                "strict-transport-security",
            ] {
                observed["headers"][key] = json!(header(&headers, key));
            }
            if !status.is_redirection() {
                observed["headers"]["content-type"] = json!(header(&headers, "content-type"));
                observed["body"] = json!(body);
            }
            values.insert(name, observed);
        }
        assert_eq!(
            saved(&app).profiles().unwrap().len(),
            1,
            "malformed forms must not create a profile on {backend}"
        );
        observations.push(values);
        finish(&mut app, go.as_mut()).await;
    }
    let differences = observations[0]
        .iter()
        .filter_map(|(name, want)| {
            let got = &observations[1][name];
            (got != want).then(|| json!({"request":name,"Go":want,"Rust":got}))
        })
        .collect::<Vec<_>>();
    assert!(
        differences.is_empty(),
        "{}",
        serde_json::to_string_pretty(&differences).unwrap()
    );
    println!(
        "Compared {} complete-router HTTP cases between Go and Rust",
        observations[0].len()
    );
}
