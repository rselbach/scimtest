use super::*;

#[tokio::test]
async fn shared_replacement_owns_only_its_account_and_revokes_the_selected_live_installation() {
    let fixture = support::GoFixture::new();
    for backend in ["Go", "Rust"] {
        println!("Hosted shared replacement workflow: {backend}");
        let mut app = Running::new(false, 1).await;
        let mut go = if backend == "Go" {
            Some(GoService::start(&mut app, &fixture).await)
        } else {
            None
        };
        let (first_socket, reply) = app.dial(24, "", "", 24).await;
        let first = decode(reply);
        drop(first_socket);
        assert_eq!(app.approve(&first).await.status(), StatusCode::OK);
        let (first_socket, reply) = app.dial(24, "", &first.enrollment_device_code, 24).await;
        let first_registered = decode(reply);
        assert_eq!(first_registered.kind, "tunnel_registered");
        *lock(&app.stub.user) = GitHubUser {
            id: 202,
            login: "abed-nadir".into(),
        };
        let (foreign, reply) = app.dial(26, "", "", 26).await;
        let foreign_required = decode(reply);
        drop(foreign);
        assert_eq!(
            app.approve(&foreign_required).await.status(),
            StatusCode::OK
        );
        let (mut foreign, reply) = app
            .dial(26, "", &foreign_required.enrollment_device_code, 26)
            .await;
        assert_eq!(decode(reply).kind, "tunnel_registered");
        foreign.close(None).await.unwrap();
        tunnels(&app, 1).await;
        *lock(&app.stub.user) = GitHubUser {
            id: 101,
            login: "troy-barnes".into(),
        };
        let (second, reply) = app.dial(25, "", "", 25).await;
        let second_required = decode(reply);
        drop(second);
        let chooser = app.approve(&second_required).await;
        assert_eq!(chooser.status(), StatusCode::OK);
        let cookie = response_cookie(&chooser, "scimtest_enrollment_replacement");
        let html = chooser.text().await.unwrap();
        assert!(html.contains("Disconnect and continue"));
        assert!(html.contains(&app.binding(24, "").instance));
        assert!(!html.contains(&app.binding(26, "").instance));
        let forbidden = app
            .request(Method::POST, "/enroll/replace")
            .header("origin", "http://admin.greendale.test")
            .header("cookie", &cookie)
            .form(&[
                ("csrf_token", csrf(&html)),
                ("instance_id", app.binding(26, "").instance.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(forbidden.status(), StatusCode::OK);
        let cookie = response_cookie(&forbidden, "scimtest_enrollment_replacement");
        let html = forbidden.text().await.unwrap();
        assert!(html.contains("no longer available"));
        assert!(
            !saved(&app)
                .instance(&app.profile, &app.binding(26, "").instance)
                .unwrap()
                .unwrap()
                .revoked
        );
        let response = app
            .request(Method::POST, "/enroll/replace")
            .header("origin", "http://admin.greendale.test")
            .header("cookie", &cookie)
            .form(&[
                ("csrf_token", csrf(&html)),
                ("instance_id", app.binding(24, "").instance.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut first_socket = first_socket;
        let socket_result = tokio::time::timeout(StdDuration::from_secs(5), first_socket.next())
            .await
            .unwrap();
        assert!(
            matches!(
                socket_result,
                None | Some(Ok(tungstenite::Message::Close(_)))
                    | Some(Err(tungstenite::Error::Protocol(
                        tungstenite::error::ProtocolError::ResetWithoutClosingHandshake
                    )))
            ),
            "{socket_result:?}"
        );
        drop(first_socket);
        tunnels(&app, 0).await;
        let denied = saved(&app)
            .instance(&app.profile, &app.binding(24, "").instance)
            .unwrap()
            .unwrap();
        assert!(denied.revoked);
        assert_eq!(denied.tunnel_id, first_registered.tunnel_id);
        let (denied, reply) = app.dial(24, "", "", 24).await;
        closed(reply, "installation revoked");
        drop(denied);
        assert_eq!(
            app.poll(&second_required.enrollment_device_code)
                .await
                .json::<Value>()
                .await
                .unwrap(),
            json!({"status":"approved"})
        );
        let (second, reply) = app
            .dial(25, "", &second_required.enrollment_device_code, 25)
            .await;
        let second_registered = decode(reply);
        assert_eq!(second_registered.kind, "tunnel_registered");
        assert_ne!(second_registered.tunnel_id, first_registered.tunnel_id);
        app.disconnect(second).await;
        tunnels(&app, 0).await;
        finish(&mut app, go.as_mut()).await;
    }
}

#[tokio::test]
async fn shared_replacement_cancels_an_approved_unconnected_setup_without_creating_a_tunnel() {
    let fixture = support::GoFixture::new();
    for backend in ["Go", "Rust"] {
        println!("Hosted shared pending-setup workflow: {backend}");
        let mut app = Running::new(false, 1).await;
        let mut go = if backend == "Go" {
            Some(GoService::start(&mut app, &fixture).await)
        } else {
            None
        };
        let (socket, reply) = app.dial(24, "", "", 24).await;
        let first = decode(reply);
        drop(socket);
        assert_eq!(app.approve(&first).await.status(), StatusCode::OK);
        let (socket, reply) = app.dial(25, "", "", 25).await;
        let second = decode(reply);
        drop(socket);
        let chooser = app.approve(&second).await;
        let cookie = response_cookie(&chooser, "scimtest_enrollment_replacement");
        let html = chooser.text().await.unwrap();
        assert!(html.contains("Authorization approved; never connected"));
        assert!(html.contains(&app.binding(24, "").instance));
        let response = app
            .request(Method::POST, "/enroll/replace")
            .header("origin", "http://admin.greendale.test")
            .header("cookie", &cookie)
            .form(&[
                ("csrf_token", csrf(&html)),
                ("instance_id", app.binding(24, "").instance.as_str()),
            ])
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            app.poll(&first.enrollment_device_code).await.status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.poll(&second.enrollment_device_code)
                .await
                .json::<Value>()
                .await
                .unwrap(),
            json!({"status":"approved"})
        );
        assert!(
            saved(&app)
                .instance(&app.profile, &app.binding(24, "").instance)
                .unwrap()
                .is_none()
        );
        assert!(
            saved(&app)
                .instance(&app.profile, &app.binding(25, "").instance)
                .unwrap()
                .is_none()
        );
        tunnels(&app, 0).await;
        finish(&mut app, go.as_mut()).await;
    }
}
