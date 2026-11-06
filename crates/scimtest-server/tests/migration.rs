mod support;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, StatusCode};
use scimtest_core::{
    Store as DesktopStore,
    configuration::SettingsPatch,
    model::{EnvironmentInput, UserInput},
    runtime::{Options, Runtime},
    tunnel::{Config as TunnelConfig, Service},
};
use scimtest_protocol::{Message, instance_challenge_payload};
use scimtest_server::{application::parse_instance_key, store::Store};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use support::{GoFixture, public_key};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct FailureLogs(PathBuf);

struct ClientFailure(Service);

impl Drop for ClientFailure {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("Rust client migration state: {:?}", self.0.account());
        }
    }
}

impl Drop for FailureLogs {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            return;
        }
        for path in std::fs::read_dir(&self.0)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|value| value == "log"))
        {
            eprintln!(
                "Migration diagnostic {}:\n{}",
                path.file_name().unwrap().to_string_lossy(),
                std::fs::read_to_string(&path).unwrap()
            );
        }
    }
}

struct Process {
    child: Child,
    log: PathBuf,
}

impl Process {
    fn start(mut command: Command, log: PathBuf) -> Self {
        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::from(std::fs::File::create(&log).unwrap()))
            .spawn()
            .unwrap();
        Self { child, log }
    }

    fn assert_running(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "{}",
            std::fs::read_to_string(&self.log).unwrap()
        );
    }

    async fn wait(&mut self, success: bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Some(status) = self.child.try_wait().unwrap() {
                    assert_eq!(
                        status.success(),
                        success,
                        "{}",
                        std::fs::read_to_string(&self.log).unwrap()
                    );
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn stop(&mut self) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
        self.wait(true).await;
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
            self.child.wait().unwrap();
        }
    }
}

async fn eventually(label: &str, mut condition: impl AsyncFnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(12), async {
        loop {
            if condition().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{label} did not become ready"));
}

fn command(binary: &Path, address: &str, state: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .args([
            "--addr",
            address,
            "--domain",
            address,
            "--dashboard-domain",
            "admin.greendale.test",
            "--data",
        ])
        .arg(state)
        .args([
            "--github-client-id",
            "greendale-client",
            "--github-client-secret",
            "greendale-secret",
            "--logs",
            "--log-format",
            "json",
        ])
        .env_remove("SCIMTEST_GITHUB_CLIENT_ID")
        .env_remove("SCIMTEST_GITHUB_CLIENT_SECRET");
    command
}

async fn ready(server: &mut Process, client: &Client, base: &str) {
    eventually("hosted server readiness", async || {
        server.assert_running();
        client
            .get(format!("{base}/ready"))
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::OK)
    })
    .await;
}

async fn exchange(base: &str, profile: &str, seed: u8) -> (Socket, tungstenite::Message) {
    let (mut socket, _) = connect_async(base.replacen("http", "ws", 1) + "/api/connect")
        .await
        .unwrap();
    let key = SigningKey::from_bytes(&[seed; 32]);
    let public = STANDARD.encode(key.verifying_key().as_bytes());
    socket
        .send(tungstenite::Message::text(
            serde_json::to_string(&Message {
                kind: "register_tunnel".into(),
                application_profile_id: profile.into(),
                instance_public_key: public.clone(),
                local_port: 4321,
                ..Default::default()
            })
            .unwrap(),
        ))
        .await
        .unwrap();
    let challenge = receive(&mut socket).await;
    let challenge: Message = serde_json::from_slice(&challenge.into_data()).unwrap();
    assert_eq!(challenge.kind, "application_challenge");
    let signature = key.sign(&instance_challenge_payload(
        profile,
        &public,
        "",
        &challenge.challenge,
    ));
    socket
        .send(tungstenite::Message::text(
            serde_json::to_string(&Message {
                kind: "application_signature".into(),
                signature: signature.to_bytes().into(),
                ..Default::default()
            })
            .unwrap(),
        ))
        .await
        .unwrap();
    let result = receive(&mut socket).await;
    (socket, result)
}

async fn receive(socket: &mut Socket) -> tungstenite::Message {
    tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

async fn identities(client: &Client, public: &str, user: &str, secret: &str) -> Value {
    eventually("OIDC JWKS through the current Rust client", async || {
        client
            .get(format!("{public}/oidc/greendale/jwks"))
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::OK)
    })
    .await;
    let discovery = client
        .get(format!(
            "{public}/oidc/greendale/.well-known/openid-configuration"
        ))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(discovery["issuer"], format!("{public}/oidc/greendale"));
    let jwks = client
        .get(format!("{public}/oidc/greendale/jwks"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let saml = client
        .get(format!("{public}/saml/greendale/metadata"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(saml.contains(&format!("{public}/saml/greendale/sso")));
    let authorization = client
        .post(format!("{public}/oidc/greendale/authorize"))
        .form(&[
            ("client_id", "study-group"),
            ("response_type", "code"),
            ("redirect_uri", "https://greendale.example/callback"),
            ("scope", "openid profile email"),
            ("user_id", user),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(authorization.status(), StatusCode::FOUND);
    let url = url::Url::parse(authorization.headers()["location"].to_str().unwrap()).unwrap();
    let code = url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .unwrap()
        .1
        .into_owned();
    let token = client
        .post(format!("{public}/oidc/greendale/token"))
        .basic_auth("study-group", Some(secret))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", "https://greendale.example/callback"),
        ])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert!(token["id_token"].as_str().unwrap().split('.').count() == 3);
    let userinfo = client
        .get(format!("{public}/oidc/greendale/userinfo"))
        .bearer_auth(token["access_token"].as_str().unwrap())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    assert_eq!(userinfo["email"], "troy@greendale.edu");
    jwks
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_go_rust_migration_and_rollback_preserve_both_clients_sessions_revocations_and_identity()
 {
    let directory = tempfile::tempdir().unwrap();
    let _failure_logs = FailureLogs(directory.path().into());
    let go = GoFixture::new();
    let binary = directory.path().join("go-scimtest-server");
    let output = Command::new("go")
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .args(["build", "-mod=readonly", "-o"])
        .arg(&binary)
        .arg("./cmd/scimtest-server")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let desktop = directory.path().join("desktop.db");
    let desktop_store = DesktopStore::open(&desktop).unwrap();
    let installation = desktop_store.installation_identity().unwrap();
    let environment = desktop_store
        .create_environment(EnvironmentInput {
            name: "Greendale".into(),
            settings: SettingsPatch {
                oidc_enabled: Some(true),
                oidc_client_id: Some("study-group".into()),
                oidc_redirect_uris: Some(vec!["https://greendale.example/callback".into()]),
                saml_enabled: Some(true),
                saml_entity_id: Some("urn:greendale:sp".into()),
                saml_acs_url: Some("https://greendale.example/acs".into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();
    let user = desktop_store
        .create_user(
            &environment.id,
            UserInput {
                given_name: "Troy".into(),
                family_name: "Barnes".into(),
                email: "troy@greendale.edu".into(),
                active: true,
                ..Default::default()
            },
        )
        .unwrap();
    drop(desktop_store);
    let state = directory.path().join("server.json");
    let seed=go.run(json!({"kind":"seed","path":state,"settings":{"name":"Greendale Community College","public_key":public_key(42),"routes":[
        {"methods":["GET","POST"],"path":"/oidc/{slug}/.well-known/openid-configuration"},{"methods":["GET"],"path":"/oidc/{slug}/jwks"},
        {"methods":["GET","POST"],"path":"/oidc/{slug}/authorize"},{"methods":["POST"],"path":"/oidc/{slug}/token"},{"methods":["GET"],"path":"/oidc/{slug}/userinfo"},
        {"methods":["GET"],"path":"/saml/{slug}/metadata"}
    ],"requests_per_minute":6000,"request_burst":1000,"concurrent_requests":32}}));
    let profile = seed["profile"]["id"].as_str().unwrap();
    let session = seed["session"]["id"].as_str().unwrap();
    let csrf = seed["session"]["csrf_token"].as_str().unwrap();
    let revoked_key = STANDARD.encode(SigningKey::from_bytes(&[33; 32]).verifying_key().as_bytes());
    let revoked_id = parse_instance_key(&revoked_key).unwrap().1;
    let initialized=go.run(json!({"kind":"store","path":state,"profile_id":profile,"actions":[
        {"kind":"enroll","instance_id":installation.fingerprint(),"public_key":installation.public_key(),"user_id":101,"login":"troy-barnes"},
        {"kind":"remember","instance_id":installation.fingerprint(),"tunnel_id":"greendale-study-group","existing":true},
        {"kind":"remember","instance_id":"legacy-greendale","tunnel_id":"human-timeline-club"},
        {"kind":"enroll","instance_id":revoked_id,"public_key":revoked_key,"user_id":303,"login":"shirley-bennett"},
        {"kind":"remember","instance_id":revoked_id,"tunnel_id":"city-college-deactivated","existing":true},
        {"kind":"set_revoked","instance_id":revoked_id,"revoked":true}
    ]}));
    for result in initialized["results"].as_array().unwrap() {
        assert_eq!(result["error"], "");
    }
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap().to_string();
    drop(reservation);
    let base = format!("http://{address}");
    let public = format!("{base}/greendale-study-group");
    let legacy = format!("{base}/human-timeline-club");
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let rust_binary = Path::new(env!("CARGO_BIN_EXE_scimtest-server"));
    let mut server = Process::start(
        command(&binary, &address, &state),
        directory.path().join("go-initial.log"),
    );
    ready(&mut server, &client, &base).await;
    let local_reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let local_port = local_reservation.local_addr().unwrap().port();
    drop(local_reservation);
    let runtime = Runtime::start_with_profile(
        Options {
            state_file: Some(desktop.clone()),
            port: local_port,
            ..Default::default()
        },
        &tokio::runtime::Handle::current(),
        Some(TunnelConfig {
            server_base_url: base.clone(),
            application_profile_id: profile.into(),
            require_account: true,
        }),
    )
    .unwrap();
    let _client_failure = ClientFailure(runtime.tunnel.clone());
    let request = directory.path().join("go-client-request.json");
    let result = directory.path().join("go-client-result.json");
    let client_ready = directory.path().join("client-ready.json");
    let client_stop = directory.path().join("client-stop");
    std::fs::write(&request,serde_json::to_vec(&json!({"kind":"client","client":{"server_url":base.replacen("http","ws",1)+"/api/connect","profile_id":profile,"legacy":true,"ready_path":client_ready,"stop_path":client_stop,"timeout_seconds":90}})).unwrap()).unwrap();
    let mut go_command = Command::new(&go.binary);
    go_command
        .arg("-test.run=^TestRustHostedContractFixture$")
        .env("SCIMTEST_RUST_HOSTED_CONTRACT", request)
        .env("SCIMTEST_RUST_HOSTED_RESULT", &result);
    let mut go_client = Process::start(go_command, directory.path().join("go-client.log"));
    let first_keys = identities(
        &client,
        &public,
        &user.id,
        &environment.settings.oidc_client_secret,
    )
    .await;
    eventually("initial Go legacy client forwarding", async || {
        go_client.assert_running();
        client
            .get(format!("{legacy}/oidc/greendale/jwks"))
            .send()
            .await
            .is_ok_and(|response| response.status() == StatusCode::OK)
    })
    .await;
    let bad_state = directory.path().join("invalid-candidate.json");
    std::fs::write(&bad_state, "{bad Greendale JSON").unwrap();
    let original = std::fs::read(&state).unwrap();
    let mut bad = Process::start(
        command(rust_binary, "127.0.0.1:0", &bad_state),
        directory.path().join("failed-preflight.log"),
    );
    bad.wait(false).await;
    assert_eq!(std::fs::read(&bad_state).unwrap(), b"{bad Greendale JSON");
    assert_eq!(std::fs::read(&state).unwrap(), original);
    server.assert_running();
    go_client.assert_running();
    println!("Migration: failed Rust preflight preserves the live Go service and both state files");
    let mut created = String::new();
    let mut pending = String::new();
    for (phase, implementation) in [
        ("rust-upgrade", rust_binary),
        ("go-rollback", binary.as_path()),
        ("rust-reupgrade", rust_binary),
    ] {
        server.stop().await;
        assert!(std::net::TcpStream::connect(&address).is_err());
        if phase == "rust-upgrade" {
            std::fs::copy(&state, directory.path().join("go-before-upgrade.json")).unwrap();
        }
        server = Process::start(
            command(implementation, &address, &state),
            directory.path().join(format!("{phase}.log")),
        );
        ready(&mut server, &client, &base).await;
        println!("Migration phase {phase}: waiting for native identity forwarding");
        assert_eq!(
            identities(
                &client,
                &public,
                &user.id,
                &environment.settings.oidc_client_secret
            )
            .await,
            first_keys
        );
        println!("Migration phase {phase}: waiting for Go legacy forwarding");
        eventually("reconnected Go legacy client forwarding", async || {
            go_client.assert_running();
            client
                .get(format!("{legacy}/oidc/greendale/jwks"))
                .send()
                .await
                .is_ok_and(|response| response.status() == StatusCode::OK)
        })
        .await;
        let native = runtime.tunnel.snapshot().unwrap();
        assert!(native.connected);
        assert_eq!(native.public_url.as_deref(), Some(public.as_str()));
        assert_eq!(native.github_login, "troy-barnes");
        let forwarded = client
            .get(format!("{legacy}/oidc/greendale/jwks"))
            .send()
            .await
            .unwrap();
        assert_eq!(forwarded.headers()["x-greendale-client"], "Go");
        let dashboard = client
            .get(format!("{base}/dashboard"))
            .header("host", "admin.greendale.test")
            .header("cookie", format!("scimtest_session={session}"))
            .send()
            .await
            .unwrap();
        assert_eq!(dashboard.status(), StatusCode::OK);
        let (denied, reply) = exchange(&base, profile, 33).await;
        drop(denied);
        match reply {
            tungstenite::Message::Close(Some(close)) => {
                assert_eq!(u16::from(close.code), 1008);
                assert!(close.reason.contains("installation revoked"));
            }
            other => panic!("revoked installation accepted: {other:?}"),
        }
        if phase == "rust-upgrade" {
            let response = client
                .post(format!("{base}/dashboard/applications/create"))
                .header("host", "admin.greendale.test")
                .header("cookie", format!("scimtest_session={session}"))
                .form(&[
                    ("csrf_token", csrf),
                    ("name", "Greendale After Migration"),
                    ("public_key", &public_key(41)),
                    ("routes", "GET /oidc/{slug}/jwks"),
                    ("requests_per_minute", "60"),
                    ("request_burst", "10"),
                    ("concurrent_requests", "4"),
                ])
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FOUND);
            created = Store::open(&state)
                .unwrap()
                .profiles()
                .unwrap()
                .into_iter()
                .find(|profile| profile.settings.name == "Greendale After Migration")
                .unwrap()
                .id;
            assert_eq!(
                client
                    .post(format!("{base}/dashboard/applications/reservations/delete"))
                    .header("host", "admin.greendale.test")
                    .header("cookie", format!("scimtest_session={session}"))
                    .form(&[
                        ("csrf_token", csrf),
                        ("profile_id", profile),
                        ("instance_id", revoked_id.as_str())
                    ])
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::FOUND
            );
            let (socket, reply) = exchange(&base, profile, 34).await;
            drop(socket);
            let required: Message = serde_json::from_slice(&reply.into_data()).unwrap();
            assert_eq!(required.kind, "enrollment_required");
            pending = required.enrollment_device_code;
            assert_eq!(
                client
                    .post(format!("{base}/api/enroll/status"))
                    .bearer_auth(&pending)
                    .send()
                    .await
                    .unwrap()
                    .json::<Value>()
                    .await
                    .unwrap(),
                json!({"status":"pending"})
            );
        } else {
            assert_eq!(
                client
                    .post(format!("{base}/api/enroll/status"))
                    .bearer_auth(&pending)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::NOT_FOUND
            );
            let saved = Store::open(&state).unwrap();
            let revoked = saved.instance(profile, &revoked_id).unwrap().unwrap();
            assert!(revoked.revoked);
            assert!(revoked.tunnel_id.is_empty());
            assert!(saved.session(session).unwrap().is_some());
            if phase == "go-rollback" {
                assert_eq!(
                    saved.profile(&created).unwrap().unwrap().settings.name,
                    "Greendale After Migration"
                );
                let response = client
                    .post(format!("{base}/dashboard/applications/update"))
                    .header("host", "admin.greendale.test")
                    .header("cookie", format!("scimtest_session={session}"))
                    .form(&[
                        ("id", created.as_str()),
                        ("csrf_token", csrf),
                        ("name", "Greendale After Rollback"),
                        ("public_key", &public_key(41)),
                        ("routes", "GET /oidc/{slug}/jwks"),
                        ("requests_per_minute", "90"),
                        ("request_burst", "20"),
                        ("concurrent_requests", "3"),
                    ])
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::FOUND);
            } else {
                assert_eq!(
                    saved.profile(&created).unwrap().unwrap().settings.name,
                    "Greendale After Rollback"
                );
            }
        }
        println!(
            "Migration phase {phase}: live Go/Rust clients, public URLs, OIDC/SAML, signing keys, dashboard session and revocation remain valid"
        );
    }
    std::fs::write(&client_stop, "stop").unwrap();
    go_client.wait(true).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(result).unwrap()).unwrap(),
        json!({"stopped":true})
    );
    runtime.shutdown().await.unwrap();
    server.stop().await;
    assert_eq!(
        DesktopStore::open(&desktop)
            .unwrap()
            .installation_identity()
            .unwrap()
            .fingerprint(),
        installation.fingerprint()
    );
}
