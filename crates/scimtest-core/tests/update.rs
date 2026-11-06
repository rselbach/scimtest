#[allow(dead_code)]
mod support;

use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signer, SigningKey};
use scimtest_core::update::*;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

fn release() -> Release {
    serde_json::from_value(json!({
        "schema":1,"app":BUNDLE_ID,"channel":"stable","version":"2.1.0","build":42,
        "published_at":"2026-11-05T20:00:00Z","notes_url":"https://github.com/rselbach/scimtest/releases/tag/v2.1.0",
        "highlights":["Greendale directory tools"],
        "artifacts":[{"os":"linux","arch":"x86_64","kind":"deb","minimum_os":"0","url":"https://github.com/rselbach/scimtest/releases/download/v2.1.0/scimtest.deb","size":9,"sha256":format!("{:x}",Sha256::digest(b"greendale"))}]
    })).unwrap()
}
fn sign(release: &Value, context: &[u8]) -> Vec<u8> {
    let payload = serde_json::to_vec(release).unwrap();
    let key = SigningKey::from_bytes(&[42; 32]);
    serde_json::to_vec(&json!({"payload":STANDARD.encode(&payload),"signature":STANDARD.encode(key.sign(&[context,&payload].concat()).to_bytes())})).unwrap()
}
fn key() -> String {
    STANDARD.encode(SigningKey::from_bytes(&[42; 32]).verifying_key().as_bytes())
}

#[test]
fn signed_feed_matches_go_and_rejects_tampering_and_untrusted_artifacts() {
    let temporary = tempfile::tempdir().unwrap();
    let value = serde_json::to_value(release()).unwrap();
    let feed = support::bridge_input(
        "sign-update-feed",
        &temporary.path().join("state.db"),
        &serde_json::to_vec(&json!({"key":STANDARD.encode([42;32]),"release":value})).unwrap(),
    );
    let verified = verify_feed(&feed, &key()).unwrap();
    assert_eq!((verified.version.as_str(), verified.build), ("2.1.0", 42));
    let mut cases = vec![("valid", value.clone(), true)];
    for (name, pointer, replacement) in [
        ("app", "/app", json!("com.greendale.citycollege")),
        ("schema", "/schema", json!(2)),
        ("channel", "/channel", json!("nightly")),
        ("version", "/version", json!("2.0-preview")),
        ("build", "/build", json!(0)),
        (
            "notes",
            "/notes_url",
            json!("https://citycollege.example/notes"),
        ),
        ("sha256", "/artifacts/0/sha256", json!("not-a-sha256")),
        ("size", "/artifacts/0/size", json!(0)),
        ("large", "/artifacts/0/size", json!(2147483649u64)),
        ("minimum", "/artifacts/0/minimum_os", json!("latest")),
        (
            "origin",
            "/artifacts/0/url",
            json!("https://citycollege.example/scimtest.deb"),
        ),
        (
            "query",
            "/artifacts/0/url",
            json!(
                "https://github.com/rselbach/scimtest/releases/download/v2/scimtest.deb?secret=1"
            ),
        ),
        (
            "traversal",
            "/artifacts/0/url",
            json!("https://github.com/rselbach/scimtest/releases/download/../scimtest.deb"),
        ),
        (
            "highlight",
            "/highlights",
            json!(["Greendale\nCity College"]),
        ),
    ] {
        let mut value = value.clone();
        *value.pointer_mut(pointer).unwrap() = replacement;
        cases.push((name, value, false));
    }
    let mut nulls = value.clone();
    nulls["artifacts"] = Value::Null;
    nulls["highlights"] = Value::Null;
    cases.push(("null arrays", nulls, true));
    for (name, value, want) in cases {
        let feed = sign(&value, b"scimtest-update-feed-v1\n");
        let go: Value = serde_json::from_slice(&support::bridge_input(
            "verify-update-feed",
            &temporary.path().join("state.db"),
            &serde_json::to_vec(
                &json!({"key":key(),"feed":serde_json::from_slice::<Value>(&feed).unwrap()}),
            )
            .unwrap(),
        ))
        .unwrap();
        assert_eq!(go["valid"], want, "Go {name}");
        assert_eq!(verify_feed(&feed, &key()).is_ok(), want, "Rust {name}");
    }
    assert!(verify_feed(&sign(&value, b""), &key()).is_err());
    let mut envelope: Value = serde_json::from_slice(&feed).unwrap();
    envelope["payload"] = json!(STANDARD.encode(b"{\"schema\":1}"));
    assert!(verify_feed(&serde_json::to_vec(&envelope).unwrap(), &key()).is_err());
    assert!(verify_feed(&vec![b' '; 65537], &key()).is_err());
    for (text, want) in [
        ("26", Some([26, 0, 0])),
        (" 26.1.2 ", Some([26, 1, 2])),
        ("+26", None),
        ("26.0.0.1", None),
        ("4294967296", None),
        ("", None),
    ] {
        assert_eq!(parse_version(text), want, "{text}");
    }
}

async fn server(router: axum::Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (url, task)
}

#[tokio::test]
async fn downloads_resume_restart_and_delete_corrupt_or_oversized_results() {
    use axum::{
        http::{HeaderMap, StatusCode},
        routing::get,
    };
    let ranges = Arc::new(Mutex::new(Vec::new()));
    let received = ranges.clone();
    let (url, task) = server(
        axum::Router::new()
            .route(
                "/resume",
                get(move |headers: HeaderMap| {
                    let received = received.clone();
                    async move {
                        received.lock().unwrap().push(
                            headers
                                .get("range")
                                .map(|value| value.to_str().unwrap().to_owned()),
                        );
                        (
                            StatusCode::PARTIAL_CONTENT,
                            [("content-range", "bytes 4-8/9")],
                            "ndale",
                        )
                    }
                }),
            )
            .route("/restart", get(|| async { "greendale" }))
            .route("/corrupt", get(|| async { "citycollege" }))
            .route("/short", get(|| async { "green" })),
    )
    .await;
    let directory = tempfile::tempdir().unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut artifact = release().artifacts.remove(0);
    let path = directory
        .path()
        .join(format!("{}.partial", artifact.sha256));
    let superseded = directory.path().join(format!("{}.partial", "1".repeat(64)));
    std::fs::write(&superseded, b"previous release").unwrap();
    let unrelated = directory.path().join("greendale-notes.txt");
    std::fs::write(&unrelated, b"preserve this file").unwrap();
    std::fs::write(&path, b"gree").unwrap();
    artifact.url = format!("{url}/resume");
    let downloaded = download(&client, &artifact, directory.path())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&downloaded).unwrap(), b"greendale");
    assert!(!superseded.exists());
    assert_eq!(std::fs::read(&unrelated).unwrap(), b"preserve this file");
    assert_eq!(*ranges.lock().unwrap(), vec![Some("bytes=4-".to_owned())]);
    std::fs::write(&path, b"wrong").unwrap();
    artifact.url = format!("{url}/restart");
    download(&client, &artifact, directory.path())
        .await
        .unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"greendale");
    artifact.url = format!("{url}/corrupt");
    assert!(
        download(&client, &artifact, directory.path())
            .await
            .is_err()
    );
    assert!(!path.exists());
    artifact.url = format!("{url}/short");
    assert!(
        download(&client, &artifact, directory.path())
            .await
            .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"green");
    artifact.url = format!("{url}/restart");
    artifact.sha256 = "0".repeat(64);
    let wrong_path = directory
        .path()
        .join(format!("{}.partial", artifact.sha256));
    assert!(
        download(&client, &artifact, directory.path())
            .await
            .is_err()
    );
    assert!(!wrong_path.exists());
    task.abort();
}

#[tokio::test]
async fn linux_offers_its_signed_package_and_preserves_the_offer_on_network_failure() {
    use axum::{http::StatusCode, routing::get};
    let feed = Arc::new(Mutex::new(sign(
        &serde_json::to_value(release()).unwrap(),
        b"scimtest-update-feed-v1\n",
    )));
    let served = feed.clone();
    let (url, task) = server(axum::Router::new().route(
        "/feed",
        get(move || {
            let served = served.clone();
            async move {
                let bytes = served.lock().unwrap().clone();
                (
                    if bytes.is_empty() {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::OK
                    },
                    bytes,
                )
            }
        }),
    ))
    .await;
    let temporary = tempfile::tempdir().unwrap();
    let updater = Updater::new(Config {
        feed_url: format!("{url}/feed"),
        public_key: key(),
        current: Install {
            version: "2.0.0".into(),
            build: 20,
            os_version: [0; 3],
        },
        platform: Platform {
            os: "linux".into(),
            arch: "x86_64".into(),
            kind: "deb".into(),
        },
        state_dir: temporary.path().into(),
        installer: None,
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
    })
    .unwrap();
    updater.check().await.unwrap();
    assert_eq!(updater.snapshot().status, Status::Available);
    assert!(updater.snapshot().download_url.ends_with("scimtest.deb"));
    assert_eq!(
        updater.snapshot().highlights,
        vec!["Greendale directory tools"]
    );
    *feed.lock().unwrap() = Vec::new();
    assert!(updater.check().await.is_err());
    assert_eq!(updater.snapshot().status, Status::Available);
    let prefs: Value =
        serde_json::from_slice(&std::fs::read(temporary.path().join("updater.json")).unwrap())
            .unwrap();
    assert!(prefs["last_check"].is_string());
    assert_eq!(prefs["last_version"], "2.0.0");
    let mut older = release();
    older.version = "1.0".into();
    *feed.lock().unwrap() = sign(
        &serde_json::to_value(older).unwrap(),
        b"scimtest-update-feed-v1\n",
    );
    updater.check().await.unwrap();
    assert_eq!(updater.snapshot().status, Status::Idle);
    task.abort();
}
