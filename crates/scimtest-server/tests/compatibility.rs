mod support;

use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{Duration, Timelike, Utc};
use scimtest_server::{
    application::{ApplicationSettings, parse_instance_key, parse_routes},
    store::{EnrollmentActor, Store},
};
use serde_json::json;
use std::{collections::BTreeSet, fs};
use support::{GoFixture, public_key};

fn settings(name: &str, seed: u8) -> ApplicationSettings {
    ApplicationSettings {
        name: name.into(),
        public_key: public_key(seed),
        routes: parse_routes("GET,POST /oidc/{slug}/authorize\nPOST /oidc/{slug}/token").unwrap(),
        requests_per_minute: 60,
        request_burst: 10,
        concurrent_requests: 4,
    }
}

#[test]
fn go_and_rust_share_profiles_sessions_and_installation_reservations() {
    let go = GoFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("server.json");
    let mut configuration = settings("  Greendale\t Identity  ", 42);
    configuration
        .public_key
        .push_str(" Troy Barnes at Greendale");
    let seeded = go.run(json!({"kind":"seed","path":path,"settings":configuration}));
    let id = seeded["profile"]["id"].as_str().unwrap();
    let session_id = seeded["session"]["id"].as_str().unwrap();
    let store = Store::open(&path).unwrap();
    assert_eq!(
        serde_json::to_value(store.profile(id).unwrap().unwrap()).unwrap(),
        seeded["profile"]
    );
    assert_eq!(
        serde_json::to_value(store.session(session_id).unwrap().unwrap()).unwrap(),
        seeded["session"]
    );
    assert_eq!(
        store.profile(id).unwrap().unwrap().settings.name,
        "Greendale Identity"
    );

    let key = STANDARD.encode(
        ed25519_dalek::SigningKey::from_bytes(&[24; 32])
            .verifying_key()
            .as_bytes(),
    );
    let (_, instance_id) = parse_instance_key(&key).unwrap();
    store
        .enroll_instance(
            id,
            &instance_id,
            &key,
            EnrollmentActor {
                github_user_id: 101,
                github_login: " troy-barnes ".into(),
            },
        )
        .unwrap();
    store
        .remember_tunnel(id, &instance_id, "human-timeline-club", true)
        .unwrap();
    let first = store.instance(id, &instance_id).unwrap().unwrap();
    store
        .remember_tunnel(id, &instance_id, "human-timeline-club", true)
        .unwrap();
    let second = store.instance(id, &instance_id).unwrap().unwrap();
    assert_eq!(first.created_at, second.created_at);
    assert!(second.last_used_at >= first.last_used_at);
    assert!(store.tunnel_id_reserved("human-timeline-club").unwrap());
    store
        .remember_tunnel(id, "legacy-installation", "study-room-club", false)
        .unwrap();
    assert_eq!(store.count_instances_for_user(id, 101).unwrap(), 1);

    let inspected =
        go.run(json!({"kind":"store","path":path,"profile_id":id,"session_id":session_id}));
    assert_eq!(
        inspected["profile"],
        serde_json::to_value(store.profile(id).unwrap().unwrap()).unwrap()
    );
    assert_eq!(inspected["session"], seeded["session"]);
    let mutated = go.run(json!({"kind":"store","path":path,"profile_id":id,"session_id":session_id,"actions":[
        {"kind":"revoke_user","instance_id":instance_id,"user_id":999},
        {"kind":"revoke_user","instance_id":instance_id,"user_id":101},
        {"kind":"remember","instance_id":instance_id,"existing":true,"tunnel_id":"human-timeline-club"},
        {"kind":"count","user_id":101},
        {"kind":"reserved","tunnel_id":"human-timeline-club"},
        {"kind":"unreserve","instance_id":instance_id},
        {"kind":"set_revoked","instance_id":instance_id,"revoked":false},
        {"kind":"remember","instance_id":instance_id,"existing":true,"tunnel_id":"troy-and-abed"},
        {"kind":"unreserve","instance_id":"legacy-installation"}
    ]}));
    assert_eq!(
        mutated["results"],
        json!([
            {"value":false,"error":""},{"value":true,"error":""},
            {"value":null,"error":"installation revoked"},{"value":0,"error":""},
            {"value":true,"error":""},{"value":true,"error":""},
            {"value":true,"error":""},{"value":null,"error":""},{"value":true,"error":""}
        ])
    );
    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        serde_json::to_value(reopened.profile(id).unwrap().unwrap()).unwrap(),
        mutated["profile"]
    );
    assert_eq!(
        reopened.tunnel_id(id, &instance_id).unwrap(),
        "troy-and-abed"
    );
    assert!(
        reopened
            .instance(id, "legacy-installation")
            .unwrap()
            .is_none()
    );
    assert_eq!(reopened.count_instances_for_user(id, 101).unwrap(), 1);
    assert!(
        !reopened
            .revoke_instance_for_user(id, &instance_id, 999)
            .unwrap()
    );
    assert!(
        reopened
            .revoke_instance_for_user(id, &instance_id, 101)
            .unwrap()
    );
    assert_eq!(
        reopened
            .remember_tunnel(id, &instance_id, "blocked", true)
            .unwrap_err()
            .to_string(),
        "installation revoked"
    );
    assert_eq!(
        reopened
            .enroll_instance(
                id,
                &instance_id,
                &key,
                EnrollmentActor {
                    github_user_id: 101,
                    github_login: "troy-barnes".into()
                }
            )
            .unwrap_err()
            .to_string(),
        "installation revoked"
    );
    assert!(reopened.unreserve_tunnel(id, &instance_id).unwrap());
    assert!(
        reopened
            .instance(id, &instance_id)
            .unwrap()
            .unwrap()
            .is_enrolled()
    );
    let final_go =
        go.run(json!({"kind":"store","path":path,"profile_id":id,"session_id":session_id}));
    assert_eq!(
        final_go["profile"],
        serde_json::to_value(reopened.profile(id).unwrap().unwrap()).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        fs::read_dir(directory.path()).unwrap().count(),
        1,
        "no temporary save files remain"
    );
}

#[test]
fn legacy_instance_dates_and_expired_sessions_migrate_identically() {
    let go = GoFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let id = "0123456789abcdef0123456789abcdef";
    let old = (Utc::now() - Duration::days(120))
        .with_nanosecond(120_000_000)
        .unwrap();
    let recent = Utc::now() - Duration::days(1);
    let data = json!({"application_profiles":{id:{"id":id,"name":"Greendale","created_at":old,
    "instances":{
        "legacy-used":{"tunnel_id":"study-room","last_used_at":recent},
        "legacy-empty":{"tunnel_id":"human-timeline"},
        "enrolled-idle":{"public_key":"troy-key","github_user_id":101,"github_login":"troy-barnes","last_used_at":old},
        "revoked-idle":{"public_key":"abed-key","github_user_id":102,"github_login":"abed-nadir","revoked":true,"last_used_at":old},
        "retained-idle":{"public_key":"annie-key","github_user_id":103,"github_login":"annie-edison","last_used_at":old}
    }}},"sessions":{
        "expired":{"id":"expired","login":"rselbach","admin":true,"csrf_token":"greendale-csrf","expires_at":old},
        "wrong-account":{"id":"wrong-account","login":"troy-barnes","admin":true,"csrf_token":"greendale-csrf","expires_at":Utc::now()+Duration::days(1)},
        "missing-csrf":{"id":"missing-csrf","login":"rselbach","admin":true,"expires_at":Utc::now()+Duration::days(1)}
    }});
    let go_path = directory.path().join("go.json");
    let rust_path = directory.path().join("rust.json");
    for path in [&go_path, &rust_path] {
        fs::write(path, serde_json::to_vec(&data).unwrap()).unwrap();
    }
    let rust = Store::open(&rust_path).unwrap();
    let migrated =
        go.run(json!({"kind":"store","path":go_path,"profile_id":id,"session_id":"expired"}));
    assert_eq!(
        Store::open(&go_path).unwrap().profile(id).unwrap(),
        rust.profile(id).unwrap(),
        "Go migrations may write null route arrays"
    );
    assert_eq!(
        serde_json::to_value(rust.profile(id).unwrap().unwrap()).unwrap(),
        migrated["profile"]
    );
    assert_eq!(
        rust.instance(id, "legacy-used")
            .unwrap()
            .unwrap()
            .created_at,
        recent
    );
    assert_eq!(
        rust.instance(id, "legacy-empty")
            .unwrap()
            .unwrap()
            .created_at,
        old
    );
    for session in ["expired", "wrong-account", "missing-csrf"] {
        assert!(rust.session(session).unwrap().is_none());
        let result =
            go.run(json!({"kind":"store","path":go_path,"profile_id":id,"session_id":session}));
        assert_eq!(result["session_found"], false);
    }
    let cutoff = Utc::now() - Duration::days(90);
    assert_eq!(
        rust.prune_idle_instances(id, cutoff, &BTreeSet::from(["retained-idle".into()]))
            .unwrap(),
        1
    );
    let pruned=go.run(json!({"kind":"store","path":go_path,"profile_id":id,"actions":[{"kind":"prune","cutoff":cutoff,"retained":{"retained-idle":true}}]}));
    assert_eq!(pruned["results"][0]["value"], 1);
    assert_eq!(
        pruned["profile"],
        serde_json::to_value(rust.profile(id).unwrap().unwrap()).unwrap()
    );
    assert!(rust.instance(id, "legacy-empty").unwrap().is_some());
    assert!(rust.instance(id, "revoked-idle").unwrap().unwrap().revoked);
    let null_path = directory.path().join("null.json");
    fs::write(
        &null_path,
        b"{\"sessions\":null,\"application_profiles\":null}",
    )
    .unwrap();
    assert!(
        Store::open(&null_path)
            .unwrap()
            .profiles()
            .unwrap()
            .is_empty()
    );
    assert!(
        go.run(json!({"kind":"store","path":null_path}))["profiles"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let corrupt = directory.path().join("corrupt.json");
    fs::write(&corrupt, b"{invalid Greendale data").unwrap();
    assert!(Store::open(&corrupt).is_err());
    assert_eq!(fs::read(&corrupt).unwrap(), b"{invalid Greendale data");
}

#[test]
fn profile_updates_and_validation_preserve_existing_installations() {
    let go = GoFixture::new();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("server.json");
    let rust = Store::open(&path).unwrap();
    let profile = rust.create_profile(settings("Greendale", 42)).unwrap();
    let session = rust.create_session(" RSELBACH ", true).unwrap();
    assert_eq!(session.id.len(), 64);
    assert_eq!(session.csrf_token.len(), 64);
    assert_ne!(session.id, session.csrf_token);
    assert_eq!(session.expires_at - session.created_at, Duration::days(30));
    assert!(rust.create_session("troy-barnes", true).is_err());
    assert!(rust.create_session("rselbach", false).is_err());
    rust.remember_tunnel(&profile.id, "legacy-installation", "study-room", false)
        .unwrap();
    let updated = rust
        .update_profile(&profile.id, settings("Greendale Community College", 24))
        .unwrap();
    assert_eq!(updated.instances.len(), 1);
    assert_eq!(updated.created_at, profile.created_at);
    let inspected =
        go.run(json!({"kind":"store","path":path,"profile_id":profile.id,"session_id":session.id}));
    assert_eq!(
        inspected["profile"],
        serde_json::to_value(&updated).unwrap()
    );
    assert!(rust.create_profile(settings("Duplicate key", 24)).is_err());
    let second = rust.create_profile(settings("Abed Nadir", 12)).unwrap();
    assert_eq!(rust.profiles().unwrap()[0].id, second.id);
    assert!(
        rust.update_profile(&second.id, settings("Duplicate key", 24))
            .is_err()
    );
    for mut configuration in [
        settings("", 1),
        settings(&"🦀".repeat(21), 1),
        settings("Invalid key", 1),
        settings("No routes", 1),
        settings("Invalid limit", 1),
    ] {
        match configuration.name.as_str() {
            "Invalid key" => configuration.public_key = "ssh-rsa AAAA".into(),
            "No routes" => configuration.routes.clear(),
            "Invalid limit" => configuration.request_burst = 0,
            _ => {}
        }
        assert!(rust.create_profile(configuration).is_err());
    }
    assert_eq!(rust.profiles().unwrap().len(), 2);
    rust.delete_session(&session.id).unwrap();
    assert!(rust.session(&session.id).unwrap().is_none());
    rust.delete_profile(&profile.id).unwrap();
    assert!(!rust.tunnel_id_reserved("study-room").unwrap());
    assert!(rust.profile(&profile.id).unwrap().is_none());
    assert!(rust.delete_profile(&profile.id).is_err());
    let final_go =
        go.run(json!({"kind":"store","path":path,"profile_id":second.id,"session_id":session.id}));
    assert_eq!(final_go["profile"], serde_json::to_value(second).unwrap());
    assert_eq!(final_go["session_found"], false);
}
