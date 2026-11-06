mod support;

use chrono::{Duration, Utc};
use scimtest_core::{
    Store,
    configuration::SettingsPatch,
    model::EnvironmentInput,
    signing::{CertificateValidity, parse_grace},
};
use serde_json::{Value, json};
use support::{bridge, bridge_input};

fn environment(store: &Store, name: &str) -> String {
    store
        .create_environment(EnvironmentInput {
            name: name.into(),
            settings: SettingsPatch {
                oidc_enabled: Some(true),
                oidc_client_id: Some(name.into()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap()
        .id
}

#[test]
fn go_and_rust_signing_material_interoperate_and_survive_rotation() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    bridge("seed", &path);
    let store = Store::open(&path).unwrap();
    let imported = store.active_signing_key("app_greendale").unwrap();
    assert_eq!(imported.stored.kid, "greendale-key");
    let claims = json!({"sub":"user_troy", "aud":"greendale", "iat":Utc::now().timestamp()});
    let token = imported.sign_jwt(&claims, "JWT").unwrap();
    let verified: Value = serde_json::from_slice(&bridge_input(
        "verify-jwt",
        &path,
        &serde_json::to_vec(
            &json!({"token":token,"certificate_pem":imported.stored.certificate_pem}),
        )
        .unwrap(),
    ))
    .unwrap();
    assert_eq!(verified["claims"], claims);
    assert_eq!(imported.verify_jwt(&token).unwrap(), claims);
    let rotated = store
        .rotate_signing_key(
            "app_greendale",
            Duration::hours(24),
            CertificateValidity::Standard,
        )
        .unwrap();
    assert_eq!(rotated.len(), 2);
    assert!(rotated[0].active && !rotated[1].active);
    assert_eq!(rotated[1].kid, "greendale-key");
    assert_ne!(rotated[0].kid, rotated[1].kid);
    let active = rotated[0].kid.clone();
    assert_eq!(
        store
            .published_signing_keys("app_greendale", Utc::now() + Duration::days(2))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .active_signing_key("app_city_college")
            .unwrap()
            .stored
            .kid,
        "greendale-key"
    );
    drop(store);
    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened
            .active_signing_key("app_greendale")
            .unwrap()
            .stored
            .kid,
        active
    );
    let dump: Value = serde_json::from_slice(&bridge("dump", &path)).unwrap();
    assert_eq!(
        dump["app_greendale"]["state"]["config"]["signing_keys"][1]["kid"],
        active
    );
}

#[test]
fn certificate_test_periods_are_accepted_by_go_and_grace_zero_removes_retired_keys() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let first = environment(&store, "Greendale");
    let second = environment(&store, "City College");
    let shared = store.active_signing_key(&first).unwrap().jwk();
    assert_eq!(shared, store.active_signing_key(&second).unwrap().jwk());
    for validity in [
        CertificateValidity::Standard,
        CertificateValidity::Expired,
        CertificateValidity::NotYetValid,
        CertificateValidity::NoExpiration,
        CertificateValidity::ZeroTime,
    ] {
        let keys = store
            .rotate_signing_key(&first, Duration::zero(), validity)
            .unwrap();
        assert_eq!(keys.len(), 1);
        let key = store.active_signing_key(&first).unwrap();
        let token = key.sign_jwt(&json!({"sub":"user_troy"}), "JWT").unwrap();
        let verified: Value = serde_json::from_slice(&bridge_input(
            "verify-jwt",
            &path,
            &serde_json::to_vec(
                &json!({"token":token,"certificate_pem":key.stored.certificate_pem}),
            )
            .unwrap(),
        ))
        .unwrap();
        assert_eq!(verified["bits"], 2048);
        assert_eq!(verified["not_before"], keys[0].not_before);
        assert_eq!(verified["not_after"], keys[0].not_after);
        let before = chrono::DateTime::parse_from_rfc3339(&keys[0].not_before).unwrap();
        let after = chrono::DateTime::parse_from_rfc3339(&keys[0].not_after).unwrap();
        match validity {
            CertificateValidity::Expired | CertificateValidity::ZeroTime => {
                assert!(after < Utc::now())
            }
            CertificateValidity::NotYetValid => assert!(before > Utc::now()),
            CertificateValidity::NoExpiration => {
                assert!(keys[0].not_after.starts_with("9999-12-31"))
            }
            _ => assert!(before < Utc::now() && after > Utc::now()),
        }
    }
    assert_eq!(shared, store.active_signing_key(&second).unwrap().jwk());
    for value in ["-1s", "169h", "bad"] {
        assert!(parse_grace(value).is_err());
    }
    assert_eq!(parse_grace("").unwrap(), Duration::hours(24));
    assert_eq!(parse_grace("1.5h").unwrap(), Duration::minutes(90));
}
