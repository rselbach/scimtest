use scimtest_core::{Store, configuration::GlobalConfigPatch, model::*};
use serde_json::json;
use std::fs;

#[test]
fn legacy_directory_without_apps_is_visible_and_configured_databases_are_not_overwritten() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("directory");
    fs::write(temporary.path().join("directory.json"),br#"{"config":null,"users":[{"id":"troy","name":"Troy Barnes","email":"troy@greendale.edu","active":false}],"groups":null,"apps":null}"#).unwrap();
    let store = Store::open(&path).unwrap();
    let directory = store.directory("env_default").unwrap();
    assert_eq!(directory.environment.name, "Default");
    assert_eq!(directory.users[0].fields.given_name, "Troy");
    assert_eq!(directory.users[0].fields.family_name, "Barnes");
    assert!(!directory.users[0].fields.active);
    store.clear_directory("env_default").unwrap();
    store.delete_environment("env_default").unwrap();
    drop(store);
    assert!(Store::open(&path).unwrap().snapshot().unwrap().is_empty());

    let path = temporary.path().join("configured.db");
    let store = Store::open(&path).unwrap();
    store
        .update_global_config(&GlobalConfigPatch {
            idp_base_url: Some("https://greendale.example".into()),
            ..Default::default()
        })
        .unwrap();
    drop(store);
    fs::write(path.with_extension("json"), b"not JSON").unwrap();
    assert_eq!(
        Store::open(&path)
            .unwrap()
            .global_config()
            .unwrap()
            .idp_base_url,
        "https://greendale.example"
    );
}

#[test]
fn invalid_legacy_json_and_conflicting_apps_leave_sqlite_empty_and_can_be_retried() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let legacy = path.with_extension("json");
    for bytes in [br#"{"users":"not an array"}"#.as_slice(),br#"{"apps":[{"id":"greendale","name":"Greendale","slug":"college"},{"id":"city-college","name":"City College","slug":"college"}]}"#] {
        fs::write(&legacy,bytes).unwrap();
        assert!(Store::open(&path).is_err());
        let connection=rusqlite::Connection::open(&path).unwrap();
        assert_eq!(connection.query_row("SELECT COUNT(*) FROM apps",[],|row| row.get::<_,i64>(0)).unwrap(),0);
        assert_eq!(connection.query_row("SELECT COUNT(*) FROM config WHERE key = 'legacy_json_imported'",[],|row| row.get::<_,i64>(0)).unwrap(),0);
        assert_eq!(fs::read(&legacy).unwrap(),bytes);
    }
    fs::write(&legacy,br#"{"apps":[{"id":"greendale","name":"Greendale"}],"users":[{"id":"troy","given_name":"Troy","email":"troy@greendale.edu"}]}"#).unwrap();
    let store = Store::open(&path).unwrap();
    let directory = store.directory("greendale").unwrap();
    assert!(directory.users[0].fields.active);
    assert_eq!(directory.environment.settings.oidc_client_id, "greendale");
    store
        .create_user(
            "greendale",
            UserInput {
                given_name: "Abed".into(),
                email: "abed@greendale.edu".into(),
                ..Default::default()
            },
        )
        .unwrap();
    drop(store);
    fs::write(&legacy, b"now corrupt").unwrap();
    assert_eq!(
        Store::open(&path)
            .unwrap()
            .directory("greendale")
            .unwrap()
            .users
            .len(),
        2
    );
}

#[test]
fn legacy_signing_material_and_modern_installation_identity_are_preserved() {
    let temporary = tempfile::tempdir().unwrap();
    let key_store = Store::open(&temporary.path().join("key.db")).unwrap();
    let key = key_store.shared_signing_key().unwrap();
    let path = temporary.path().join("legacy.db");
    let input = json!({"config":{"signing_private_key_pem":key.stored.private_key_pem,"signing_certificate_pem":key.stored.certificate_pem,"tunnel_instance_id":"greendale-installation","rgrok_instance_id":"obsolete-installation"},"apps":[{"id":"greendale","name":"Greendale"}]});
    fs::write(
        path.with_extension("json"),
        serde_json::to_vec(&input).unwrap(),
    )
    .unwrap();
    let store = Store::open(&path).unwrap();
    assert_eq!(
        store
            .backup("greendale")
            .unwrap()
            .state
            .config
            .tunnel_instance_id,
        "greendale-installation"
    );
    let imported = store.shared_signing_key().unwrap();
    assert_eq!(imported.stored.private_key_pem, key.stored.private_key_pem);
    assert_eq!(imported.stored.certificate_pem, key.stored.certificate_pem);
}
