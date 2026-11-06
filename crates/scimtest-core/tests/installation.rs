mod support;
use base64::{Engine, engine::general_purpose::STANDARD};
use scimtest_core::Store;
use serde_json::{Value, json};

#[test]
fn installation_credentials_and_challenge_signatures_interoperate_with_go() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let first = store.installation_identity().unwrap();
    let go: Value =
        serde_json::from_slice(&support::bridge("installation-identity", &path)).unwrap();
    assert_eq!(
        go,
        json!({"instance_id":first.instance_id,"public_key":first.public_key(),"fingerprint":first.fingerprint()})
    );
    let signature = first.sign_challenge("0123456789abcdef0123456789abcdef", "greendale-challenge");
    let verified:Value=serde_json::from_slice(&support::bridge_input("verify-installation-signature",&path,&serde_json::to_vec(&json!({"profile":"0123456789abcdef0123456789abcdef","public_key":first.public_key(),"instance_id":first.instance_id,"challenge":"greendale-challenge","signature":STANDARD.encode(signature)})).unwrap())).unwrap();
    assert_eq!(verified["valid"], true);
    drop(store);
    let store = Store::open(&path).unwrap();
    assert_eq!(
        store.installation_identity().unwrap().fingerprint(),
        first.fingerprint()
    );
    let second = store.rotate_installation_identity().unwrap();
    assert_ne!(second.instance_id, first.instance_id);
    assert_ne!(second.fingerprint(), first.fingerprint());
    let go: Value =
        serde_json::from_slice(&support::bridge("installation-identity", &path)).unwrap();
    assert_eq!(go["fingerprint"], second.fingerprint());
    let go: Value = serde_json::from_slice(&support::bridge("rotate-installation", &path)).unwrap();
    let third = store.installation_identity().unwrap();
    assert_eq!(go["instance_id"], third.instance_id);
    assert_eq!(go["fingerprint"], third.fingerprint());
    assert_ne!(third.fingerprint(), second.fingerprint());
}

#[test]
fn legacy_ids_are_preserved_but_invalid_credentials_are_repaired_and_rotation_is_atomic() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    let legacy = "091A87D4-BB33-4CF0-B573-4E8AAB36D21B";
    connection
        .execute(
            "INSERT INTO config VALUES ('rgrok_instance_id',?1)",
            [legacy],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO config VALUES ('tunnel_instance_key','not-a-seed')",
            [],
        )
        .unwrap();
    let first = store.installation_identity().unwrap();
    assert_eq!(first.instance_id, legacy);
    assert_eq!(
        store.installation_identity().unwrap().fingerprint(),
        first.fingerprint()
    );
    connection.execute("UPDATE config SET value='invalid' WHERE key IN ('tunnel_instance_key','tunnel_instance_id')",[]).unwrap();
    let repaired = store.installation_identity().unwrap();
    assert_ne!(repaired.instance_id, legacy);
    assert!(uuid::Uuid::parse_str(&repaired.instance_id).is_ok());
    assert_ne!(repaired.fingerprint(), first.fingerprint());
    connection.execute_batch("CREATE TRIGGER block_identity_rotation BEFORE UPDATE OF value ON config WHEN NEW.key='tunnel_instance_key' BEGIN SELECT RAISE(ABORT,'Greendale blocked rotation'); END;").unwrap();
    assert!(store.rotate_installation_identity().is_err());
    let saved: String = connection
        .query_row(
            "SELECT value FROM config WHERE key='tunnel_instance_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(saved, repaired.instance_id);
    connection
        .execute_batch("DROP TRIGGER block_identity_rotation;")
        .unwrap();
    let rotated = store.rotate_installation_identity().unwrap();
    assert_ne!(rotated.instance_id, repaired.instance_id);
    let aliases: i64 = connection
        .query_row(
            "SELECT count(*) FROM config WHERE key='rgrok_instance_id'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(aliases, 0);
}
