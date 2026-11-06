mod support;
use support::{bridge, bridge_input};

use scimtest_core::{Store, model::UserPatch};
use serde_json::Value;

#[test]
fn backups_can_be_restored_by_either_implementation() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    bridge("seed", &path);
    let original: Value = serde_json::from_slice(&bridge("dump", &path)).unwrap();
    let store = Store::open(&path).unwrap();
    let rust_backup = store.backup("app_greendale").unwrap();
    let exported = temporary.path().join("greendale-backup.json");
    store.write_backup("app_greendale", &exported).unwrap();
    let file: scimtest_core::backup::StateBackup =
        serde_json::from_slice(&std::fs::read(&exported).unwrap()).unwrap();
    assert_eq!(file.state.users.len(), 2);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&exported).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    bridge_input("restore", &path, &serde_json::to_vec(&rust_backup).unwrap());
    let restored_by_go: Value = serde_json::from_slice(&bridge("dump", &path)).unwrap();
    assert_eq!(original, restored_by_go);
    store
        .update_user(
            "app_greendale",
            "user_troy",
            UserPatch {
                department: Some("Film Studies".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let go_backup = serde_json::from_value(original["app_greendale"].clone()).unwrap();
    let safety = store.restore_backup("app_greendale", go_backup).unwrap();
    let before_restore = rusqlite::Connection::open(safety).unwrap();
    let department: String = before_restore.query_row("SELECT department FROM users WHERE environment_id = 'app_greendale' AND id = 'user_troy'", [], |row| row.get(0)).unwrap();
    assert_eq!(department, "Film Studies");
    let restored_by_rust: Value = serde_json::from_slice(&bridge("dump", &path)).unwrap();
    assert_eq!(original, restored_by_rust);
}

#[test]
fn original_state_round_trips_through_rust_without_losing_configuration() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    bridge("seed", &path);
    let mut before: Value = serde_json::from_slice(&bridge("dump", &path)).unwrap();
    let database = rusqlite::Connection::open(&path).unwrap();
    let rows = |table: &str| {
        let mut statement = database
            .prepare(&format!("SELECT rowid, id FROM {table} ORDER BY rowid"))
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let app_rows = rows("apps");
    let user_rows = rows("users");
    let raw_config = |table: &str| {
        let mut statement = database
            .prepare(&format!("SELECT key, value FROM {table} ORDER BY rowid"))
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    let global = raw_config("config");
    let configuration = raw_config("environment_config");
    let store = Store::open(&path).unwrap();
    store
        .update_user(
            "app_greendale",
            "user_troy",
            UserPatch {
                department: Some("Film Studies".into()),
                ..Default::default()
            },
        )
        .unwrap();
    drop(store);
    before["app_greendale"]["state"]["users"][0]["department"] = "Film Studies".into();
    before["app_greendale"]["user_sync"]["app_greendale"]["user_troy"]["Dirty"] = true.into();
    before["app_greendale"]["user_sync"]["app_greendale"]["user_troy"]["LastError"] = "".into();
    let mut after: Value = serde_json::from_slice(&bridge("dump", &path)).unwrap();
    let operation = after["app_greendale"]["user_operations"]["user_troy"]
        .as_array_mut()
        .unwrap()
        .remove(0);
    assert_eq!(operation["Summary"], "Updated enterprise attributes");
    assert_eq!(operation["Kind"], "local");
    assert!(chrono::DateTime::parse_from_rfc3339(operation["CreatedAt"].as_str().unwrap()).is_ok());
    assert_eq!(before, after);
    assert_eq!(app_rows, rows("apps"));
    assert_eq!(user_rows, rows("users"));
    assert_eq!(global, raw_config("config"));
    assert_eq!(configuration, raw_config("environment_config"));
}

#[test]
fn legacy_migration_matches_the_original_and_keeps_a_private_safety_copy() {
    let temporary = tempfile::tempdir().unwrap();
    let go_path = temporary.path().join("original.db");
    let rust_path = temporary.path().join("rust.db");
    bridge("seed-legacy", &go_path);
    std::fs::copy(&go_path, &rust_path).unwrap();
    let original: Value = serde_json::from_slice(&bridge("dump", &go_path)).unwrap();
    let store = Store::open(&rust_path).unwrap();
    let directories = store.snapshot().unwrap();
    assert_eq!(directories.len(), 2);
    for directory in &directories {
        assert_eq!(
            directory.environment.settings.protocol,
            original[&directory.environment.id]["state"]["apps"][0]["protocol"]
        );
        assert_eq!(
            serde_json::to_value(&directory.environment.settings.saml_attribute_mappings).unwrap(),
            original[&directory.environment.id]["state"]["apps"][0]["saml_attribute_mappings"]
        );
    }
    drop(store);
    let migrated: Value = serde_json::from_slice(&bridge("dump", &rust_path)).unwrap();
    assert_eq!(original, migrated);
    let copies = std::fs::read_dir(temporary.path().join("backups"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect::<Vec<_>>();
    let rust_copy = copies
        .iter()
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("pre-migrate-")
                && !path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .starts_with("pre-migrate-v")
        })
        .unwrap();
    let copy = rusqlite::Connection::open(rust_copy).unwrap();
    let version: i64 = copy
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 0);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(rust_copy).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
