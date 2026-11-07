use scimtest_core::{Store, model::UserPatch};

#[test]
fn initial_rust_preview_migrates_with_a_readable_safety_copy() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let database = rusqlite::Connection::open(&path).unwrap();
    database.execute_batch("CREATE TABLE environments (id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT NOT NULL UNIQUE);
        CREATE TABLE users (id TEXT PRIMARY KEY, environment_id TEXT NOT NULL, data TEXT NOT NULL);
        CREATE TABLE groups (id TEXT PRIMARY KEY, environment_id TEXT NOT NULL, data TEXT NOT NULL);
        INSERT INTO environments VALUES ('app_greendale', 'Greendale', 'greendale');
        INSERT INTO users VALUES ('user_troy', 'app_greendale', '{\"id\":\"user_troy\",\"given_name\":\"Troy\",\"email\":\"troy@greendale.edu\",\"active\":false}');
        INSERT INTO groups VALUES ('group_study', 'app_greendale', '{\"id\":\"group_study\",\"display_name\":\"Study Group\",\"member_ids\":[\"user_troy\"]}');
        PRAGMA application_id = 1396920915; PRAGMA user_version = 1;").unwrap();
    drop(database);
    let store = Store::open(&path).unwrap();
    let directory = store.directory("app_greendale").unwrap();
    assert!(!directory.users[0].fields.active);
    assert_eq!(directory.groups[0].fields.member_ids, ["user_troy"]);
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
    let copies = std::fs::read_dir(temporary.path().join("backups"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(copies.len(), 1);
    let copy = rusqlite::Connection::open(copies[0].path()).unwrap();
    assert_eq!(
        copy.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        copy.query_row("SELECT data FROM users", [], |row| row.get::<_, String>(0))
            .unwrap(),
        r#"{"id":"user_troy","given_name":"Troy","email":"troy@greendale.edu","active":false}"#
    );
    drop(store);
    assert_eq!(
        Store::open(&path)
            .unwrap()
            .directory("app_greendale")
            .unwrap()
            .users[0]
            .fields
            .department,
        "Film Studies"
    );
}
