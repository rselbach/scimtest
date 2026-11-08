use scimtest_core::{Error, Store, model::*};

fn environment(store: &Store, name: &str) -> Environment {
    store
        .create_environment(EnvironmentInput {
            name: name.into(),
            ..Default::default()
        })
        .unwrap()
}

fn troy() -> UserInput {
    UserInput {
        given_name: "Troy".into(),
        family_name: "Barnes".into(),
        email: "troy@greendale.edu".into(),
        ..Default::default()
    }
}

#[test]
fn directory_survives_restart_and_sample_is_idempotent() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let environment = environment(&store, "Greendale Portal");
    assert_eq!(environment.slug, "greendale-portal");
    let result = store.seed_sample(&environment.id).unwrap();
    assert_eq!((result.users_added, result.groups_added), (10, 3));
    let second = store.seed_sample(&environment.id).unwrap();
    assert_eq!((second.users_added, second.groups_added), (0, 0));
    drop(store);
    let reopened = Store::open(&path).unwrap();
    let directory = reopened.directory(&environment.id).unwrap();
    assert_eq!(directory.users.len(), 10);
    assert_eq!(directory.groups[0].fields.member_ids.len(), 6);
    assert_eq!(
        directory
            .users
            .iter()
            .filter(|user| !user.fields.active)
            .count(),
        1
    );
    let troy = directory
        .users
        .iter()
        .find(|user| user.fields.username == "tbarnes")
        .unwrap();
    let dean = directory
        .users
        .iter()
        .find(|user| user.fields.username == "dpelton")
        .unwrap();
    assert_eq!(troy.fields.manager_id, dean.id);
    assert_eq!(troy.fields.attributes["role"], "student");
}

#[test]
fn failed_mutations_roll_back_and_resources_stay_in_their_environment() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let first = environment(&store, "Greendale");
    let second = environment(&store, "City College");
    let user = store.create_user(&first.id, troy()).unwrap();
    assert_eq!(user.fields.username, user.fields.email);
    assert!(matches!(
        store.create_user(&first.id, troy()),
        Err(Error::Validation(_))
    ));
    store.create_user(&second.id, troy()).unwrap();
    assert!(matches!(
        store.update_user(
            &second.id,
            &user.id,
            UserPatch {
                active: Some(false),
                ..Default::default()
            }
        ),
        Err(Error::NotFound("user"))
    ));
    assert!(
        store
            .create_group(
                &second.id,
                GroupInput {
                    display_name: "Study Group".into(),
                    member_ids: vec![user.id]
                }
            )
            .is_err()
    );
    assert_eq!(store.directory(&first.id).unwrap().users.len(), 1);
    assert!(store.directory(&second.id).unwrap().groups.is_empty());
}

#[test]
fn removing_a_user_cleans_memberships_and_preserves_manager_history() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let environment = environment(&store, "Greendale");
    store.seed_sample(&environment.id).unwrap();
    let before = store.directory(&environment.id).unwrap();
    let dean = before
        .users
        .iter()
        .find(|user| user.fields.username == "dpelton")
        .unwrap();
    store.delete_user(&environment.id, &dean.id).unwrap();
    let after = store.directory(&environment.id).unwrap();
    assert_eq!(after.users.len(), 9);
    let troy = after
        .users
        .iter()
        .find(|user| user.fields.username == "tbarnes")
        .unwrap();
    assert_eq!(troy.fields.manager_id, dean.id);
    store
        .update_user(
            &environment.id,
            &troy.id,
            UserPatch {
                active: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        after
            .groups
            .iter()
            .all(|group| !group.fields.member_ids.contains(&dean.id))
    );
    store.delete_environment(&environment.id).unwrap();
    assert!(store.snapshot().unwrap().is_empty());
}

#[test]
fn sample_preserves_existing_users_and_uses_usernames_for_memberships() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let environment = environment(&store, "Greendale");
    let user = store
        .create_user(
            &environment.id,
            UserInput {
                email: "troy.barnes@greendale.edu".into(),
                username: "troy".into(),
                active: false,
                ..troy()
            },
        )
        .unwrap();
    let result = store.seed_sample(&environment.id).unwrap();
    assert_eq!(result.users_added, 9);
    let directory = store.directory(&environment.id).unwrap();
    assert!(
        !directory
            .users
            .iter()
            .find(|value| value.id == user.id)
            .unwrap()
            .fields
            .active
    );
    assert!(!directory.groups[0].fields.member_ids.contains(&user.id));
    assert_eq!(directory.groups[0].fields.member_ids.len(), 5);
}

#[test]
fn concurrent_changes_do_not_lose_directory_updates() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let environment = environment(&store, "Greendale");
    std::thread::scope(|scope| {
        for index in 0..12 {
            let store = &store;
            let id = &environment.id;
            scope.spawn(move || {
                store
                    .create_user(
                        id,
                        UserInput {
                            email: format!("troy{index}@greendale.edu"),
                            ..troy()
                        },
                    )
                    .unwrap()
            });
        }
    });
    assert_eq!(store.directory(&environment.id).unwrap().users.len(), 12);
}

#[test]
fn malformed_databases_are_rejected_without_changing_the_schema() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("go.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT); PRAGMA user_version = 8;",
        )
        .unwrap();
    assert!(matches!(Store::open(&path), Err(Error::Validation(_))));
    let version: i32 = connection
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 8);
}

#[test]
fn directory_tools_keep_changes_local_and_history_bounded() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let store = Store::open(&path).unwrap();
    let environment = environment(&store, "Greendale");
    store
        .create_users(&environment.id, 2, " @Greendale.edu ")
        .unwrap();
    store
        .create_users(&environment.id, 1, "greendale.edu")
        .unwrap();
    let before = store.directory(&environment.id).unwrap();
    assert_eq!(before.users[0].fields.username, "user001");
    assert_eq!(before.users[2].fields.email, "user003@greendale.edu");
    assert!(
        store
            .create_users(&environment.id, 0, "greendale.edu")
            .is_err()
    );
    assert!(
        store
            .create_users(&environment.id, 2, "greendale.edu/invalid")
            .is_err()
    );
    assert_eq!(
        store
            .set_all_active(&environment.id, false)
            .unwrap()
            .users_changed,
        3
    );
    assert_eq!(
        store
            .set_all_active(&environment.id, false)
            .unwrap()
            .users_changed,
        0
    );
    let id = &before.users[0].id;
    for index in 0..105 {
        store
            .update_user(
                &environment.id,
                id,
                UserPatch {
                    department: Some(format!("Film Studies {index}")),
                    ..Default::default()
                },
            )
            .unwrap();
    }
    let after = store.directory(&environment.id).unwrap();
    assert_eq!(after.user_operations[id].len(), 100);
    let database = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        database
            .query_row(
                "SELECT COUNT(*) FROM operation_logs WHERE resource_id = ?1",
                [id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        100
    );
    let cleared = store.clear_directory(&environment.id).unwrap();
    assert_eq!(cleared.users_changed, 3);
    let after = store.directory(&environment.id).unwrap();
    assert!(after.users.is_empty() && after.groups.is_empty() && after.user_operations.is_empty());
    assert_eq!(
        database
            .query_row("SELECT COUNT(*) FROM operation_logs", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn manager_and_attribute_validation_match_directory_editing_rules() {
    let temporary = tempfile::tempdir().unwrap();
    let store = Store::open(&temporary.path().join("state.db")).unwrap();
    let environment = environment(&store, "Greendale");
    let troy = store.create_user(&environment.id, troy()).unwrap();
    let abed = store
        .create_user(
            &environment.id,
            UserInput {
                given_name: "Abed".into(),
                email: "abed@greendale.edu".into(),
                manager_id: troy.id.clone(),
                ..Default::default()
            },
        )
        .unwrap();
    store
        .update_user(
            &environment.id,
            &troy.id,
            UserPatch {
                manager_id: Some(abed.id.clone()),
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        store
            .update_user(
                &environment.id,
                &troy.id,
                UserPatch {
                    manager_id: Some(troy.id.clone()),
                    ..Default::default()
                }
            )
            .is_err()
    );
    for text in [
        "sub=forged",
        "employeeNumber=forged",
        "1invalid=value",
        "role=student\nrole=faculty",
    ] {
        assert!(scimtest_core::parse_custom_attributes(text).is_err());
    }
    let values = scimtest_core::parse_custom_attributes(
        " role = student \nurn:greendale:club= study group ",
    )
    .unwrap();
    assert_eq!(values["role"], "student");
    assert_eq!(values["urn:greendale:club"], "study group");
}
