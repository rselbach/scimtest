use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};

fn settings(seed: u8) -> ApplicationSettings {
    let mut blob = 11_u32.to_be_bytes().to_vec();
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32_u32.to_be_bytes());
    blob.extend_from_slice(&[seed; 32]);
    ApplicationSettings {
        name: "Greendale Community College".into(),
        public_key: format!("ssh-ed25519 {}", STANDARD.encode(blob)),
        routes: crate::application::parse_routes("GET /oidc/{slug}/jwks").unwrap(),
        requests_per_minute: 60,
        request_burst: 10,
        concurrent_requests: 4,
    }
}

#[test]
fn failed_persistence_rolls_back_all_mutations_and_expired_session_removal() {
    for action in [
        "session",
        "expired-session",
        "delete-session",
        "create-profile",
        "update-profile",
        "delete-profile",
        "enroll",
        "prune",
        "revoke-user",
        "set-revoked",
        "remember",
        "unreserve",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut store = Store::open(directory.path().join("server.json")).unwrap();
        let profile = store.create_profile(settings(42)).unwrap();
        let session = store.create_session("rselbach", true).unwrap();
        store
            .enroll_instance(
                &profile.id,
                "troy-installation",
                "troy-key",
                EnrollmentActor {
                    github_user_id: 101,
                    github_login: "troy-barnes".into(),
                },
            )
            .unwrap();
        store
            .remember_tunnel(
                &profile.id,
                "troy-installation",
                "human-timeline-club",
                true,
            )
            .unwrap();
        if action == "expired-session" {
            store
                .data
                .lock()
                .unwrap()
                .sessions
                .get_mut(&session.id)
                .unwrap()
                .expires_at = Utc::now() - Duration::days(1);
        }
        let want = store.read().unwrap().clone();
        store.path = directory.path().into();
        let result = match action {
            "session" => store.create_session("rselbach", true).map(|_| ()),
            "expired-session" => store.session(&session.id).map(|_| ()),
            "delete-session" => store.delete_session(&session.id),
            "create-profile" => store.create_profile(settings(24)).map(|_| ()),
            "update-profile" => store.update_profile(&profile.id, settings(24)).map(|_| ()),
            "delete-profile" => store.delete_profile(&profile.id),
            "enroll" => store.enroll_instance(
                &profile.id,
                "abed-installation",
                "abed-key",
                EnrollmentActor {
                    github_user_id: 102,
                    github_login: "abed-nadir".into(),
                },
            ),
            "prune" => store
                .prune_idle_instances(
                    &profile.id,
                    Utc::now() + Duration::days(1),
                    &BTreeSet::new(),
                )
                .map(|_| ()),
            "revoke-user" => store
                .revoke_instance_for_user(&profile.id, "troy-installation", 101)
                .map(|_| ()),
            "set-revoked" => store
                .set_instance_revoked(&profile.id, "troy-installation", true)
                .map(|_| ()),
            "remember" => {
                store.remember_tunnel(&profile.id, "troy-installation", "study-room", true)
            }
            "unreserve" => store
                .unreserve_tunnel(&profile.id, "troy-installation")
                .map(|_| ()),
            _ => unreachable!(),
        };
        assert_eq!(
            result.unwrap_err().to_string(),
            "replace server store",
            "{action}"
        );
        assert_eq!(*store.read().unwrap(), want, "{action}");
        assert!(
            !store
                .set_instance_revoked(&profile.id, "missing", true)
                .unwrap()
        );
        assert!(
            !store
                .revoke_instance_for_user(&profile.id, "missing", 101)
                .unwrap()
        );
        assert!(!store.unreserve_tunnel(&profile.id, "missing").unwrap());
    }
}

#[test]
fn full_instance_limit_preserves_revocations_and_permits_existing_identity() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path().join("server.json")).unwrap();
    let profile = store.create_profile(settings(42)).unwrap();
    {
        let mut data = store.read().unwrap();
        let profile = data.application_profiles.get_mut(&profile.id).unwrap();
        for index in 0..MAX_INSTANCES {
            profile.instances.insert(
                format!("revoked-{index}"),
                Instance {
                    public_key: "abed-key".into(),
                    revoked: true,
                    ..Instance::default()
                },
            );
        }
    }
    let want = store.profile(&profile.id).unwrap().unwrap();
    assert_eq!(
        store
            .remember_tunnel(&profile.id, "new", "study-room", false)
            .unwrap_err()
            .to_string(),
        "application has too many remembered instances"
    );
    assert!(
        store
            .enroll_instance(
                &profile.id,
                "new",
                "troy-key",
                EnrollmentActor {
                    github_user_id: 101,
                    github_login: "troy-barnes".into()
                }
            )
            .is_err()
    );
    assert_eq!(store.profile(&profile.id).unwrap().unwrap(), want);
    assert_eq!(
        store
            .prune_idle_instances(&profile.id, Utc::now(), &BTreeSet::new())
            .unwrap(),
        0
    );
    assert!(
        store
            .set_instance_revoked(&profile.id, "revoked-0", false)
            .unwrap()
    );
    store
        .enroll_instance(
            &profile.id,
            "revoked-0",
            "abed-key",
            EnrollmentActor {
                github_user_id: 102,
                github_login: "abed-nadir".into(),
            },
        )
        .unwrap();
    store
        .remember_tunnel(&profile.id, "revoked-0", "abed-and-troy", true)
        .unwrap();
    assert_eq!(
        store.profile(&profile.id).unwrap().unwrap().instances.len(),
        MAX_INSTANCES
    );
    assert_eq!(
        store
            .remember_tunnel(&profile.id, "missing", "invalid", true)
            .unwrap_err()
            .to_string(),
        "application instance authorization no longer exists"
    );
    let mut cloned = store.profile(&profile.id).unwrap().unwrap();
    cloned.settings.routes[0].methods.clear();
    cloned.instances.clear();
    assert_eq!(
        store.profile(&profile.id).unwrap().unwrap().instances.len(),
        MAX_INSTANCES
    );
    assert_eq!(
        store.profile(&profile.id).unwrap().unwrap().settings.routes[0].methods,
        ["GET"]
    );
}

#[test]
fn concurrent_reservations_are_not_lost() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path().join("server.json")).unwrap();
    let profile = store.create_profile(settings(42)).unwrap();
    std::thread::scope(|scope| {
        for index in 0..16 {
            let store = &store;
            let id = &profile.id;
            scope.spawn(move || {
                store
                    .remember_tunnel(
                        id,
                        &format!("installation-{index}"),
                        &format!("greendale-{index}"),
                        false,
                    )
                    .unwrap()
            });
        }
    });
    assert_eq!(
        store.profile(&profile.id).unwrap().unwrap().instances.len(),
        16
    );
    assert_eq!(
        Store::open(directory.path().join("server.json"))
            .unwrap()
            .profile(&profile.id)
            .unwrap(),
        store.profile(&profile.id).unwrap()
    );
}
