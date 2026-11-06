use scimtest_core::runtime::{Options, Runtime};
use serde_json::Value;

#[cfg(unix)]
#[tokio::test]
async fn headless_sigterm_clears_metadata_and_allows_a_clean_restart() {
    use std::process::{Command, Stdio};
    struct Runner(std::process::Child);
    impl Drop for Runner {
        fn drop(&mut self) {
            if self.0.try_wait().unwrap().is_none() {
                self.0.kill().unwrap();
                self.0.wait().unwrap();
            }
        }
    }
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let lock = temporary.path().join("state.db.lock");
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    drop(occupied);
    let mut previous_url = None;
    for _ in 0..2 {
        let mut command = Command::new(env!("CARGO_BIN_EXE_scimtest-rust"));
        command
            .arg("--no-open")
            .env("SCIMTEST_STATE_FILE", &path)
            .env("SCIMTEST_PORT", port.to_string())
            .env_remove("PORT")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit());
        let mut child = Runner(command.spawn().unwrap());
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let metadata = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if let Ok(bytes) = std::fs::read(&lock)
                    && let Ok(metadata) = serde_json::from_slice::<Value>(&bytes)
                    && let (Some(url), Some(token)) =
                        (metadata["url"].as_str(), metadata["token"].as_str())
                    && client
                        .get(format!("{url}/-/ready"))
                        .header("X-Scimtest-Instance-Token", token)
                        .send()
                        .await
                        .is_ok_and(|response| response.status() == 204)
                {
                    break metadata;
                }
                assert!(child.0.try_wait().unwrap().is_none());
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(metadata["pid"], child.0.id());
        let url = metadata["url"].as_str().unwrap().to_owned();
        if let Some(previous) = &previous_url {
            assert_eq!(previous, &url);
        }
        previous_url = Some(url);
        assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) }, 0);
        let status = tokio::time::timeout(std::time::Duration::from_secs(8), async {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(status.success(), "{status}");
        assert!(std::fs::read(&lock).unwrap().is_empty());
    }
}

#[tokio::test]
async fn runtime_publishes_private_connection_metadata_and_releases_its_lease() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let preferred = reserved.local_addr().unwrap().port();
    drop(reserved);
    let mut options = Options {
        state_file: Some(path.clone()),
        port: preferred,
        ..Default::default()
    };
    let runtime = Runtime::start(options.clone(), &tokio::runtime::Handle::current()).unwrap();
    let lock = temporary.path().join("state.db.lock");
    let metadata: Value = serde_json::from_slice(&std::fs::read(&lock).unwrap()).unwrap();
    assert_eq!(metadata["url"], runtime.url);
    assert_eq!(metadata["token"].as_str().unwrap().len(), 64);
    assert!(runtime.url.starts_with("http://127.0.0.1:"));
    assert!(Runtime::start(options.clone(), &tokio::runtime::Handle::current()).is_err());
    let original_url = runtime.url.clone();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    runtime.shutdown().await.unwrap();
    assert!(std::fs::read(&lock).unwrap().is_empty());
    options.port = 0;
    let restarted = Runtime::start(options, &tokio::runtime::Handle::current()).unwrap();
    assert_eq!(restarted.url, original_url);
    restarted.shutdown().await.unwrap();
}

#[tokio::test]
async fn explicit_ports_are_pinned_and_debug_secrets_enables_debugging() {
    let temporary = tempfile::tempdir().unwrap();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    let options = Options {
        state_file: Some(temporary.path().join("state.db")),
        port,
        debug_secrets: true,
        ..Default::default()
    };
    assert!(Runtime::start(options.clone(), &tokio::runtime::Handle::current()).is_err());
    drop(occupied);
    let runtime = Runtime::start(options, &tokio::runtime::Handle::current()).unwrap();
    assert_eq!(url::Url::parse(&runtime.url).unwrap().port(), Some(port));
    let settings = runtime.identity.diagnostics().settings().unwrap();
    assert!(settings.debug && settings.record && settings.record_secrets);
    let database = rusqlite::Connection::open(&runtime.state_file).unwrap();
    assert_eq!(
        database
            .query_row(
                "SELECT value FROM config WHERE key='last_admin_port'",
                [],
                |row| row.get::<_, String>(0)
            )
            .unwrap(),
        port.to_string()
    );
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_bounds_stalled_requests_and_releases_the_listener_and_instance_lease() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let temporary = tempfile::tempdir().unwrap();
    let options = Options {
        state_file: Some(temporary.path().join("state.db")),
        ..Default::default()
    };
    let runtime = Runtime::start(options.clone(), &tokio::runtime::Handle::current()).unwrap();
    let metadata: Value =
        serde_json::from_slice(&std::fs::read(temporary.path().join("state.db.lock")).unwrap())
            .unwrap();
    let address = url::Url::parse(&runtime.url).unwrap();
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", address.port().unwrap()))
        .await
        .unwrap();
    let request = format!(
        "POST /api/v1/environments HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Scimtest-Instance-Token: {}\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n{{",
        address.port().unwrap(),
        metadata["token"].as_str().unwrap()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let store = runtime.store.clone();
    tokio::time::timeout(std::time::Duration::from_secs(7), runtime.shutdown())
        .await
        .unwrap()
        .unwrap();
    let mut bytes = Vec::new();
    let drained = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        stream.read_to_end(&mut bytes),
    )
    .await
    .unwrap();
    assert!(
        drained.is_ok()
            || matches!(
                drained.as_ref().unwrap_err().kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            )
    );
    assert!(store.snapshot().unwrap().is_empty());
    let restarted = Runtime::start(options, &tokio::runtime::Handle::current()).unwrap();
    restarted.shutdown().await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn instance_lock_precedes_migration_and_rejects_unsafe_aliases() {
    use std::{
        fs::OpenOptions,
        os::{fd::AsRawFd, unix::fs::symlink},
    };
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("state.db");
    drop(scimtest_core::Store::open(&path).unwrap());
    let database = rusqlite::Connection::open(&path).unwrap();
    database.execute_batch("PRAGMA user_version = 7").unwrap();
    let lock_path = temporary.path().join("state.db.lock");
    let lease = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let options = Options {
        state_file: Some(path.clone()),
        port: 0,
        ..Default::default()
    };
    assert!(Runtime::start(options.clone(), &tokio::runtime::Handle::current()).is_err());
    assert_eq!(
        database
            .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert!(!temporary.path().join("backups").exists());
    drop(lease);
    std::fs::remove_file(&lock_path).unwrap();
    let victim = temporary.path().join("victim");
    std::fs::write(&victim, "preserve this content").unwrap();
    symlink(&victim, &lock_path).unwrap();
    assert!(Runtime::start(options.clone(), &tokio::runtime::Handle::current()).is_err());
    assert_eq!(
        std::fs::read_to_string(&victim).unwrap(),
        "preserve this content"
    );
    std::fs::remove_file(&lock_path).unwrap();
    let alias = temporary.path().join("alias.db");
    std::fs::hard_link(&path, &alias).unwrap();
    assert!(Runtime::start(options.clone(), &tokio::runtime::Handle::current()).is_err());
    std::fs::remove_file(&alias).unwrap();
    let runtime = Runtime::start(options, &tokio::runtime::Handle::current()).unwrap();
    symlink(&path, &alias).unwrap();
    assert!(
        Runtime::start(
            Options {
                state_file: Some(alias),
                port: 0,
                ..Default::default()
            },
            &tokio::runtime::Handle::current()
        )
        .is_err()
    );
    runtime.shutdown().await.unwrap();
}
