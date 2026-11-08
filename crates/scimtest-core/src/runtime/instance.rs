use super::*;
use serde::Deserialize;
use std::io::Read;

pub enum Launch {
    Started(Box<Runtime>),
    Existing(Instance),
}
#[derive(Deserialize)]
pub struct Instance {
    pub url: String,
    token: String,
    #[serde(default)]
    implementation: String,
    #[serde(default)]
    desktop: Option<bool>,
    #[serde(default)]
    github_account_required: bool,
}
pub(super) enum Acquired {
    Lease(File),
    Existing(Instance),
}
impl Instance {
    pub async fn open(&self) -> Result<()> {
        if self.implementation == "rust-preview" && self.desktop != Some(true) {
            return Ok(());
        }
        if self.implementation == "rust-preview" && self.desktop == Some(true) {
            let response = client()?
                .post(format!("{}/-/activate", self.url.trim_end_matches('/')))
                .header("X-Scimtest-Instance-Token", &self.token)
                .send()
                .await
                .context("Activate running scimtest")?;
            anyhow::ensure!(
                response.status() == reqwest::StatusCode::NO_CONTENT,
                "running scimtest could not activate its window"
            );
            return Ok(());
        }
        let mut command = if cfg!(target_os = "macos") {
            let mut command = std::process::Command::new("open");
            command.arg(&self.url);
            command
        } else if cfg!(target_os = "windows") {
            let mut command = std::process::Command::new("rundll32");
            command.args(["url.dll,FileProtocolHandler", &self.url]);
            command
        } else {
            let mut command = std::process::Command::new("xdg-open");
            command.arg(&self.url);
            command
        };
        let mut child = command.spawn().context("Open running scimtest")?;
        std::thread::spawn(move || match child.wait() {
            Ok(status) if !status.success() => eprintln!("Browser opener exited with {status}"),
            Err(error) => eprintln!("Wait for browser opener: {error}"),
            _ => {}
        });
        Ok(())
    }
    async fn ready(&self, client: &reqwest::Client) -> Result<()> {
        let response = client
            .get(format!("{}/-/ready", self.url.trim_end_matches('/')))
            .header("X-Scimtest-Instance-Token", &self.token)
            .send()
            .await
            .context("Contact running scimtest")?;
        anyhow::ensure!(
            response.status() == reqwest::StatusCode::NO_CONTENT,
            "running scimtest is not ready"
        );
        Ok(())
    }
    fn read(file: &mut File) -> Result<Self> {
        let size = file.metadata()?.len();
        anyhow::ensure!(
            (1..=4096).contains(&size),
            "instance metadata has an invalid size"
        );
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = vec![0; size as usize];
        file.read_exact(&mut bytes)?;
        let instance: Self = serde_json::from_slice(&bytes).context("Decode instance metadata")?;
        let url = url::Url::parse(&instance.url).context("Parse instance URL")?;
        let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
        anyhow::ensure!(
            url.scheme() == "http"
                && (host == "localhost"
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback()))
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && matches!(url.path(), "" | "/"),
            "instance metadata contains an invalid loopback URL"
        );
        anyhow::ensure!(
            !instance.token.trim().is_empty(),
            "instance metadata is missing its token"
        );
        Ok(instance)
    }
}
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_millis(250))
        .build()
        .context("Create instance readiness client")
}
fn open(state_file: &Path) -> Result<File> {
    let mut lock_name = state_file.as_os_str().to_owned();
    lock_name.push(".lock");
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(PathBuf::from(lock_name))
        .context("Open instance lock")?;
    validate_private_file(&file).context("Inspect instance lock")?;
    Ok(file)
}
fn try_acquire(file: &File) -> Result<bool> {
    match lock_instance(file) {
        Ok(()) => {
            file.set_len(0)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error).context("Lock state file"),
    }
}
pub(super) fn acquire(state_file: &Path) -> Result<File> {
    let file = open(state_file)?;
    anyhow::ensure!(
        try_acquire(&file)?,
        "Another scimtest instance is using this state file"
    );
    Ok(file)
}
pub(super) async fn launch(state_file: &Path, desktop: bool, required: bool) -> Result<Acquired> {
    let mut file = open(state_file)?;
    let client = client()?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if try_acquire(&file)? {
            return Ok(Acquired::Lease(file));
        }
        let last = match Instance::read(&mut file) {
            Ok(instance) => match instance.ready(&client).await {
                Ok(()) => {
                    let native = instance.desktop.unwrap_or(instance.github_account_required);
                    anyhow::ensure!(
                        !desktop || native,
                        "scimtest is already running without a native desktop; stop it before launching the desktop app"
                    );
                    anyhow::ensure!(
                        !required || instance.github_account_required,
                        "scimtest is already running without GitHub account protection; stop it before launching this desktop build"
                    );
                    return Ok(Acquired::Existing(instance));
                }
                Err(error) => error.to_string(),
            },
            Err(error) => error.to_string(),
        };
        anyhow::ensure!(
            tokio::time::Instant::now() < deadline,
            "another scimtest process is running but its API is unavailable: {last}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn options(directory: &tempfile::TempDir) -> Options {
        Options {
            state_file: Some(directory.path().join("state.db")),
            ..Default::default()
        }
    }
    #[tokio::test]
    async fn a_second_launch_authenticates_and_activates_the_running_desktop_without_opening_state()
    {
        let temporary = tempfile::tempdir().unwrap();
        let options = options(&temporary);
        let runtime = Runtime::start_kind(options.clone(), &Handle::current(), None, true).unwrap();
        let mut activations = runtime.subscribe_activation();
        let database = rusqlite::Connection::open(&runtime.state_file).unwrap();
        database.execute_batch("PRAGMA user_version=7").unwrap();
        let metadata = std::fs::read(temporary.path().join("state.db.lock")).unwrap();
        let result = Runtime::launch_kind(options, &Handle::current(), None, true)
            .await
            .unwrap();
        let Launch::Existing(instance) = result else {
            panic!("second launch must hand off");
        };
        assert_eq!(instance.url, runtime.url);
        instance.open().await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), activations.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*activations.borrow_and_update(), 1);
        assert_eq!(
            database
                .query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            7
        );
        assert!(!temporary.path().join("backups").exists());
        assert_eq!(
            std::fs::read(temporary.path().join("state.db.lock")).unwrap(),
            metadata
        );
        database.execute_batch("PRAGMA user_version=8").unwrap();
        runtime.shutdown().await.unwrap();
    }
    #[tokio::test]
    async fn desktop_handoff_preserves_account_protection_and_rejects_headless_instances() {
        for desktop in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let options = options(&temporary);
            let runtime =
                Runtime::start_kind(options.clone(), &Handle::current(), None, desktop).unwrap();
            let profile = crate::tunnel::Config {
                server_base_url: "http://127.0.0.1:9".into(),
                application_profile_id: "0123456789abcdef0123456789abcdef".into(),
                require_account: true,
            };
            let result =
                Runtime::launch_kind(options, &Handle::current(), Some(profile), true).await;
            let message = match result {
                Err(error) => error.to_string(),
                Ok(_) => panic!("desktop protection must not be bypassed"),
            };
            assert!(
                message.contains(if desktop {
                    "without GitHub account protection"
                } else {
                    "without a native desktop"
                }),
                "{message}"
            );
            runtime.shutdown().await.unwrap();
        }
    }
    #[tokio::test]
    async fn launch_takes_over_when_the_starting_process_releases_its_lease() {
        let temporary = tempfile::tempdir().unwrap();
        let options = options(&temporary);
        let file = acquire(&options.state_path().unwrap()).unwrap();
        let release = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(file);
        });
        let result = Runtime::launch_kind(options, &Handle::current(), None, false)
            .await
            .unwrap();
        let Launch::Started(runtime) = result else {
            panic!("released lease must be acquired");
        };
        release.await.unwrap();
        runtime.shutdown().await.unwrap();
    }
    #[test]
    fn instance_metadata_accepts_go_records_and_rejects_nonlocal_or_oversized_values() {
        let mut file = tempfile::tempfile().unwrap();
        for url in [
            "https://127.0.0.1:8080",
            "http://citycollege.example",
            "http://127.0.0.1:8080?token=secret",
            "http://troy@127.0.0.1:8080",
        ] {
            file.set_len(0).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            serde_json::to_writer(
                &mut file,
                &serde_json::json!({"url":url,"token":"greendale"}),
            )
            .unwrap();
            assert!(Instance::read(&mut file).is_err(), "{url}");
        }
        file.set_len(0).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        serde_json::to_writer(&mut file,&serde_json::json!({"url":"http://127.0.0.1:8080","token":"greendale","github_account_required":true})).unwrap();
        let instance = Instance::read(&mut file).unwrap();
        assert!(instance.github_account_required);
        assert!(instance.implementation.is_empty());
        file.set_len(4097).unwrap();
        assert!(Instance::read(&mut file).is_err());
    }
}
