use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    net::{Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use tokio::{runtime::Handle, sync::oneshot, task::JoinHandle};
use uuid::Uuid;

use crate::{Store, api};
mod instance;
mod options;
mod ports;
mod shutdown;
pub use instance::{Instance, Launch};
pub use options::{Options, version};

pub async fn wait_for_termination() -> Result<()> {
    shutdown::signal().await
}

pub struct Runtime {
    pub store: Store,
    pub identity: crate::oidc::Identity,
    pub scim: crate::scim::Service,
    pub tunnel: crate::tunnel::Service,
    pub url: String,
    pub state_file: PathBuf,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
    public_shutdown: Option<oneshot::Sender<()>>,
    public_task: Option<JoinHandle<std::io::Result<()>>>,
    lease: File,
    activation: tokio::sync::watch::Sender<u64>,
    force_shutdown: tokio_util::sync::CancellationToken,
}

impl Runtime {
    pub fn start(options: Options, handle: &Handle) -> Result<Self> {
        let profile = crate::tunnel::Config::build_profile()?.map(|mut profile| {
            profile.require_account = false;
            profile
        });
        Self::start_with_profile(options, handle, profile)
    }

    pub fn start_desktop(options: Options, handle: &Handle) -> Result<Self> {
        Self::start_kind(
            options,
            handle,
            crate::tunnel::Config::build_profile()?,
            true,
        )
    }

    pub fn start_with_profile(
        options: Options,
        handle: &Handle,
        profile: Option<crate::tunnel::Config>,
    ) -> Result<Self> {
        Self::start_kind(options, handle, profile, false)
    }
    fn start_kind(
        options: Options,
        handle: &Handle,
        profile: Option<crate::tunnel::Config>,
        desktop: bool,
    ) -> Result<Self> {
        if let Some(profile) = &profile {
            profile.validate()?;
        }
        let state_file = options.state_path()?;
        let lease = instance::acquire(&state_file)?;
        Self::start_acquired(options, handle, profile, desktop, state_file, lease)
    }
    pub async fn launch(options: Options, handle: &Handle) -> Result<Launch> {
        let profile = crate::tunnel::Config::build_profile()?.map(|mut profile| {
            profile.require_account = false;
            profile
        });
        Self::launch_kind(options, handle, profile, false).await
    }
    pub async fn launch_desktop(options: Options, handle: &Handle) -> Result<Launch> {
        Self::launch_kind(
            options,
            handle,
            crate::tunnel::Config::build_profile()?,
            true,
        )
        .await
    }
    async fn launch_kind(
        options: Options,
        handle: &Handle,
        profile: Option<crate::tunnel::Config>,
        desktop: bool,
    ) -> Result<Launch> {
        if let Some(profile) = &profile {
            profile.validate()?;
        }
        let state_file = options.state_path()?;
        let required = profile
            .as_ref()
            .is_some_and(|profile| profile.require_account);
        match instance::launch(&state_file, desktop, required).await? {
            instance::Acquired::Lease(lease) => {
                Self::start_acquired(options, handle, profile, desktop, state_file, lease)
                    .map(Box::new)
                    .map(Launch::Started)
            }
            instance::Acquired::Existing(instance) => {
                if options.port != 0 || options.debug || options.debug_secrets {
                    eprintln!(
                        "Port and debug flags apply to a new instance; the running instance keeps its settings"
                    );
                }
                Ok(Launch::Existing(instance))
            }
        }
    }
    fn start_acquired(
        options: Options,
        handle: &Handle,
        profile: Option<crate::tunnel::Config>,
        desktop: bool,
        state_file: PathBuf,
        mut lease: File,
    ) -> Result<Self> {
        let store = Store::open(&state_file).context("Open state")?;
        let last = store.last_admin_port().unwrap_or_else(|error| {
            eprintln!("Load last admin port: {error}");
            String::new()
        });
        let choice = ports::resolve(
            options.port,
            &std::env::var("SCIMTEST_PORT").unwrap_or_default(),
            &std::env::var("PORT").unwrap_or_default(),
            &last,
        )?;
        let listener = ports::bind(&choice)?;
        listener.set_nonblocking(true)?;
        let bound = listener.local_addr()?.port();
        if bound != choice.port {
            eprintln!(
                "Port {} is in use; scimtest started on port {bound}; local issuer and metadata URLs use this port",
                choice.port
            );
        }
        if let Err(error) = store.remember_admin_port(bound) {
            eprintln!("Persist admin port: {error}");
        }
        let host = listener.local_addr()?.to_string();
        let url = format!("http://{host}");
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let metadata = serde_json::json!({"url": url, "token": token, "implementation": "rust-preview", "desktop":desktop,"github_account_required":profile.as_ref().is_some_and(|profile|profile.require_account),"pid":std::process::id()});
        lease.set_len(0)?;
        lease.seek(SeekFrom::Start(0))?;
        serde_json::to_writer(&mut lease, &metadata)?;
        lease.write_all(b"\n")?;
        lease.sync_all()?;
        let listener = {
            let _entered = handle.enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let _runtime_context = handle.enter();
        let public_listener = if profile.is_some() {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
            listener.set_nonblocking(true)?;
            Some(tokio::net::TcpListener::from_std(listener)?)
        } else {
            None
        };
        let public_port = public_listener
            .as_ref()
            .map(|listener| listener.local_addr().map(|address| address.port()))
            .transpose()?
            .unwrap_or_default();
        let tunnel = crate::tunnel::Service::new(store.clone(), profile, public_port)?;
        let identity = crate::oidc::Identity::new(store.clone());
        identity.diagnostics().update(
            Some(options.debug || options.debug_secrets),
            Some(true),
            Some(options.debug_secrets),
        )?;
        let scim = crate::scim::Service::new(store.clone());
        let force_shutdown = tokio_util::sync::CancellationToken::new();
        let (activation, _) = tokio::sync::watch::channel(0);
        let router = api::router_with_runtime(
            store.clone(),
            token,
            host,
            identity.clone(),
            scim.clone(),
            tunnel.clone(),
            desktop.then(|| activation.clone()),
        );
        let (public_shutdown, public_task) = if let Some(listener) = public_listener {
            let router = api::public_router(
                store.clone(),
                listener.local_addr()?.to_string(),
                identity.clone(),
                scim.clone(),
                tunnel.clone(),
            );
            let listener = shutdown::listener(listener, force_shutdown.clone());
            let (shutdown, stopped) = oneshot::channel();
            let task = handle.spawn(async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await
            });
            (Some(shutdown), Some(task))
        } else {
            (None, None)
        };
        let (shutdown, stopped) = oneshot::channel();
        let listener = shutdown::listener(listener, force_shutdown.clone());
        let task = handle.spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
        });
        let runtime = Self {
            store,
            identity,
            scim,
            tunnel,
            url,
            state_file,
            shutdown: Some(shutdown),
            task: Some(task),
            public_shutdown,
            public_task,
            lease,
            activation,
            force_shutdown,
        };
        runtime.tunnel.start()?;
        Ok(runtime)
    }
    pub fn subscribe_activation(&self) -> tokio::sync::watch::Receiver<u64> {
        self.activation.subscribe()
    }

    pub async fn shutdown(mut self) -> Result<()> {
        let tunnel = self.tunnel.shutdown().await;
        let scim = self.scim.shutdown().await;
        if let Some(shutdown) = self.public_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.shutdown.take() {
            // A closed receiver means the listener has already stopped.
            let _ = shutdown.send(());
        }
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let (local, public) = tokio::join!(
            shutdown::server(
                self.task.take(),
                "local API",
                deadline,
                &self.force_shutdown
            ),
            shutdown::server(
                self.public_task.take(),
                "public protocols",
                deadline,
                &self.force_shutdown
            )
        );
        self.lease.set_len(0)?;
        self.lease.sync_all()?;
        tunnel?;
        scim?;
        local?;
        public?;
        Ok(())
    }

    pub async fn run_until_signal(mut self) -> Result<()> {
        let outcome = tokio::select! {
            result=shutdown::wait_server(&mut self.task,"local API")=>{self.task=None;result},
            result=shutdown::wait_server(&mut self.public_task,"public protocols")=>{self.public_task=None;result},
            result=shutdown::signal()=>result,
        };
        let stopped = self.shutdown().await;
        outcome.and(stopped)
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.force_shutdown.cancel();
        if let Err(error) = self.tunnel.cancel() {
            eprintln!("Cancel tunnel: {error}");
        }
        if let Err(error) = self.scim.cancel_all() {
            eprintln!("Cancel provisioning: {error}");
        }
        if let Some(shutdown) = self.public_shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

fn default_state_path() -> Result<PathBuf> {
    let directory = dirs::config_dir().context("Find the user configuration directory")?;
    Ok(directory.join("scimtest-rust").join("state.db"))
}

fn canonical_state_path(path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    if std::fs::symlink_metadata(&absolute).is_ok() {
        let path = absolute.canonicalize()?;
        let file = File::open(&path)?;
        validate_private_file(&file).context("Inspect state file")?;
        return Ok(path);
    }
    let parent = absolute
        .parent()
        .context("State file needs a parent directory")?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent)?;
    Ok(parent.canonicalize()?.join(
        absolute
            .file_name()
            .context("State file needs a filename")?,
    ))
}

fn validate_private_file(file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "File must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // geteuid has no preconditions and does not modify process state.
        let uid = unsafe { libc::geteuid() };
        anyhow::ensure!(
            metadata.uid() == uid && metadata.nlink() == 1,
            "File must be owned by the current user with a single hard link"
        );
    }
    Ok(())
}

fn lock_instance(file: &File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        // The file descriptor stays open for the runtime's lifetime.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        file.try_lock().map_err(std::io::Error::from)
    }
}
