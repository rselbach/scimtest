mod feed;
#[cfg(target_os = "macos")]
mod macos;
mod service;
mod transport;

pub use feed::{Artifact, Release, parse_version, verify_feed};
#[cfg(target_os = "macos")]
pub use macos::MacInstaller;
pub use service::{Config, Install, Installer, Platform, Snapshot, Staged, Status, Updater};
pub use transport::{download, http_client, read_feed};

pub const FEED_URL: &str = "https://rselbach.github.io/scimtest/update.json";
pub const PUBLIC_KEY: &str = "2obyIySbPw8xSuXQwzSw2sCbOixUww08jk95se82unc=";
pub const BUNDLE_ID: &str = "com.rselbach.scimtest";
pub const CODE_REQUIREMENT: &str = include_str!("../../../internal/update/requirement.txt");

#[derive(Debug, thiserror::Error)]
#[error(
    "the update is installed, but scimtest could not restart; quit and reopen it. The previous app is at {previous}: {source}"
)]
pub struct Stranded {
    pub previous: std::path::PathBuf,
    pub source: anyhow::Error,
}
