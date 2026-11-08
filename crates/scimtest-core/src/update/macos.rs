use super::*;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawFd,
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};

const PREFIX: &str = ".scimtest-update-";
const RECEIPT: &str = "receipt.json";
const APP_NAME: &str = "scimtest.app";
const WAITER: &str = r#"pid="$1"; shift; i=0
while /bin/kill -0 "$pid" 2>/dev/null; do
  i=$((i + 1))
  if [ "$i" -gt 600 ]; then exit 1; fi
  /bin/sleep 0.1
done
exec "$@""#;

pub struct MacInstaller {
    bundle: PathBuf,
    current: Install,
    verify: fn(&Path, &Release, [u32; 3]) -> Result<()>,
    relaunch: fn(&Path) -> Result<()>,
}

#[derive(Serialize, Deserialize, PartialEq)]
struct Receipt {
    installed: PathBuf,
    build: u64,
}

struct Bundle {
    folder: PathBuf,
    app: PathBuf,
    installed: PathBuf,
    release: Release,
    receipt: File,
}
impl Staged for Bundle {
    fn build(&self) -> u64 {
        self.release.build
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl MacInstaller {
    pub fn running() -> Result<(Install, Self)> {
        let executable = std::env::current_exe()?.canonicalize()?;
        let macos = executable.parent().context("Locate MacOS directory")?;
        let contents = macos.parent().context("Locate Contents directory")?;
        let bundle = contents.parent().context("Locate application bundle")?;
        ensure!(
            macos.file_name().is_some_and(|name| name == "MacOS")
                && contents.file_name().is_some_and(|name| name == "Contents")
                && bundle
                    .extension()
                    .is_some_and(|extension| extension == "app"),
            "scimtest is not running from an application bundle"
        );
        let plist = bundle.join("Contents/Info.plist");
        ensure!(
            plist_value(&plist, "CFBundleIdentifier")? == BUNDLE_ID,
            "this is not the scimtest application bundle"
        );
        let output = Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .context("Read macOS version")?;
        ensure!(output.status.success(), "read macOS version failed");
        let os_version = parse_version(std::str::from_utf8(&output.stdout)?)
            .context("Unrecognized macOS version")?;
        let current = Install {
            version: plist_value(&plist, "CFBundleShortVersionString")?,
            build: plist_value(&plist, "CFBundleVersion")?
                .parse()
                .context("Read application build")?,
            os_version,
        };
        Ok((
            current.clone(),
            Self {
                bundle: bundle.into(),
                current,
                verify: verify_bundle,
                relaunch: relaunch_after_exit,
            },
        ))
    }
}

impl Installer for MacInstaller {
    fn replaceable(&self) -> bool {
        use std::ffi::CString;
        if !self.bundle.is_absolute()
            || self.bundle.to_string_lossy().contains("/AppTranslocation/")
        {
            return false;
        }
        [
            self.bundle.as_path(),
            self.bundle.parent().unwrap_or(&self.bundle),
        ]
        .iter()
        .all(|path| {
            use std::os::unix::ffi::OsStrExt;
            CString::new(path.as_os_str().as_bytes())
                .is_ok_and(|path| unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 })
        })
    }

    fn stage(&self, archive: &Path, release: &Release) -> Result<Arc<dyn Staged>> {
        let installed = self
            .bundle
            .canonicalize()
            .context("Resolve installed application")?;
        let parent = installed
            .parent()
            .context("Find installed application directory")?;
        let folder = tempfile::Builder::new()
            .prefix(&format!("{PREFIX}{}-", release.build))
            .tempdir_in(parent)?;
        let receipt = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(folder.path().join(RECEIPT))?;
        lock(&receipt)?;
        let mut receipt = receipt;
        serde_json::to_writer(
            &mut receipt,
            &Receipt {
                installed: installed.clone(),
                build: release.build,
            },
        )?;
        receipt.flush()?;
        receipt.sync_all()?;
        let output = Command::new("/usr/bin/ditto")
            .args(["-x", "-k"])
            .arg(archive)
            .arg(folder.path())
            .output()
            .context("Unpack update archive")?;
        ensure!(
            output.status.success(),
            "unpack update: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let app = folder.path().join(APP_NAME);
        (self.verify)(&app, release, self.current.os_version)?;
        Ok(Arc::new(Bundle {
            folder: folder.keep(),
            app,
            installed,
            release: release.clone(),
            receipt,
        }))
    }

    fn apply(&self, staged: &dyn Staged, relaunch: bool) -> Result<()> {
        let staged = staged
            .as_any()
            .downcast_ref::<Bundle>()
            .context("Not a staged scimtest application")?;
        let bundle_lock = File::open(&staged.installed).context("Open installed application")?;
        lock(&bundle_lock)?;
        let held = bundle_lock.metadata()?;
        let current = std::fs::symlink_metadata(&staged.installed)?;
        ensure!(
            same_file(&held, &current)
                && plist_value(
                    &staged.installed.join("Contents/Info.plist"),
                    "CFBundleVersion"
                )? == self.current.build.to_string(),
            "the installed app is no longer the running build"
        );
        check_owned(staged)?;
        (self.verify)(&staged.app, &staged.release, self.current.os_version)?;
        swap(&staged.app, &staged.installed)?;
        if relaunch && let Err(error) = (self.relaunch)(&staged.installed) {
            if let Err(rollback) = swap(&staged.app, &staged.installed) {
                return Err(Stranded {
                    previous: staged.app.clone(),
                    source: error.context(format!("undoing the swap failed: {rollback:#}")),
                }
                .into());
            }
            return Err(error);
        }
        Ok(())
    }

    fn discard(&self, staged: &dyn Staged) {
        let discard = || -> Result<()> {
            let staged = staged
                .as_any()
                .downcast_ref::<Bundle>()
                .context("Not a staged scimtest application")?;
            check_owned(staged)?;
            remove_folder(&staged.folder)
        };
        if let Err(error) = discard() {
            eprintln!("Discard update: {error:#}");
        }
    }

    fn remove_leftovers(&self) {
        let cleanup = || -> Result<()> {
            let installed = self.bundle.canonicalize()?;
            for entry in std::fs::read_dir(installed.parent().context("Find app directory")?)? {
                let entry = entry?;
                if !entry.file_type()?.is_dir()
                    || !entry.file_name().to_string_lossy().starts_with(PREFIX)
                {
                    continue;
                }
                let folder = entry.path();
                let receipt = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(folder.join(RECEIPT));
                let Ok(receipt) = receipt else {
                    continue;
                };
                if !receipt.metadata()?.is_file() || lock(&receipt).is_err() {
                    continue;
                }
                let found: Result<Receipt, _> = serde_json::from_reader((&receipt).take(4096));
                if found.is_ok_and(|found| found.installed == installed) {
                    remove_folder(&folder)?;
                }
            }
            Ok(())
        };
        if let Err(error) = cleanup() {
            eprintln!("Clean earlier updates: {error:#}");
        }
    }
}

fn same_file(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.ino() == b.ino() && a.dev() == b.dev()
}

fn lock(file: &File) -> Result<()> {
    for attempt in 0..10 {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(error).context("Lock application update");
        }
        if attempt < 9 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    anyhow::bail!("another scimtest process is using this update")
}

fn check_owned(bundle: &Bundle) -> Result<()> {
    let held = bundle.receipt.metadata()?;
    let path = bundle.folder.join(RECEIPT);
    ensure!(
        same_file(&held, &std::fs::symlink_metadata(&path)?),
        "the staged update lost its receipt"
    );
    let found: Receipt = serde_json::from_reader(File::open(path)?.take(4096))?;
    ensure!(
        found
            == Receipt {
                installed: bundle.installed.clone(),
                build: bundle.release.build
            },
        "the staged update belongs to another installation"
    );
    Ok(())
}

fn remove_folder(folder: &Path) -> Result<()> {
    ensure!(
        folder
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(PREFIX)),
        "refuse to remove a folder that is not an update"
    );
    std::fs::remove_dir_all(folder).context("Remove update folder")
}

fn swap(a: &Path, b: &Path) -> Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let a = CString::new(a.as_os_str().as_bytes())?;
    let b = CString::new(b.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("Swap application update");
    }
    Ok(())
}

fn relaunch_after_exit(bundle: &Path) -> Result<()> {
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            WAITER,
            "scimtest-relaunch",
            &std::process::id().to_string(),
            "/usr/bin/open",
        ])
        .arg(bundle)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Start update relauncher")?;
    std::thread::spawn(move || {
        if let Err(error) = child.wait() {
            eprintln!("Wait for update relauncher: {error}");
        }
    });
    Ok(())
}

fn plist_value(plist: &Path, key: &str) -> Result<String> {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-"])
        .arg(plist)
        .output()
        .context("Read application metadata")?;
    ensure!(
        output.status.success(),
        "application metadata is missing {key}"
    );
    Ok(std::str::from_utf8(&output.stdout)?.trim().into())
}

fn verify_bundle(app: &Path, release: &Release, os_version: [u32; 3]) -> Result<()> {
    ensure!(
        std::fs::symlink_metadata(app)?.is_dir(),
        "update has no scimtest.app directory"
    );
    let plist = app.join("Contents/Info.plist");
    ensure!(
        plist_value(&plist, "CFBundleIdentifier")? == BUNDLE_ID,
        "update is for another application"
    );
    ensure!(
        plist_value(&plist, "CFBundleShortVersionString")? == release.version,
        "update version does not match signed release"
    );
    ensure!(
        plist_value(&plist, "CFBundleVersion")? == release.build.to_string(),
        "update build does not match signed release"
    );
    ensure!(
        parse_version(&plist_value(&plist, "LSMinimumSystemVersion")?)
            .is_some_and(|minimum| minimum <= os_version),
        "update requires a newer macOS version"
    );
    let executable = plist_value(&plist, "CFBundleExecutable")?;
    ensure!(
        !executable.is_empty() && !executable.starts_with('.') && !executable.contains('/'),
        "invalid update executable name"
    );
    let mut head = Vec::new();
    File::open(app.join("Contents/MacOS").join(executable))?
        .take(4096)
        .read_to_end(&mut head)?;
    ensure!(has_arm64(&head), "update has no arm64 executable");
    let output = Command::new("/usr/bin/codesign")
        .args(["--verify", "--deep", "--strict"])
        .arg(format!("-R={}", CODE_REQUIREMENT.trim()))
        .arg(app)
        .output()
        .context("Verify update code signature")?;
    ensure!(
        output.status.success(),
        "update is not scimtest's notarized Developer ID application: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn has_arm64(head: &[u8]) -> bool {
    let word = |offset| {
        head.get(offset..offset + 4)
            .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
    };
    match word(0) {
        Some(0xcffaedfe) => word(4).is_some_and(|cpu| cpu.swap_bytes() == 0x0100000c),
        Some(magic @ (0xcafebabe | 0xcafebabf)) => {
            let stride = if magic == 0xcafebabe { 20 } else { 32 };
            (0..word(4).unwrap_or(0).min(16) as usize)
                .any(|index| word(8 + index * stride) == Some(0x0100000c))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release() -> Release {
        Release {
            schema: 1,
            app: BUNDLE_ID.into(),
            channel: "stable".into(),
            version: "2.1.0".into(),
            build: 42,
            published_at: String::new(),
            notes_url: String::new(),
            highlights: vec![],
            artifacts: vec![],
        }
    }
    fn app(path: &Path, build: u64) {
        std::fs::create_dir_all(path.join("Contents")).unwrap();
        std::fs::write(path.join("Contents/Info.plist"), format!(r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleVersion</key><string>{build}</string></dict></plist>"#)).unwrap();
    }
    fn fixture() -> (tempfile::TempDir, MacInstaller, PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let bundle = temporary.path().join(APP_NAME);
        app(&bundle, 20);
        let source = temporary.path().join("source").join(APP_NAME);
        app(&source, 42);
        let archive = temporary.path().join("update.zip");
        assert!(
            Command::new("/usr/bin/ditto")
                .args(["-c", "-k", "--keepParent"])
                .arg(&source)
                .arg(&archive)
                .status()
                .unwrap()
                .success()
        );
        let installer = MacInstaller {
            bundle,
            current: Install {
                version: "2.0.0".into(),
                build: 20,
                os_version: [26, 0, 0],
            },
            verify: |path, release, _| {
                ensure!(
                    plist_value(&path.join("Contents/Info.plist"), "CFBundleVersion")?
                        == release.build.to_string(),
                    "update build changed"
                );
                Ok(())
            },
            relaunch: |_| Ok(()),
        };
        (temporary, installer, archive)
    }

    #[test]
    fn atomic_install_revalidates_builds_receipts_and_cleans_only_unclaimed_folders() {
        let (temporary, installer, archive) = fixture();
        let staged = installer.stage(&archive, &release()).unwrap();
        let bundle = staged.as_any().downcast_ref::<Bundle>().unwrap();
        let other = temporary.path().join(format!("{PREFIX}another-install"));
        std::fs::create_dir(&other).unwrap();
        std::fs::write(
            other.join(RECEIPT),
            serde_json::to_vec(&Receipt {
                installed: temporary.path().join("CityCollege.app"),
                build: 42,
            })
            .unwrap(),
        )
        .unwrap();
        installer.remove_leftovers();
        assert!(bundle.app.exists());
        assert!(other.exists());
        installer.apply(staged.as_ref(), false).unwrap();
        assert_eq!(
            plist_value(
                &installer.bundle.join("Contents/Info.plist"),
                "CFBundleVersion"
            )
            .unwrap(),
            "42"
        );
        assert_eq!(
            plist_value(&bundle.app.join("Contents/Info.plist"), "CFBundleVersion").unwrap(),
            "20"
        );
        assert!(installer.apply(staged.as_ref(), false).is_err());
        let folder = bundle.folder.clone();
        drop(staged);
        installer.remove_leftovers();
        assert!(!folder.exists());
        assert!(other.exists());
    }

    #[test]
    fn changed_staging_and_failed_relaunch_preserve_the_installed_application() {
        let (_temporary, mut installer, archive) = fixture();
        let staged = installer.stage(&archive, &release()).unwrap();
        let bundle = staged.as_any().downcast_ref::<Bundle>().unwrap();
        app(&bundle.app, 43);
        assert!(installer.apply(staged.as_ref(), false).is_err());
        assert_eq!(
            plist_value(
                &installer.bundle.join("Contents/Info.plist"),
                "CFBundleVersion"
            )
            .unwrap(),
            "20"
        );
        app(&bundle.app, 42);
        installer.relaunch = |_| anyhow::bail!("Greendale relaunch failed");
        assert!(installer.apply(staged.as_ref(), true).is_err());
        assert_eq!(
            plist_value(
                &installer.bundle.join("Contents/Info.plist"),
                "CFBundleVersion"
            )
            .unwrap(),
            "20"
        );
        let receipt_path = bundle.folder.join(RECEIPT);
        std::fs::remove_file(&receipt_path).unwrap();
        std::fs::write(&receipt_path, b"{}").unwrap();
        assert!(installer.apply(staged.as_ref(), false).is_err());
        assert!(bundle.app.exists());
    }

    #[test]
    fn ad_hoc_or_unsigned_apps_fail_the_real_developer_id_requirement() {
        let temporary = tempfile::tempdir().unwrap();
        let app = temporary.path().join(APP_NAME);
        std::fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        std::fs::write(app.join("Contents/Info.plist"),r#"<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.rselbach.scimtest</string><key>CFBundleVersion</key><string>42</string><key>CFBundleShortVersionString</key><string>2.1.0</string><key>CFBundleExecutable</key><string>scimtest</string><key>LSMinimumSystemVersion</key><string>26.0</string></dict></plist>"#).unwrap();
        std::fs::copy("/usr/bin/true", app.join("Contents/MacOS/scimtest")).unwrap();
        assert!(
            Command::new("/usr/bin/codesign")
                .args(["--force", "--sign", "-"])
                .arg(&app)
                .output()
                .unwrap()
                .status
                .success()
        );
        let error = verify_bundle(&app, &release(), [26, 0, 0]).unwrap_err();
        assert!(
            error.to_string().contains("notarized Developer ID"),
            "{error:#}"
        );
    }

    #[test]
    #[ignore = "requires real notarized and unnotarized macOS app fixtures"]
    fn production_verifier_accepts_notarized_app_and_rejects_signed_unnotarized_app() {
        let output = Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .unwrap();
        assert!(output.status.success());
        let os_version = parse_version(std::str::from_utf8(&output.stdout).unwrap()).unwrap();
        for (variable, accepted) in [
            ("SCIMTEST_NOTARIZED_APP", true),
            ("SCIMTEST_UNNOTARIZED_APP", false),
        ] {
            let app = PathBuf::from(std::env::var_os(variable).expect(variable));
            let plist = app.join("Contents/Info.plist");
            let mut release = release();
            release.version = plist_value(&plist, "CFBundleShortVersionString").unwrap();
            release.build = plist_value(&plist, "CFBundleVersion")
                .unwrap()
                .parse()
                .unwrap();
            let result = verify_bundle(&app, &release, os_version);
            if accepted {
                result.unwrap();
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("notarized Developer ID"),
                    "unnotarized fixture must fail the production trust requirement"
                );
            }
        }
    }
}
