use super::{Artifact, Release, feed::MAX_FEED_BYTES, verify_feed};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

pub fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(300))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let url = attempt.url();
            if attempt.previous().len() >= 10 {
                return attempt.error("too many update redirects");
            }
            if url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && matches!(
                    url.host_str(),
                    Some(
                        "github.com"
                            | "objects.githubusercontent.com"
                            | "release-assets.githubusercontent.com"
                            | "rselbach.github.io"
                    )
                )
            {
                attempt.follow()
            } else {
                attempt.error("update redirect has an untrusted destination")
            }
        }))
        .build()
        .context("Create update client")
}

pub async fn read_feed(client: &reqwest::Client, url: &str, public_key: &str) -> Result<Release> {
    let mut response = client.get(url).send().await.context("Fetch update feed")?;
    ensure!(
        response.status() == reqwest::StatusCode::OK,
        "fetch update feed: {}",
        response.status()
    );
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.context("Read update feed")? {
        ensure!(
            body.len() + chunk.len() <= MAX_FEED_BYTES,
            "update feed is too large"
        );
        body.extend_from_slice(&chunk);
    }
    verify_feed(&body, public_key)
}

pub async fn download(
    client: &reqwest::Client,
    artifact: &Artifact,
    directory: &Path,
) -> Result<PathBuf> {
    ensure!(
        artifact.size > 0
            && artifact.size <= 2 << 30
            && artifact.sha256.len() == 64
            && artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid artifact download"
    );
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(directory)
        .context("Create update downloads")?;
    let path = directory.join(format!("{}.partial", artifact.sha256));
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.path() != path
            && entry.file_type()?.is_file()
            && name.strip_suffix(".partial").is_some_and(|sum| {
                sum.len() == 64 && sum.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        {
            std::fs::remove_file(entry.path()).context("Remove superseded update download")?;
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&path).context("Open update download")?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "update download must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.nlink() == 1 && metadata.uid() == unsafe { libc::geteuid() },
            "update download must be privately owned"
        );
    }
    let mut offset = metadata.len();
    if offset >= artifact.size {
        file.set_len(0)?;
        offset = 0;
    }
    let mut request = client.get(&artifact.url);
    if offset > 0 {
        request = request.header(reqwest::header::RANGE, format!("bytes={offset}-"));
    }
    let mut response = request.send().await.context("Download update")?;
    match response.status() {
        reqwest::StatusCode::PARTIAL_CONTENT
            if offset > 0 && range_start(&response) == Some(offset) =>
        {
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::End(0))?;
        }
        reqwest::StatusCode::OK => {
            file.set_len(0)?;
            offset = 0;
        }
        status => anyhow::bail!("download update: {status}"),
    }
    while let Some(chunk) = response.chunk().await.context("Read update download")? {
        offset += chunk.len() as u64;
        if offset > artifact.size {
            drop(file);
            std::fs::remove_file(&path)?;
            anyhow::bail!("the download is larger than the signed size");
        }
        file.write_all(&chunk).context("Write update download")?;
    }
    file.sync_all()?;
    ensure!(
        offset == artifact.size,
        "incomplete update download: {offset} of {} bytes",
        artifact.size
    );
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hash.update(&buffer[..length]);
    }
    if format!("{:x}", hash.finalize()) != artifact.sha256 {
        drop(file);
        std::fs::remove_file(&path)?;
        anyhow::bail!("the download does not match the signed SHA-256");
    }
    Ok(path)
}

fn range_start(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)?
        .to_str()
        .ok()?
        .strip_prefix("bytes ")?
        .split_once('-')?
        .0
        .parse()
        .ok()
}
