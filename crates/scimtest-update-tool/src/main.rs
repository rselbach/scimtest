use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey};
use scimtest_core::update::{self, Artifact, Release};
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::PathBuf};

#[derive(Parser)]
#[command(about = "Sign scimtest update feeds and legacy Sparkle appcasts")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    SignFeed {
        #[command(flatten)]
        metadata: Metadata,
        #[arg(long, default_value = "")]
        notes_url: String,
        #[arg(long)]
        notes: Option<PathBuf>,
        #[arg(long)]
        artifact: Vec<String>,
    },
    Appcast {
        #[command(flatten)]
        metadata: Metadata,
        #[arg(long)]
        minimum_os: String,
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        url: String,
    },
}

#[derive(Args)]
struct Metadata {
    #[arg(long)]
    version: String,
    #[arg(long)]
    build: u64,
    #[arg(long)]
    published_at: String,
    #[arg(long)]
    out: PathBuf,
}

fn main() -> Result<()> {
    run(Cli::parse().command, std::io::stdin(), update::PUBLIC_KEY)
}

fn signing_key(input: impl Read, pinned: &str) -> Result<SigningKey> {
    let mut bytes = Vec::new();
    input.take(4097).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 4096, "signing seed input exceeds 4096 bytes");
    let text = std::str::from_utf8(&bytes).context("signing seed is not UTF-8")?;
    let seed: [u8; 32] = STANDARD
        .decode(text.trim())
        .context("signing seed is not base64")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("signing seed must contain 32 bytes"))?;
    let key = SigningKey::from_bytes(&seed);
    ensure!(
        STANDARD.encode(key.verifying_key().as_bytes()) == pinned.trim(),
        "signing key does not match scimtest's pinned public key"
    );
    Ok(key)
}

fn release(metadata: &Metadata) -> Result<Release> {
    DateTime::parse_from_rfc3339(&metadata.published_at)
        .context("invalid --published-at timestamp")?;
    Ok(Release {
        schema: 1,
        app: update::BUNDLE_ID.into(),
        channel: "stable".into(),
        version: metadata.version.clone(),
        build: metadata.build,
        published_at: metadata.published_at.clone(),
        notes_url: String::new(),
        highlights: Vec::new(),
        artifacts: Vec::new(),
    })
}

fn artifact(spec: &str) -> Result<Artifact> {
    let fields = spec.split(',').collect::<Vec<_>>();
    ensure!(
        fields.len() == 6,
        "--artifact needs os,arch,kind,minimum_os,FILE,URL"
    );
    let bytes = fs::read(fields[4]).context("read update artifact")?;
    Ok(Artifact {
        os: fields[0].into(),
        arch: fields[1].into(),
        kind: fields[2].into(),
        minimum_os: fields[3].into(),
        url: fields[5].into(),
        size: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
    })
}

fn run(command: Command, input: impl Read, pinned: &str) -> Result<()> {
    let key = signing_key(input, pinned)?;
    match command {
        Command::SignFeed {
            metadata,
            notes_url,
            notes,
            artifact: specs,
        } => {
            let mut release = release(&metadata)?;
            release.notes_url = notes_url;
            if let Some(path) = notes {
                release.highlights = fs::read_to_string(path)?
                    .lines()
                    .filter_map(|line| {
                        let line = line.trim();
                        let text = line
                            .strip_prefix("- ")
                            .or_else(|| line.strip_prefix("* "))?;
                        let text = text.replace("**", "").replace('`', "").trim().to_owned();
                        (!text.is_empty() && text.len() <= 200).then_some(text)
                    })
                    .take(5)
                    .collect();
            }
            release.artifacts = specs
                .iter()
                .map(|spec| artifact(spec))
                .collect::<Result<_>>()?;
            let bytes = update::sign_feed(&release, &key)?;
            update::verify_feed(&bytes, pinned)?;
            fs::write(metadata.out, bytes).context("write signed update feed")
        }
        Command::Appcast {
            metadata,
            minimum_os,
            archive,
            url,
        } => {
            let bytes = fs::read(archive).context("read Sparkle archive")?;
            let mut release = release(&metadata)?;
            release.artifacts.push(Artifact {
                os: "macos".into(),
                arch: "arm64".into(),
                kind: "app-zip".into(),
                minimum_os: minimum_os.clone(),
                url: url.clone(),
                size: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(&bytes)),
            });
            update::sign_feed(&release, &key)?;
            let published = DateTime::parse_from_rfc3339(&metadata.published_at)?
                .with_timezone(&Utc)
                .format("%a, %d %b %Y %H:%M:%S %z");
            let signature = STANDARD.encode(key.sign(&bytes).to_bytes());
            let version = xml(&metadata.version);
            let url = xml(&url);
            let minimum_os = xml(&minimum_os);
            let build = metadata.build;
            let length = bytes.len();
            let feed = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <rss version=\"2.0\" xmlns:sparkle=\"http://www.andymatuschak.org/xml-namespaces/sparkle\">\n\
                 <channel><title>scimtest</title><link>https://github.com/rselbach/scimtest</link><item>\n\
                 <title>{version}</title><pubDate>{published}</pubDate>\n\
                 <sparkle:version>{build}</sparkle:version><sparkle:shortVersionString>{version}</sparkle:shortVersionString>\n\
                 <sparkle:minimumSystemVersion>{minimum_os}</sparkle:minimumSystemVersion>\n\
                 <sparkle:hardwareRequirements>arm64</sparkle:hardwareRequirements>\n\
                 <enclosure url=\"{url}\" length=\"{length}\" type=\"application/octet-stream\" sparkle:edSignature=\"{signature}\"/>\n\
                 </item></channel></rss>\n"
            );
            fs::write(metadata.out, feed).context("write Sparkle appcast")
        }
    }
}

fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests;
