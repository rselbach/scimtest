use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub(super) const MAX_FEED_BYTES: usize = 64 * 1024;
const SIGNING_CONTEXT: &[u8] = b"scimtest-update-feed-v1\n";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Artifact {
    pub os: String,
    pub arch: String,
    pub kind: String,
    pub minimum_os: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Release {
    pub schema: u32,
    pub app: String,
    pub channel: String,
    pub version: String,
    pub build: u64,
    #[serde(default)]
    pub published_at: String,
    #[serde(default)]
    pub notes_url: String,
    #[serde(default, deserialize_with = "null_vector")]
    pub highlights: Vec<String>,
    #[serde(default, deserialize_with = "null_vector")]
    pub artifacts: Vec<Artifact>,
}

fn null_vector<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

impl Release {
    pub fn artifact(&self, os: &str, arch: &str, kind: &str) -> Option<&Artifact> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.os == os && artifact.arch == arch && artifact.kind == kind)
    }
}

pub fn parse_version(text: &str) -> Option<[u32; 3]> {
    let mut version = [0; 3];
    for (index, part) in text.trim().split('.').enumerate() {
        if index >= 3 || part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        version[index] = part.parse().ok()?;
    }
    Some(version)
}

pub fn verify_feed(bytes: &[u8], public_key: &str) -> Result<Release> {
    ensure!(bytes.len() <= MAX_FEED_BYTES, "update feed is too large");
    #[derive(Deserialize)]
    struct Envelope {
        payload: String,
        signature: String,
    }
    let envelope: Envelope = serde_json::from_slice(bytes).context("Decode update envelope")?;
    let payload = STANDARD
        .decode(envelope.payload)
        .context("Decode update payload")?;
    let signature = Signature::from_slice(
        &STANDARD
            .decode(envelope.signature)
            .context("Decode update signature")?,
    )?;
    let key: [u8; 32] = STANDARD
        .decode(public_key.trim())
        .context("Decode update public key")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("update public key must be 32 bytes"))?;
    let message = [SIGNING_CONTEXT, &payload].concat();
    VerifyingKey::from_bytes(&key)?
        .verify_strict(&message, &signature)
        .context("Verify update feed signature")?;
    let release: Release = serde_json::from_slice(&payload).context("Decode verified release")?;
    validate_release(&release)?;
    Ok(release)
}

pub fn sign_feed(release: &Release, key: &SigningKey) -> Result<Vec<u8>> {
    validate_release(release)?;
    let payload = serde_json::to_vec(release)?;
    let signature = key.sign(&[SIGNING_CONTEXT, &payload].concat());
    let mut envelope = serde_json::to_vec_pretty(&serde_json::json!({
        "payload": STANDARD.encode(&payload),
        "signature": STANDARD.encode(signature.to_bytes()),
    }))?;
    envelope.push(b'\n');
    Ok(envelope)
}

fn validate_release(release: &Release) -> Result<()> {
    ensure!(release.schema == 1, "unsupported update feed schema");
    ensure!(
        release.app == super::BUNDLE_ID,
        "update feed is for another application"
    );
    ensure!(
        release.channel == "stable",
        "update feed is for another channel"
    );
    ensure!(
        release.version.len() <= 32
            && release.version.trim() == release.version
            && parse_version(&release.version).is_some(),
        "invalid update version"
    );
    ensure!(release.build > 0, "invalid update build");
    ensure!(
        release.notes_url.is_empty()
            || release
                .notes_url
                .starts_with("https://github.com/rselbach/scimtest/"),
        "invalid release notes URL"
    );
    ensure!(release.highlights.len() <= 8, "too many release highlights");
    ensure!(
        release
            .highlights
            .iter()
            .all(|text| !text.is_empty() && text.len() <= 200 && !text.contains(['\r', '\n'])),
        "invalid release highlight"
    );
    for artifact in &release.artifacts {
        ensure!(
            artifact.sha256.len() == 64
                && artifact
                    .sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "invalid update SHA-256"
        );
        ensure!(
            artifact.size > 0 && artifact.size <= 2 << 30,
            "invalid update size"
        );
        ensure!(
            parse_version(&artifact.minimum_os).is_some(),
            "invalid update minimum OS version"
        );
        let url = url::Url::parse(&artifact.url).context("Parse update URL")?;
        let tail = artifact
            .url
            .strip_prefix("https://github.com/rselbach/scimtest/releases/download/");
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
                && tail.is_some_and(|tail| !tail.is_empty()
                    && !tail.split('/').any(|part| matches!(part, "." | ".."))),
            "invalid update artifact URL"
        );
    }
    Ok(())
}
