use base64::{Engine, engine::general_purpose::STANDARD};

pub fn public_key(seed: u8) -> String {
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
    let mut blob = Vec::from(11_u32.to_be_bytes());
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&32_u32.to_be_bytes());
    blob.extend_from_slice(key.as_bytes());
    format!("ssh-ed25519 {}", STANDARD.encode(blob))
}
