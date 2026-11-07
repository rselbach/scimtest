use crate::{Error, Store};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use rusqlite::params;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct InstallationIdentity {
    pub instance_id: String,
    key: SigningKey,
}
impl InstallationIdentity {
    pub fn public_key(&self) -> String {
        STANDARD.encode(self.key.verifying_key().as_bytes())
    }
    pub fn fingerprint(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.key.verifying_key().as_bytes()))
    }
    pub fn sign_challenge(&self, profile: &str, challenge: &str) -> Vec<u8> {
        let payload = format!(
            "scimtest-server-instance-registration-v1\n{profile}\n{}\n{}\n{challenge}",
            self.public_key(),
            self.instance_id
        );
        self.key.sign(payload.as_bytes()).to_bytes().to_vec()
    }
}
impl Store {
    pub fn installation_identity(&self) -> Result<InstallationIdentity, Error> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let values = crate::persistence::config_values(&transaction, None)?;
        let instance_id = values
            .get("tunnel_instance_id")
            .or_else(|| values.get("rgrok_instance_id"))
            .filter(|value| valid_uuid(value))
            .cloned()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let seed = values
            .get("tunnel_instance_key")
            .and_then(|value| STANDARD.decode(value.replace(['\r', '\n'], "")).ok())
            .and_then(|seed| <[u8; 32]>::try_from(seed).ok())
            .unwrap_or_else(new_seed);
        persist(&transaction, &instance_id, &seed)?;
        transaction.commit()?;
        Ok(InstallationIdentity {
            instance_id,
            key: SigningKey::from_bytes(&seed),
        })
    }
    pub fn rotate_installation_identity(&self) -> Result<InstallationIdentity, Error> {
        let instance_id = uuid::Uuid::new_v4().to_string();
        let seed = new_seed();
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        persist(&transaction, &instance_id, &seed)?;
        transaction.execute("DELETE FROM config WHERE key = 'rgrok_instance_id'", [])?;
        transaction.commit()?;
        Ok(InstallationIdentity {
            instance_id,
            key: SigningKey::from_bytes(&seed),
        })
    }
}
fn persist(
    transaction: &rusqlite::Transaction<'_>,
    id: &str,
    seed: &[u8; 32],
) -> Result<(), Error> {
    for (key, value) in [
        ("tunnel_instance_id", id.to_owned()),
        ("tunnel_instance_key", STANDARD.encode(seed)),
    ] {
        transaction.execute("INSERT INTO config(key,value) VALUES (?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key,value])?;
    }
    Ok(())
}
fn new_seed() -> [u8; 32] {
    let mut seed = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    seed
}
fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && [8, 13, 18, 23]
            .iter()
            .all(|index| value.as_bytes()[*index] == b'-')
        && uuid::Uuid::parse_str(value).is_ok()
}
