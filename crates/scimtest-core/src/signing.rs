use std::sync::Arc;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Datelike, Duration, NaiveDate, Utc};
use rand::RngCore;
use rsa::{
    RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey},
    pkcs1v15::{Signature, SigningKey as RsaSigner, VerifyingKey},
    pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding},
    signature::{RandomizedSigner, SignatureEncoding, Verifier},
    traits::PublicKeyParts,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{Error, Store, persistence};

#[derive(Clone, Deserialize, Serialize)]
pub struct StoredSigningKey {
    pub kid: String,
    pub private_key_pem: String,
    pub certificate_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_until: Option<DateTime<Utc>>,
}

pub struct SigningKey {
    pub stored: StoredSigningKey,
    pub private: Arc<RsaPrivateKey>,
    pub certificate: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SigningKeyView {
    pub kid: String,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_until: Option<String>,
    pub not_before: String,
    pub not_after: String,
    pub certificate_pem: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateValidity {
    #[default]
    Standard,
    Expired,
    NotYetValid,
    NoExpiration,
    ZeroTime,
}

impl CertificateValidity {
    pub fn parse(value: &str) -> Result<Self, Error> {
        match value.trim() {
            "" | "standard" => Ok(Self::Standard),
            "expired" => Ok(Self::Expired),
            "not_yet_valid" => Ok(Self::NotYetValid),
            "no_expiration" => Ok(Self::NoExpiration),
            "zero_time" => Ok(Self::ZeroTime),
            _ => Err(Error::Validation(format!(
                "certificate validity {value:?} is not standard, expired, not_yet_valid, no_expiration, or zero_time"
            ))),
        }
    }

    fn period(self, now: DateTime<Utc>) -> Result<(DateTime<Utc>, DateTime<Utc>), Error> {
        let at = |year, month, day, hour, minute, second| {
            NaiveDate::from_ymd_opt(year, month, day)
                .and_then(|date| date.and_hms_opt(hour, minute, second))
                .map(|date| date.and_utc())
                .ok_or_else(|| Error::Crypto("Certificate date is out of range".into()))
        };
        let years = |offset| -> Result<DateTime<Utc>, Error> {
            let first = NaiveDate::from_ymd_opt(now.year() + offset, now.month(), 1)
                .ok_or_else(|| Error::Crypto("Certificate date is out of range".into()))?;
            Ok((first + Duration::days(i64::from(now.day() - 1)))
                .and_time(now.time())
                .and_utc())
        };
        Ok(match self {
            Self::Standard => (now - Duration::hours(1), years(10)?),
            Self::Expired => (years(-1)?, now - Duration::days(1)),
            Self::NotYetValid => (years(1)?, years(11)?),
            Self::NoExpiration => (now - Duration::hours(1), at(9999, 12, 31, 23, 59, 59)?),
            Self::ZeroTime => (now - Duration::hours(1), at(1, 1, 1, 0, 0, 0)?),
        })
    }
}

pub fn parse_grace(value: &str) -> Result<Duration, Error> {
    if value.trim().is_empty() {
        return Ok(Duration::hours(24));
    }
    let nanoseconds = crate::duration::parse(value.trim()).ok_or_else(|| {
        Error::Validation(format!(
            "grace period {value:?} is not a duration such as 24h"
        ))
    })?;
    let grace = Duration::nanoseconds(nanoseconds);
    if grace < Duration::zero() || grace > Duration::days(7) {
        return Err(Error::Validation(
            "grace period must be between 0s and 168h0m0s".into(),
        ));
    }
    Ok(grace)
}

fn crypto(error: impl std::fmt::Display) -> Error {
    Error::Crypto(error.to_string())
}

impl SigningKey {
    pub fn parse(stored: StoredSigningKey) -> Result<Self, Error> {
        let private = RsaPrivateKey::from_pkcs1_pem(&stored.private_key_pem)
            .or_else(|_| RsaPrivateKey::from_pkcs8_pem(&stored.private_key_pem))
            .map_err(crypto)?;
        private.validate().map_err(crypto)?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(stored.certificate_pem.trim().as_bytes())
            .map_err(crypto)?;
        if pem.label != "CERTIFICATE" {
            return Err(Error::Crypto(
                "Signing certificate PEM block is required".into(),
            ));
        }
        x509_parser::parse_x509_certificate(&pem.contents).map_err(crypto)?;
        Ok(Self {
            stored,
            private: Arc::new(private),
            certificate: pem.contents,
        })
    }

    pub fn generate(
        kid: String,
        validity: CertificateValidity,
        now: DateTime<Utc>,
    ) -> Result<Self, Error> {
        let private = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).map_err(crypto)?;
        let pkcs8 = private.to_pkcs8_pem(LineEnding::LF).map_err(crypto)?;
        let pair = rcgen::KeyPair::from_pkcs8_pem_and_sign_algo(&pkcs8, &rcgen::PKCS_RSA_SHA256)
            .map_err(crypto)?;
        let (before, after) = validity.period(now)?;
        let mut distinguished_name = rcgen::DistinguishedName::new();
        distinguished_name.push(rcgen::DnType::CommonName, "scimtest local signing");
        let mut serial = [0; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut serial)
            .map_err(crypto)?;
        let mut parameters = rcgen::CertificateParams::default();
        parameters.not_before =
            time::OffsetDateTime::from_unix_timestamp(before.timestamp()).map_err(crypto)?;
        parameters.not_after =
            time::OffsetDateTime::from_unix_timestamp(after.timestamp()).map_err(crypto)?;
        parameters.distinguished_name = distinguished_name;
        parameters.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
        parameters.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let certificate = parameters.self_signed(&pair).map_err(crypto)?;
        Ok(Self {
            stored: StoredSigningKey {
                kid,
                private_key_pem: private
                    .to_pkcs1_pem(LineEnding::LF)
                    .map_err(crypto)?
                    .to_string(),
                certificate_pem: certificate.pem(),
                created_at: Some(now),
                published_until: None,
            },
            private: Arc::new(private),
            certificate: certificate.der().to_vec(),
        })
    }

    pub fn jwk(&self) -> Value {
        json!({"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.stored.kid,
            "n": URL_SAFE_NO_PAD.encode(self.private.n().to_bytes_be()), "e": URL_SAFE_NO_PAD.encode(self.private.e().to_bytes_be())})
    }

    pub fn sign_jwt(&self, claims: &Value, typ: &str) -> Result<String, Error> {
        self.sign_jwt_with_header(
            claims,
            &json!({"alg": "RS256", "typ": typ, "kid": self.stored.kid}),
        )
    }

    pub fn sign_jwt_with_header(&self, claims: &Value, header: &Value) -> Result<String, Error> {
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(header)?),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims)?)
        );
        let signature = RsaSigner::<Sha256>::new((*self.private).clone())
            .sign_with_rng(&mut rand::rngs::OsRng, input.as_bytes());
        Ok(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    pub fn verify_jwt(&self, token: &str) -> Result<Value, Error> {
        let parts = token.split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(Error::Validation("Invalid JWT".into()));
        }
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).map_err(crypto)?)?;
        if header["alg"] != "RS256" {
            return Err(Error::Validation("JWT algorithm must be RS256".into()));
        }
        let signature =
            Signature::try_from(URL_SAFE_NO_PAD.decode(parts[2]).map_err(crypto)?.as_slice())
                .map_err(crypto)?;
        VerifyingKey::<Sha256>::new(RsaPublicKey::from(self.private.as_ref()))
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .map_err(crypto)?;
        Ok(serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(parts[1]).map_err(crypto)?,
        )?)
    }

    pub fn view(&self, active: bool) -> Result<SigningKeyView, Error> {
        let (_, certificate) =
            x509_parser::parse_x509_certificate(&self.certificate).map_err(crypto)?;
        let date = |timestamp| {
            DateTime::<Utc>::from_timestamp(timestamp, 0)
                .map(format_time)
                .ok_or_else(|| Error::Crypto("Certificate date is out of range".into()))
        };
        Ok(SigningKeyView {
            kid: self.stored.kid.clone(),
            active,
            created_at: self
                .stored
                .created_at
                .filter(|date| date.year() > 1)
                .map(format_time),
            published_until: self
                .stored
                .published_until
                .filter(|date| date.year() > 1)
                .map(format_time),
            not_before: date(certificate.validity().not_before.timestamp())?,
            not_after: date(certificate.validity().not_after.timestamp())?,
            certificate_pem: self.stored.certificate_pem.clone(),
        })
    }
}

fn format_time(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

impl Store {
    pub fn shared_signing_key(&self) -> Result<SigningKey, Error> {
        let mut connection = self.connection()?;
        let values = persistence::config_values(&connection, None)?;
        let private = values
            .get("signing_private_key_pem")
            .cloned()
            .unwrap_or_default();
        let certificate = values
            .get("signing_certificate_pem")
            .cloned()
            .unwrap_or_default();
        if !private.trim().is_empty() && !certificate.trim().is_empty() {
            return SigningKey::parse(StoredSigningKey {
                kid: "scimtest-dev".into(),
                private_key_pem: private,
                certificate_pem: certificate,
                created_at: None,
                published_until: None,
            });
        }
        let mut key = SigningKey::generate(
            "scimtest-dev".into(),
            CertificateValidity::Standard,
            Utc::now(),
        )?;
        key.stored.created_at = None;
        let transaction = connection.transaction()?;
        transaction.execute("INSERT INTO config VALUES ('signing_private_key_pem', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [&key.stored.private_key_pem])?;
        transaction.execute("INSERT INTO config VALUES ('signing_certificate_pem', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [&key.stored.certificate_pem])?;
        transaction.commit()?;
        Ok(key)
    }

    pub fn published_signing_keys(
        &self,
        environment: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<SigningKey>, Error> {
        let directory = self.directory(environment)?;
        let ring: Vec<StoredSigningKey> = directory
            .config
            .get("signing_keys")
            .filter(|value| !value.is_empty())
            .map(|value| serde_json::from_str(value))
            .transpose()?
            .unwrap_or_default();
        if ring.is_empty() {
            return Ok(vec![self.shared_signing_key()?]);
        }
        let last = ring.len() - 1;
        ring.into_iter()
            .enumerate()
            .rev()
            .filter(|(index, stored)| {
                *index == last || stored.published_until.is_some_and(|until| now < until)
            })
            .map(|(_, stored)| SigningKey::parse(stored))
            .collect()
    }

    pub fn active_signing_key(&self, environment: &str) -> Result<SigningKey, Error> {
        let directory = self.directory(environment)?;
        let mut ring: Vec<StoredSigningKey> = directory
            .config
            .get("signing_keys")
            .filter(|value| !value.is_empty())
            .map(|value| serde_json::from_str(value))
            .transpose()?
            .unwrap_or_default();
        match ring.pop() {
            Some(key) => SigningKey::parse(key),
            None => self.shared_signing_key(),
        }
    }

    pub fn signing_key_views(&self, environment: &str) -> Result<Vec<SigningKeyView>, Error> {
        self.published_signing_keys(environment, Utc::now())?
            .iter()
            .enumerate()
            .map(|(index, key)| key.view(index == 0))
            .collect()
    }

    pub fn rotate_signing_key(
        &self,
        environment: &str,
        grace: Duration,
        validity: CertificateValidity,
    ) -> Result<Vec<SigningKeyView>, Error> {
        if grace < Duration::zero() || grace > Duration::days(7) {
            return Err(Error::Validation(
                "grace period must be between 0s and 168h0m0s".into(),
            ));
        }
        self.directory(environment)?;
        let now = Utc::now();
        let new = SigningKey::generate(crate::store::new_id("scimtest"), validity, now)?;
        let shared = self.shared_signing_key()?.stored;
        self.edit(environment, |directory| {
            let mut ring: Vec<StoredSigningKey> = directory
                .config
                .get("signing_keys")
                .filter(|value| !value.is_empty())
                .map(|value| serde_json::from_str(value))
                .transpose()?
                .unwrap_or_default();
            if ring.is_empty() {
                ring.push(shared);
            }
            if let Some(active) = ring.last_mut() {
                active.published_until = Some(now + grace);
            }
            ring.retain(|stored| stored.published_until.is_some_and(|until| now < until));
            ring.push(new.stored);
            directory
                .config
                .insert("signing_keys".into(), serde_json::to_string(&ring)?);
            Ok(())
        })?;
        self.signing_key_views(environment)
    }
}
