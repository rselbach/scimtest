use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[cfg(test)]
mod tests;

pub const MAX_BODY: usize = 32 << 20;
pub const MAX_MESSAGE: usize = MAX_BODY.div_ceil(3) * 4 + (1 << 20);

pub fn max_message_bytes(max_body: i64) -> i64 {
    if max_body <= 0 {
        return 1 << 20;
    }
    let blocks = max_body / 3 + i64::from(max_body % 3 != 0);
    blocks.saturating_mul(4).saturating_add(1 << 20)
}

pub fn application_challenge_payload(profile: &str, instance: &str, challenge: &str) -> Vec<u8> {
    format!("scimtest-server-application-registration-v1\n{profile}\n{instance}\n{challenge}")
        .into_bytes()
}

pub fn instance_challenge_payload(
    profile: &str,
    key: &str,
    legacy: &str,
    challenge: &str,
) -> Vec<u8> {
    format!("scimtest-server-instance-registration-v1\n{profile}\n{key}\n{legacy}\n{challenge}")
        .into_bytes()
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(default)]
pub struct Message {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tunnel_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub public_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_ip: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub github_user_id: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub github_login: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub local_port: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub application_profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub instance_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub instance_public_key: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub enrollment_supported: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub challenge: String,
    #[serde(with = "bytes", skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub enrollment_grant: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub enrollment_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub enrollment_browser_handoff_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub enrollment_status_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub enrollment_device_code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub enrollment_verification_code: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub enrollment_poll_seconds: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub stream_id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub host: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub scheme: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub header: BTreeMap<String, Vec<String>>,
    #[serde(with = "bytes", skip_serializing_if = "Vec::is_empty")]
    pub body: Vec<u8>,
    #[serde(skip_serializing_if = "is_zero")]
    pub status_code: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

impl Message {
    /// Decode Go-compatible field names in wire order, retaining the last value.
    pub fn decode(json: &[u8]) -> Result<Self, serde_json::Error> {
        use serde::de::{MapAccess, Visitor};
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = serde_json::Map<String, serde_json::Value>;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a tunnel message")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(Default::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut fields = serde_json::Map::new();
                while let Some((key, mut value)) = map.next_entry::<String, serde_json::Value>()? {
                    let key: String = key
                        .chars()
                        .map(|ch| match ch {
                            'ſ' => 's',
                            'K' => 'k',
                            ch => ch.to_ascii_lowercase(),
                        })
                        .collect();
                    if value.is_null() {
                        continue;
                    }
                    if key == "header"
                        && let Some(headers) = value.as_object_mut()
                    {
                        for values in headers.values_mut() {
                            if values.is_null() {
                                *values = serde_json::json!([]);
                            }
                            if let Some(values) = values.as_array_mut() {
                                for value in values {
                                    if value.is_null() {
                                        *value = "".into();
                                    }
                                }
                            }
                        }
                    }
                    fields.insert(key, value);
                }
                Ok(fields)
            }
        }
        let mut decoder = serde_json::Deserializer::from_slice(json);
        let fields = serde::Deserializer::deserialize_any(&mut decoder, Fields)?;
        decoder.end()?;
        serde_json::from_value(serde_json::Value::Object(fields))
    }
}
fn is_zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}
mod bytes {
    use base64::{
        Engine, alphabet,
        engine::{GeneralPurpose, GeneralPurposeConfig, general_purpose::STANDARD},
    };
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::Null => Ok(Vec::new()),
            serde_json::Value::String(value) => GeneralPurpose::new(
                &alphabet::STANDARD,
                GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
            )
            .decode(value.replace(['\r', '\n'], ""))
            .map_err(serde::de::Error::custom),
            serde_json::Value::Array(values) => values
                .into_iter()
                .map(|value| {
                    if value.is_null() {
                        return Ok(0);
                    }
                    value
                        .as_u64()
                        .and_then(|value| value.try_into().ok())
                        .ok_or_else(|| serde::de::Error::custom("invalid byte value"))
                })
                .collect(),
            _ => Err(serde::de::Error::custom(
                "expected a base64 string or byte array",
            )),
        }
    }
}
