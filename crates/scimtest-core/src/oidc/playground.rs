use super::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlaygroundInput {
    pub user_id: String,
    pub login_identifier: String,
    pub faults: Option<Faults>,
    pub refresh: bool,
}

pub async fn playground(
    store: Store,
    id: String,
    base: String,
    mut input: PlaygroundInput,
) -> Result<Value> {
    let directory = tokio::task::spawn_blocking(move || store.directory(&id))
        .await
        .map_err(|_| ProtocolError::new("server_error", "could not load environment"))??;
    let environment = &directory.environment;
    let settings = &environment.settings;
    if !settings.supports_oidc() {
        return Err(ProtocolError::new("invalid_request", "OIDC is not enabled"));
    }
    input.faults = input.faults.map(Faults::normalized).transpose()?;
    if let Some(faults) = &input.faults {
        if !faults.saml_status.is_empty() {
            return Err(ProtocolError::new(
                "invalid_request",
                "saml_status is not valid for an OIDC playground flow",
            ));
        }
        if faults.assertion_ttl.is_some() {
            return Err(ProtocolError::new(
                "invalid_request",
                "assertion_ttl is not valid for an OIDC playground flow",
            ));
        }
        for fault in &faults.tamper {
            if fault.starts_with("logout_") || {
                [
                    "wrong_destination",
                    "wrong_recipient",
                    "in_response_to_mismatch",
                    "replayed_assertion",
                    "xsw_assertion",
                    "xsw_response",
                    "nameid_comment",
                ]
                .contains(&fault.as_str())
            } {
                return Err(ProtocolError::new(
                    "invalid_request",
                    &format!("tamper {fault} is not valid for an OIDC playground flow"),
                ));
            }
        }
    }
    let base = base.trim_end_matches('/');
    let callback = format!(
        "{base}/inspect/oidc/{}/playground/callback",
        environment.slug
    );
    let prefix = format!("{base}/oidc/{}", environment.slug);
    let state = random_secret(16);
    let nonce = random_secret(16);
    let verifier = random_secret(32);
    let mut values = Parameters::from([
        ("response_type".into(), "code".into()),
        ("client_id".into(), settings.oidc_client_id.clone()),
        ("redirect_uri".into(), callback.clone()),
        (
            "scope".into(),
            if input.refresh {
                "openid profile email groups offline_access".into()
            } else {
                "openid profile email groups".into()
            },
        ),
        ("state".into(), state.clone()),
        ("nonce".into(), nonce),
        ("user_id".into(), input.user_id),
        ("login_identifier".into(), input.login_identifier),
    ]);
    if settings.oidc_public_client {
        values.insert(
            "code_challenge".into(),
            URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())),
        );
        values.insert("code_challenge_method".into(), "S256".into());
    }
    if let Some(faults) = input.faults {
        if let Some(ttl) = faults.id_token_ttl {
            values.insert("fault_id_token_ttl".into(), ttl);
        }
        if let Some(skew) = faults.clock_skew {
            values.insert("fault_clock_skew".into(), skew);
        }
        if faults.break_signature {
            values.insert("fault_break_signature".into(), "true".into());
        }
        values.insert("fault_drop_claims".into(), faults.drop_claims.join(","));
        values.insert("fault_token_error".into(), faults.token_error);
        values.insert("fault_tamper".into(), faults.tamper.join(","));
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(http_error)?;
    let response = client
        .get(format!("{prefix}/authorize"))
        .query(&values)
        .send()
        .await
        .map_err(http_error)?;
    let mut result = json!({"authorize_status":response.status().as_u16(),"state":state});
    let location = response
        .headers()
        .get("location")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| url::Url::parse(value).ok());
    let body = read(response, 64 << 10).await?;
    let Some(location) = location else {
        result["error"] = json!(if body.is_empty() {
            "authorize response carried no code".into()
        } else {
            String::from_utf8_lossy(&body).into_owned()
        });
        return Ok(result);
    };
    let query = location.query_pairs().collect::<HashMap<_, _>>();
    if let Some(error) = query.get("error") {
        result["error"] = json!(format!(
            "{error}: {}",
            query
                .get("error_description")
                .map(|value| value.as_ref())
                .unwrap_or_default()
        ));
        return Ok(result);
    }
    let code = query
        .get("code")
        .map(|value| value.as_ref())
        .unwrap_or_default();
    if code.is_empty() {
        result["error"] = json!("authorize response carried no code");
        return Ok(result);
    }
    result["code"] = json!(code);
    let mut credentials = Parameters::from([("client_id".into(), settings.oidc_client_id.clone())]);
    if !settings.oidc_public_client {
        credentials.insert("client_secret".into(), settings.oidc_client_secret.clone());
    }
    let mut form = credentials.clone();
    form.extend([
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code.into()),
        ("redirect_uri".into(), callback),
    ]);
    if settings.oidc_public_client {
        form.insert("code_verifier".into(), verifier);
    }
    let (status, token) = exchange(&client, &prefix, &form).await?;
    result["token_status"] = json!(status);
    result["token"] = token.clone();
    if !(200..300).contains(&status) {
        result["error"] = token
            .get("error")
            .cloned()
            .unwrap_or(json!("token exchange failed"));
        return Ok(result);
    }
    if let Some((header, claims)) = decode_jwt(&token["id_token"]) {
        result["id_token_header"] = header;
        result["id_token_claims"] = claims;
    }
    if let Some((header, claims)) = decode_jwt(&token["access_token"]) {
        result["access_token_header"] = header;
        result["access_token_claims"] = claims;
    }
    let access = token["access_token"].as_str().unwrap_or_default();
    if access.is_empty() {
        result["error"] = json!("token response carried no access token");
        return Ok(result);
    }
    let response = client
        .get(format!("{prefix}/userinfo"))
        .bearer_auth(access)
        .send()
        .await
        .map_err(http_error)?;
    result["userinfo_status"] = json!(response.status().as_u16());
    result["userinfo"] =
        serde_json::from_slice(&read(response, 1 << 20).await?).map_err(Error::Json)?;
    if input.refresh {
        let mut form = credentials;
        form.extend([
            ("grant_type".into(), "refresh_token".into()),
            (
                "refresh_token".into(),
                token["refresh_token"].as_str().unwrap_or_default().into(),
            ),
        ]);
        let (status, refresh) = exchange(&client, &prefix, &form).await?;
        result["refresh_status"] = json!(status);
        if let Some((_, claims)) = decode_jwt(&refresh["id_token"]) {
            result["refreshed_id_token_claims"] = claims;
        }
        result["refresh"] = refresh;
    }
    Ok(result)
}
async fn exchange(
    client: &reqwest::Client,
    prefix: &str,
    form: &Parameters,
) -> Result<(u16, Value)> {
    let response = client
        .post(format!("{prefix}/token"))
        .form(form)
        .send()
        .await
        .map_err(http_error)?;
    let status = response.status().as_u16();
    let body = read(response, 1 << 20).await?;
    let value = serde_json::from_slice(&body).map_err(Error::from)?;
    Ok((status, value))
}
async fn read(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(http_error)? {
        if body.len() + chunk.len() > limit {
            return Err(ProtocolError::new(
                "server_error",
                "response body too large",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
fn http_error(error: reqwest::Error) -> ProtocolError {
    ProtocolError {
        status: 502,
        ..ProtocolError::new("server_error", &error.to_string())
    }
}
fn decode_jwt(token: &Value) -> Option<(Value, Value)> {
    let parts = token.as_str()?.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return None;
    }
    Some((
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).ok()?).ok()?,
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).ok()?).ok()?,
    ))
}
