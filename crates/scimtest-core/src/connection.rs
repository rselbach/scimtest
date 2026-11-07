use crate::{Error, Store};
use serde_json::{Value, json};
use std::{io::Write, path::Path};

impl Store {
    pub fn connection_config(&self, environment: &str, base: &str) -> Result<Value, Error> {
        let app = self.directory(environment)?.environment;
        let settings = &app.settings;
        let base = base.trim_end_matches('/');
        let mut result = json!({"environment": app.name, "slug": app.slug});
        if settings.supports_oidc() {
            let issuer = format!("{base}/oidc/{}", app.slug);
            let mut oidc = json!({
                "issuer": issuer,
                "discovery_url": format!("{issuer}/.well-known/openid-configuration"),
                "authorize_url": format!("{issuer}/authorize"),
                "token_url": format!("{issuer}/token"),
                "userinfo_url": format!("{issuer}/userinfo"),
                "jwks_url": format!("{issuer}/jwks"),
                "introspection_url": format!("{issuer}/introspect"),
                "revocation_url": format!("{issuer}/revoke"),
                "client_id": settings.oidc_client_id,
                "public_client": settings.oidc_public_client,
                "jwt_access_tokens": settings.oidc_jwt_access_tokens
            });
            if !settings.oidc_public_client && !settings.oidc_client_secret.is_empty() {
                oidc["client_secret"] = json!(settings.oidc_client_secret);
            }
            if !settings.oidc_redirect_uris.is_empty() {
                oidc["redirect_uris"] = json!(settings.oidc_redirect_uris);
            }
            if settings.oidc_jwt_access_tokens {
                oidc["access_token_audience"] =
                    json!(if settings.oidc_access_token_audience.is_empty() {
                        &settings.oidc_client_id
                    } else {
                        &settings.oidc_access_token_audience
                    });
            }
            result["oidc"] = oidc;
        }
        if settings.supports_saml() {
            let prefix = format!("{base}/saml/{}", app.slug);
            let metadata = format!("{prefix}/metadata");
            let mut saml = json!({
                "sso_url": format!("{prefix}/sso"), "slo_url": format!("{prefix}/slo"),
                "idp_entity_id": metadata, "metadata_url": metadata,
                "certificate_pem": self.active_signing_key(environment)?.stored.certificate_pem,
                "name_id_format": crate::saml::name_id_format(&app)
            });
            for (name, value) in [
                ("sp_entity_id", &settings.saml_entity_id),
                ("acs_url", &settings.saml_acs_url),
                ("sp_slo_url", &settings.saml_slo_url),
                ("audience", &settings.saml_audience),
            ] {
                if !value.is_empty() {
                    saml[name] = json!(value);
                }
            }
            result["saml"] = saml;
        }
        Ok(result)
    }

    pub fn write_connection_config(
        &self,
        environment: &str,
        base: &str,
        path: &Path,
    ) -> Result<(), Error> {
        let data = serde_json::to_vec_pretty(&self.connection_config(environment, base)?)?;
        let temporary = path.parent().unwrap_or(Path::new(".")).join(format!(
            ".scimtest-config-{}",
            uuid::Uuid::new_v4().simple()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        let write = (|| {
            file.write_all(&data)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)
        })();
        if let Err(error) = write {
            std::fs::remove_file(&temporary).map_err(|cleanup| {
                std::io::Error::other(format!("{error}; remove incomplete config: {cleanup}"))
            })?;
            return Err(error.into());
        }
        Ok(())
    }
}
