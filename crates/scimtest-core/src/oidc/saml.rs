use super::*;
use super::{
    authorize::Request,
    claims::{MFA_CONTEXTS, PASSWORD_CONTEXTS},
};
use crate::saml::{ResponseContext, build_response, name_id, name_id_format, resolve_request};
use base64::engine::general_purpose::STANDARD;

pub enum SamlAuthorization {
    Chooser {
        directory: Box<Directory>,
        options: ChooserOptions,
    },
    Response {
        acs_url: String,
        saml_response: String,
        relay_state: String,
        session: String,
    },
}
impl Identity {
    pub fn saml_sign_in(
        &self,
        slug: &str,
        values: &Parameters,
        cookie: &str,
        base: &str,
        raw_query: &str,
        post: bool,
    ) -> Result<SamlAuthorization> {
        let directory = self.0.store.directory_by_slug(slug)?;
        if !directory.environment.settings.supports_saml() {
            return Err(ProtocolError {
                status: 404,
                ..ProtocolError::new("not_found", "SAML is not enabled")
            });
        }
        let environment = &directory.environment;
        let parsed = resolve_request(environment, base, values, raw_query)?;
        let request = Request {
            fresh_reason: if parsed.force_authn {
                "ForceAuthn".into()
            } else {
                String::new()
            },
            contexts: parsed.contexts,
            ..Default::default()
        };
        let now = Utc::now();
        let mut memory = self.memory()?;
        memory.prune(now);
        let remembered = memory
            .sessions
            .get(cookie)
            .filter(|session| {
                session.environment == environment.id
                    && active_user(&directory, &session.user).is_some()
            })
            .cloned();
        let mut context = ResponseContext {
            acs_url: parsed.acs_url,
            in_response_to: parsed.id,
            assertion_id: String::new(),
            session_index: String::new(),
            authn_time: now,
            authn_context: PASSWORD_CONTEXTS[0].into(),
        };
        if truthy(param(values, "deny")) {
            let key = self.0.store.active_signing_key(&environment.id)?;
            let posted = build_response(
                &directory,
                &User::default(),
                &key,
                base,
                &context,
                &Faults {
                    saml_status: "AuthnFailed".into(),
                    ..Default::default()
                },
            )?;
            memory.protocol_event(
                &environment.id,
                "saml",
                "sso",
                "failed",
                "",
                "user denied the request (AuthnFailed)",
            );
            return Ok(SamlAuthorization::Response {
                acs_url: context.acs_url,
                saml_response: STANDARD.encode(posted.xml),
                relay_state: param(values, "RelayState").into(),
                session: String::new(),
            });
        }
        let reuse = truthy(param(values, "continue_session"));
        let selection = reuse
            || if environment.settings.chooser_mode == "identifier" {
                !param(values, "login_identifier").trim().is_empty()
            } else {
                !param(values, "user_id").trim().is_empty()
            };
        let chooser = !selection
            && (!post
                || !param(values, "SAMLRequest").is_empty()
                || !param(values, "login_hint").is_empty()
                || !param(values, "RelayState").is_empty());
        if chooser {
            let options = request.chooser_options(
                &directory,
                values,
                remembered.as_ref(),
                now,
                &parsed.login_hint,
            );
            return Ok(SamlAuthorization::Chooser {
                directory: Box::new(directory),
                options,
            });
        }
        let (user, mut authn) = if reuse {
            let session = request.reused_session(remembered.as_ref(), now)?;
            (
                active_user(&directory, &session.user).unwrap(),
                session.authn.clone(),
            )
        } else {
            let user = selected_user(&directory, values)
                .ok_or_else(|| ProtocolError::new("invalid_request", "active user is required"))?;
            (user, request.authentication(values, now)?)
        };
        let contexts = if authn.strength == "mfa" {
            MFA_CONTEXTS
        } else {
            PASSWORD_CONTEXTS
        };
        authn.context = request
            .contexts
            .iter()
            .find(|context| contexts.contains(&context.as_str()))
            .map(String::as_str)
            .unwrap_or(contexts[0])
            .into();
        let faults = memory.flow_faults(&environment.id, values);
        context.assertion_id = if faults.tampers("replayed_assertion") {
            memory
                .saml_inspections
                .get(&environment.id)
                .into_iter()
                .flatten()
                .find_map(|entry| {
                    entry["AssertionID"]
                        .as_str()
                        .filter(|value| !value.is_empty())
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| crate::store::new_id("saml-assertion"))
        } else {
            crate::store::new_id("saml-assertion")
        };
        let mut session =
            memory.join_session(environment, user, authn.clone(), cookie, "saml", now);
        if session.saml_index.is_empty() {
            session.saml_index = crate::store::new_id("saml-session");
        }
        session.saml_name_id = name_id(environment, user).into();
        session.saml_name_id_format = name_id_format(environment);
        memory.sessions.insert(session.id.clone(), session.clone());
        context.session_index = session.saml_index.clone();
        context.authn_time = authn.time;
        context.authn_context = authn.context;
        let key = self.0.store.active_signing_key(&environment.id)?;
        let posted = build_response(&directory, user, &key, base, &context, &faults)?;
        if let Some((groups, carried)) =
            posted.group_values(&environment.settings.saml_attribute_mappings.groups)
        {
            memory.note_groups(
                &directory,
                &user.id,
                "saml",
                "SAML assertion",
                &context.acs_url,
                lifecycle::IssuedGroups {
                    groups,
                    carried,
                    overage: false,
                },
            );
        }
        let encoded = STANDARD.encode(&posted.xml);
        let entries = memory
            .saml_inspections
            .entry(environment.id.clone())
            .or_default();
        entries.insert(0,json!({"User":label(user),"ACSURL":context.acs_url,"InResponseTo":context.in_response_to,"AssertionID":posted.assertion_id,
            "ResponseXML":posted.xml,"PlaintextAssertionXML":posted.plaintext_assertion,"EncodedResponse":encoded,"Faults":faults.describe(),"UpdatedAt":now.to_rfc3339_opts(chrono::SecondsFormat::Secs,true)}));
        entries.truncate(10);
        memory.protocol_event(
            &environment.id,
            "saml",
            "sso",
            "ok",
            &label(user),
            &format!("Signed response posted to {}", context.acs_url),
        );
        Ok(SamlAuthorization::Response {
            acs_url: context.acs_url,
            saml_response: encoded,
            relay_state: param(values, "RelayState").into(),
            session: session.id,
        })
    }
    pub fn saml_inspections(&self, id: &str) -> Result<Vec<Value>> {
        if !self
            .0
            .store
            .directory(id)?
            .environment
            .settings
            .supports_saml()
        {
            return Err(ProtocolError::new("invalid_request", "SAML is not enabled"));
        }
        Ok(self
            .memory()?
            .saml_inspections
            .get(id)
            .cloned()
            .unwrap_or_default())
    }
    pub fn record_saml_failure(&self, slug: &str, stage: &str, detail: &str) -> Result<()> {
        let directory = self.0.store.directory_by_slug(slug)?;
        self.memory()?.protocol_event(
            &directory.environment.id,
            "saml",
            stage,
            "failed",
            "",
            detail,
        );
        Ok(())
    }
}
