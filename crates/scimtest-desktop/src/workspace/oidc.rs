use super::Workspace;
pub(super) mod view;
use gpui::Context;
use scimtest_core::oidc::{Faults, Identity, PlaygroundInput, ProtocolError};
use serde_json::Value;

#[derive(Default)]
pub(super) struct Inspector {
    user: String,
    section: &'static str,
    keys: Vec<scimtest_core::signing::SigningKeyView>,
    fault: &'static str,
    refresh: bool,
    result: Option<Value>,
    pub inspections: Vec<Value>,
    pub sessions: Vec<Value>,
    holders: Vec<Value>,
    flows: Vec<Value>,
}
impl Workspace {
    pub(super) fn refresh_identity(&mut self, cx: &mut Context<Self>) {
        let Some(id) = self.selected.clone() else {
            return;
        };
        if self.identity_refreshing || self.busy {
            self.identity_refresh_pending = true;
            return;
        }
        self.identity_refreshing = true;
        self.identity_refresh_pending = false;
        let identity = self.identity.clone();
        let store = self.store.clone();
        let requested_id = id.clone();
        cx.spawn(async move |view, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    let id = requested_id;
                    let settings = store.directory(&id)?.environment.settings;
                    let saml = settings.supports_saml();
                    Ok::<_, ProtocolError>(Snapshot {
                        inspections: identity.inspections(&id)?,
                        sessions: identity.sessions(&id)?,
                        holders: identity.token_holders(&id)?,
                        flows: identity.flows(&id)?,
                        keys: if saml || settings.supports_oidc() {
                            store.signing_key_views(&id)?
                        } else {
                            Vec::new()
                        },
                        saml_inspections: if saml {
                            identity.saml_inspections(&id)?
                        } else {
                            Vec::new()
                        },
                        saml_logouts: if saml {
                            identity.saml_logouts(&id)?
                        } else {
                            Vec::new()
                        },
                        presets: identity.resilience_presets(&id)?,
                        run: identity.resilience_run(&id)?,
                        manual: identity.faults(&id)?,
                        lifecycle: identity.lifecycle_runs(&id)?,
                    })
                })
                .await;
            let _ = view.update(cx, |view, cx| {
                view.identity_refreshing = false;
                if view.selected.as_ref() == Some(&id) {
                    match result {
                        Ok(snapshot) => {
                            view.oidc.inspections = snapshot.inspections;
                            view.oidc.sessions = snapshot.sessions;
                            view.oidc.holders = snapshot.holders;
                            view.oidc.flows = snapshot.flows;
                            view.oidc.keys = snapshot.keys;
                            view.saml.inspections = snapshot.saml_inspections;
                            view.saml.logouts = snapshot.saml_logouts;
                            view.resilience.presets = snapshot.presets;
                            view.resilience.run = snapshot.run;
                            view.resilience.manual = snapshot.manual;
                            view.lifecycle.runs = snapshot.lifecycle;
                        }
                        Err(error) => {
                            view.message = error.description;
                            view.failed = true;
                        }
                    }
                } else {
                    view.identity_refresh_pending = true;
                }
                if view.identity_refresh_pending {
                    view.refresh_identity(cx);
                }
                cx.notify();
            });
        })
        .detach();
    }
    pub(super) fn identity_command(
        &mut self,
        action: impl FnOnce(Identity, String) -> Result<String, ProtocolError> + Send + 'static,
        cx: &mut Context<Self>,
    ) {
        let Some(id) = self.selected.clone() else {
            return;
        };
        if self.busy {
            return;
        }
        self.busy = true;
        self.identity_refresh_pending = false;
        let identity = self.identity.clone();
        let requested_id = id.clone();
        cx.spawn(async move |view, cx| {
            let result = cx
                .background_executor()
                .spawn(async move {
                    let id = requested_id;
                    action(identity, id)
                })
                .await;
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                if view.selected.as_ref() != Some(&id) {
                    cx.notify();
                    return;
                }
                view.status_revision = view.status_revision.wrapping_add(1);
                match result {
                    Ok(message) => {
                        if matches!(
                            view.editor,
                            Some(super::Editor::Faults(_) | super::Editor::Lifecycle(_))
                        ) {
                            view.editor = None;
                        }
                        if !message.is_empty() {
                            view.message = message;
                            view.failed = false;
                        }
                    }
                    Err(error) => {
                        view.message = error.description;
                        view.failed = true;
                    }
                }
                view.refresh_identity(cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
    pub(super) fn run_oidc(&mut self, cx: &mut Context<Self>) {
        if self.busy {
            return;
        }
        let Some(directory) = self.directory() else {
            return;
        };
        let user = directory
            .projected_users()
            .into_iter()
            .filter(|user| user.fields.active && !user.deleted)
            .min_by_key(|user| user.id != self.oidc.user);
        let Some(user) = user else {
            self.message = "Select an active user to run sign-in".into();
            self.failed = true;
            cx.notify();
            return;
        };
        let id = directory.environment.id.clone();
        let input = PlaygroundInput {
            user_id: user.id,
            login_identifier: user.fields.email,
            refresh: self.oidc.refresh,
            faults: fault(self.oidc.fault),
        };
        let store = self.store.clone();
        let base = self.api_url.clone();
        let handle = self.executor.clone();
        let request_id = id.clone();
        self.busy = true;
        cx.spawn(async move |view, cx| {
            let result = handle
                .spawn(scimtest_core::oidc::playground(
                    store, request_id, base, input,
                ))
                .await;
            let _ = view.update(cx, |view, cx| {
                view.busy = false;
                if view.selected.as_ref() != Some(&id) {
                    cx.notify();
                    return;
                }
                view.status_revision = view.status_revision.wrapping_add(1);
                match result {
                    Ok(Ok(result)) => {
                        view.failed = result.get("error").is_some();
                        view.message = result["error"]
                            .as_str()
                            .unwrap_or("Sign-in completed")
                            .into();
                        view.oidc.result = Some(result);
                    }
                    Ok(Err(error)) => {
                        view.failed = true;
                        view.message = error.description;
                    }
                    Err(error) => {
                        view.failed = true;
                        view.message = error.to_string();
                    }
                }
                view.refresh_identity(cx);
                cx.notify();
            });
        })
        .detach();
        cx.notify();
    }
}

struct Snapshot {
    inspections: Vec<Value>,
    sessions: Vec<Value>,
    holders: Vec<Value>,
    flows: Vec<Value>,
    keys: Vec<scimtest_core::signing::SigningKeyView>,
    saml_inspections: Vec<Value>,
    saml_logouts: Vec<Value>,
    presets: Vec<scimtest_core::oidc::ResiliencePreset>,
    run: Option<scimtest_core::oidc::ResilienceRun>,
    manual: Faults,
    lifecycle: Vec<scimtest_core::oidc::LifecycleRun>,
}

fn fault(name: &str) -> Option<Faults> {
    let mut fault = Faults::default();
    match name {
        "Expired ID token" => fault.id_token_ttl = Some("-1m".into()),
        "Broken signature" => fault.break_signature = true,
        "Missing email" => fault.drop_claims = vec!["email".into()],
        "Wrong audience" => fault.tamper = vec!["wrong_audience".into()],
        "Unsigned token" => fault.tamper = vec!["alg_none".into()],
        "Token endpoint error" => fault.token_error = "temporarily_unavailable".into(),
        _ => return None,
    }
    Some(fault)
}
