use super::{authorize::Request, *};

pub struct ChooserOptions {
    pub login_hint: String,
    pub selected_user_id: String,
    pub selected_strength: String,
    pub fresh_reason: String,
    pub session: Option<ChooserSession>,
}

pub struct ChooserSession {
    pub user: String,
    pub strength: &'static str,
    pub age: String,
}

impl Request {
    pub(super) fn chooser_options(
        &self,
        directory: &Directory,
        values: &Parameters,
        remembered: Option<&Session>,
        now: DateTime<Utc>,
        request_hint: &str,
    ) -> ChooserOptions {
        let login_hint = login_hint(values, request_hint);
        let selected_user_id = login_user(directory, &login_hint)
            .map(|user| user.id.clone())
            .or_else(|| remembered.map(|session| session.user.clone()))
            .unwrap_or_default();
        let fresh_reason = remembered
            .and_then(|session| self.reuse_blocker(&session.authn, now))
            .unwrap_or_else(|| self.fresh_reason.clone());
        let session = remembered
            .filter(|_| fresh_reason.is_empty())
            .map(|session| ChooserSession {
                user: session.label.clone(),
                strength: if session.authn.strength == "mfa" {
                    "Password + MFA"
                } else {
                    "Password"
                },
                age: crate::duration::format(
                    ((now - session.authn.time).num_milliseconds() + 500) / 1000 * 1_000_000_000,
                ),
            });
        ChooserOptions {
            login_hint,
            selected_user_id,
            selected_strength: self
                .authentication(values, now)
                .map(|authn| authn.strength)
                .unwrap_or_default(),
            fresh_reason,
            session,
        }
    }
}

pub(super) fn login_user<'a>(directory: &'a Directory, identifier: &str) -> Option<&'a User> {
    let identifier = identifier.trim();
    if identifier.is_empty() {
        return None;
    }
    let mut matches = directory.users.iter().filter(|user| {
        user.fields.active
            && !user.deleted
            && !directory
                .user_sync
                .get(&user.id)
                .is_some_and(|sync| sync.deleted)
            && (crate::casefold::equal(user.fields.username.trim(), identifier)
                || crate::casefold::equal(user.fields.email.trim(), identifier))
    });
    let user = matches.next()?;
    matches.next().is_none().then_some(user)
}

fn login_hint(values: &Parameters, request_hint: &str) -> String {
    if let Some(hint) = direct_hint(values) {
        return hint;
    }
    if !request_hint.is_empty() {
        return request_hint.into();
    }
    let relay = param(values, "RelayState").trim();
    let decoded = percent_encoding::percent_decode_str(&relay.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned();
    for candidate in [relay, decoded.as_str()] {
        if let Ok(url) = url::Url::parse(candidate)
            && let Some(hint) = direct_hint(&url.query_pairs().into_owned().collect())
        {
            return hint;
        }
        if let Some(hint) = direct_hint(
            &url::form_urlencoded::parse(candidate.as_bytes())
                .into_owned()
                .collect(),
        ) {
            return hint;
        }
    }
    String::new()
}

fn direct_hint(values: &Parameters) -> Option<String> {
    ["login_hint", "LoginHint", "loginHint"]
        .iter()
        .map(|key| param(values, key).trim())
        .find(|hint| !hint.is_empty())
        .map(str::to_owned)
}
