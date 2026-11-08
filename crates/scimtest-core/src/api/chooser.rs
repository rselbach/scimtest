use super::oidc::escape;
use crate::{
    model::{Directory, User},
    oidc::{ChooserOptions, Parameters},
};

pub(super) fn chooser(
    title: &str,
    directory: &Directory,
    values: &Parameters,
    options: &ChooserOptions,
) -> String {
    let mut users = directory
        .projected_users()
        .into_iter()
        .filter(|user| user.fields.active && !user.deleted)
        .collect::<Vec<_>>();
    users.sort_by_key(display_name);
    let hinted_user = crate::oidc::login_hint_user(directory, &options.login_hint);
    if let Some(index) = users
        .iter()
        .position(|user| Some(user.id.as_str()) == hinted_user)
    {
        users[..=index].rotate_right(1);
    }
    let environment = &directory.environment;
    let identifier = environment.settings.chooser_mode == "identifier";
    let title = escape(title);
    let app_name = escape(&environment.name);
    // Keep the public URL prefix and the original signed query when submitting.
    let action = "";
    let hidden = hidden(values);
    let mut html = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{title} · {app_name}</title><style>{}</style></head><body><main><header><h1>{title}</h1><p>{app_name}</p>",
        include_str!("chooser.css"),
    );
    if !options.fresh_reason.is_empty() {
        html.push_str(&format!(
            "<p class=\"fresh-note\">{app_name} requires a fresh sign-in ({}).</p>",
            escape(&options.fresh_reason)
        ));
    }
    if let Some(session) = &options.session {
        html.push_str(&format!(
            "<div class=\"session-option\" data-session><div><strong>Signed in as {}</strong><p class=\"user-meta\">{}, {} ago</p></div><form method=\"post\" action=\"{action}\">{hidden}<button type=\"submit\" name=\"continue_session\" value=\"1\">Reuse session</button></form></div>",
            escape(&session.user),session.strength,escape(&session.age),
        ));
    }
    html.push_str("</header>");
    if identifier || !users.is_empty() {
        html.push_str(&format!(
            "<form id=\"chooser-form\"{} method=\"post\" action=\"{action}\">{hidden}",
            if identifier {
                " class=\"identifier-form\""
            } else {
                ""
            }
        ));
        if identifier {
            html.push_str(&format!("<label class=\"identifier-field\">Username or email<input name=\"login_identifier\" value=\"{}\" autocomplete=\"username\" required autofocus></label>",escape(&options.login_hint)));
        } else {
            html.push_str("<div class=\"search-row\"><input type=\"search\" placeholder=\"Search name, username, or email\" aria-label=\"Search users\" aria-controls=\"user-list\" autocomplete=\"off\" autofocus data-user-search><span class=\"match-count\" aria-live=\"polite\" data-match-count></span></div><div class=\"user-list\" id=\"user-list\" role=\"radiogroup\" aria-label=\"Users\" data-user-list>");
            for user in &users {
                let name = display_name(user);
                html.push_str(&format!("<label class=\"user-option\" data-user-option data-search=\"{}\"><input type=\"radio\" name=\"user_id\" value=\"{}\" required{}><div><strong>{}</strong><span class=\"user-meta\">{}</span></div></label>",
                    escape(&format!("{name} {} {}",user.fields.username,user.fields.email)),escape(&user.id),if user.id==options.selected_user_id { " checked" } else { "" },escape(&name),escape(&user.fields.email)));
            }
            html.push_str("<div class=\"no-matches\" hidden data-no-matches>No users match your search.</div></div>");
        }
        html.push_str("<div class=\"chooser-actions\"><label class=\"strength-field\">Sign-in method<select name=\"authn_strength\">");
        for (value, label) in [("password", "Password"), ("mfa", "Password + MFA")] {
            html.push_str(&format!(
                "<option value=\"{value}\"{}>{label}</option>",
                if options.selected_strength == value {
                    " selected"
                } else {
                    ""
                }
            ));
        }
        html.push_str("</select></label><button type=\"submit\" data-continue>Continue</button><button type=\"submit\" formnovalidate name=\"deny\" value=\"1\" class=\"secondary\" data-deny>Deny</button></div></form>");
    } else {
        html.push_str("<div class=\"empty\">Create an active user before starting sign-in.</div>");
    }
    html.push_str("</main>");
    if !identifier && !users.is_empty() {
        html.push_str(&format!("<script>{}</script>", include_str!("chooser.js")));
    }
    html.push_str("</body></html>");
    html
}

fn hidden(values: &Parameters) -> String {
    let mut fields = values
        .iter()
        .filter(|(key, _)| {
            ![
                "user_id",
                "login_identifier",
                "authn_strength",
                "continue_session",
            ]
            .contains(&key.as_str())
        })
        .collect::<Vec<_>>();
    fields.sort_by_key(|(key, _)| *key);
    fields
        .into_iter()
        .map(|(key, value)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                escape(key),
                escape(value)
            )
        })
        .collect()
}

fn display_name(user: &User) -> String {
    let name = format!("{} {}", user.fields.given_name, user.fields.family_name)
        .trim()
        .to_owned();
    if name.is_empty() {
        user.fields.username.clone()
    } else {
        name
    }
}
