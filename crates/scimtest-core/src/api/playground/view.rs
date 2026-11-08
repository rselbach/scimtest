use super::{Environment, ResultPage, Value};
use crate::api::oidc::escape;

fn page(environment: &Environment, title: &str) -> String {
    let name = escape(&environment.name);
    let slug = escape(&environment.slug);
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{title} · {name} · scimtest</title><style>{}</style></head><body><header class=\"topbar\"><a href=\"/\">scimtest</a></header><main><div class=\"page-heading\"><div><h1>{title}</h1><p>{name} — built-in relying party</p></div><nav aria-label=\"Playground\"><a class=\"btn\" href=\"/inspect/oidc/{slug}/playground\">Run again</a><a class=\"btn\" href=\"/inspect/oidc/{slug}\">Flow inspector</a></nav></div>",
        include_str!("style.css")
    )
}

fn payload(title: &str, value: &str) -> String {
    format!(
        "<h3>{title}</h3><pre class=\"inspector-payload\">{}</pre>",
        escape(value)
    )
}

pub(super) fn result(environment: &Environment, result: &ResultPage) -> String {
    let mut html = page(environment, "OIDC playground");
    if !result.error.is_empty() {
        html.push_str(&format!("<section class=\"card\" role=\"alert\"><h2>Flow did not complete</h2><p>{}</p></section></main></body></html>", escape(&result.error)));
        return html;
    }
    if result.refreshed {
        html.push_str(&format!("<section class=\"card\"><h2>Refresh request</h2><dl><dt>Grant type</dt><dd class=\"mono\">refresh_token</dd><dt>Scope</dt><dd class=\"mono\">{}</dd></dl></section>", escape(if result.scope.is_empty() { "original grant" } else { &result.scope })));
    } else {
        html.push_str(&format!("<section class=\"card\"><h2>Authorization response</h2><dl><dt>Code</dt><dd class=\"mono\">{}</dd><dt>State echoed</dt><dd>{}</dd></dl></section>", escape(&result.code), if result.state.is_empty() { "No" } else { "Yes" }));
    }
    html.push_str(&format!("<section class=\"card\"><h2>Token response <span class=\"hint\">{}</span></h2><pre class=\"inspector-payload\">{}</pre></section>", escape(&result.token_status), escape(&result.token_body)));
    if !result.id_claims.is_empty() {
        html.push_str("<section class=\"card\"><h2>Decoded ID token</h2>");
        html.push_str(&payload("Header", &result.id_header));
        html.push_str(&payload("Claims", &result.id_claims));
        if !result.previous_claims.is_empty() {
            html.push_str(&format!("<details><summary>Claims before this refresh</summary><pre class=\"inspector-payload\">{}</pre></details>", escape(&result.previous_claims)));
        }
        html.push_str(&payload("Raw (compact)", &result.id_token));
        html.push_str("</section>");
    }
    if !result.access_claims.is_empty() {
        html.push_str("<section class=\"card\"><h2>Decoded access token</h2>");
        html.push_str(&payload("Header", &result.access_header));
        html.push_str(&payload("Claims", &result.access_claims));
        html.push_str("</section>");
    }
    if !result.userinfo.is_empty() {
        html.push_str(&format!("<section class=\"card\"><h2>Userinfo</h2><pre class=\"inspector-payload\">{}</pre></section>", escape(&result.userinfo)));
    }
    if !result.refresh_token.is_empty() {
        html.push_str(&format!("<section class=\"card\"><h2>Refresh tokens</h2><p class=\"hint\">Redeems the refresh token above. The response carries a replacement, and the old token stops working. Leave scope empty to keep the original grant, or name a subset to narrow it.</p><form method=\"post\" action=\"/inspect/oidc/{}/playground/refresh\"><input type=\"hidden\" name=\"refresh_token\" value=\"{}\"><input type=\"hidden\" name=\"previous_id_token\" value=\"{}\"><label>Scope<input name=\"scope\" placeholder=\"openid email\" autocomplete=\"off\"></label><button type=\"submit\">Refresh tokens</button></form></section>", escape(&environment.slug), escape(&result.refresh_token), escape(&result.id_token)));
    }
    html.push_str("</main></body></html>");
    html
}

pub(super) fn inspector(
    environment: &Environment,
    sessions: &[Value],
    holders: &[Value],
    inspections: &[Value],
    flows: &[Value],
) -> String {
    let mut html = page(environment, "OIDC inspector");
    let path = format!("/inspect/oidc/{}", escape(&environment.slug));
    html.push_str("<section class=\"card\"><h2>IdP sessions</h2>");
    if sessions.is_empty() {
        html.push_str("<p>No active sessions.</p>");
    }
    for session in sessions {
        let user = escape(session["user"].as_str().unwrap_or_default());
        let id = escape(session["session_id"].as_str().unwrap_or_default());
        html.push_str(&format!("<article><h3>{user}</h3>{}<form method=\"post\" action=\"{path}/sessions/end\"><input type=\"hidden\" name=\"session_id\" value=\"{id}\"><button>End {user}'s session</button></form></article>", details(session, &[("Session ID", "session_id"), ("Signed in", "signed_in_at"), ("Sign-in method", "authn_strength"), ("Protocols", "protocols")])));
    }
    html.push_str("</section><section class=\"card\"><h2>Tokens</h2>");
    if holders.is_empty() {
        html.push_str("<p>No active tokens.</p>");
    }
    for holder in holders {
        let user = escape(holder["user"].as_str().unwrap_or_default());
        let id = escape(holder["user_id"].as_str().unwrap_or_default());
        html.push_str(&format!("<article><h3>{user}</h3>{}<form method=\"post\" action=\"{path}/revoke\"><input type=\"hidden\" name=\"user_id\" value=\"{id}\"><button>Revoke {user}'s tokens</button></form></article>", details(holder, &[("Access tokens", "access_tokens"), ("Refresh tokens", "refresh_tokens")])));
    }
    html.push_str("</section>");
    html.push_str("<section class=\"card\"><h2>Inspections</h2>");
    if inspections.is_empty() {
        html.push_str("<p>No recorded flows.</p>");
    }
    for entry in inspections {
        html.push_str(&format!(
            "<article><h3>{} · {}</h3>{}",
            value(entry, "Stage"),
            value(entry, "User"),
            details(
                entry,
                &[
                    ("Updated", "UpdatedAt"),
                    ("Client", "ClientID"),
                    ("Redirect URI", "RedirectURI"),
                    ("Scope", "Scope"),
                    ("PKCE", "PKCE"),
                    ("Faults", "Faults")
                ]
            )
        ));
        for (title, key) in [("Header", "Header"), ("Claims", "Claims")] {
            if let Some(raw) = entry[key].as_str().filter(|raw| !raw.is_empty()) {
                html.push_str(&payload(title, &super::pretty(raw)));
            }
        }
        if let Some(raw) = entry["IDToken"].as_str().filter(|raw| !raw.is_empty()) {
            html.push_str(&format!("<details><summary>Raw ID token</summary><pre class=\"inspector-payload\">{}</pre></details>", escape(raw)));
        }
        html.push_str("</article>");
    }
    html.push_str("</section><section class=\"card\"><h2>Recent activity</h2>");
    if flows.is_empty() {
        html.push_str("<p>No recorded flows.</p>");
    }
    if !flows.is_empty() {
        html.push_str("<div class=\"table-scroll\"><table><thead><tr><th scope=\"col\">Time</th><th scope=\"col\">Stage</th><th scope=\"col\">User</th><th scope=\"col\">Outcome</th><th scope=\"col\">Detail</th></tr></thead><tbody>");
        for entry in flows {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{} {}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                value(entry, "Time"),
                value(entry, "Protocol"),
                value(entry, "Stage"),
                value(entry, "User"),
                value(entry, "Outcome"),
                value(entry, "Detail")
            ));
        }
        html.push_str("</tbody></table></div>");
    }
    html.push_str("</section>");
    html.push_str("</main></body></html>");
    html
}

fn value(entry: &Value, key: &str) -> String {
    let value = &entry[key];
    match value {
        Value::String(value) => escape(value),
        Value::Null => String::new(),
        _ => escape(&value.to_string()),
    }
}

fn details(entry: &Value, fields: &[(&str, &str)]) -> String {
    let mut html = String::from("<dl>");
    for (label, key) in fields {
        html.push_str(&format!("<dt>{label}</dt><dd>{}</dd>", value(entry, key)));
    }
    html.push_str("</dl>");
    html
}
