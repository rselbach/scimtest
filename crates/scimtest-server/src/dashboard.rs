use crate::{
    application::{ApplicationSettings, parse_routes},
    auth::{self, Form, field},
    lock,
    server::{State, error, not_found, text_response},
    store::Session,
};
use anyhow::{Result, bail};
use axum::{
    extract::Request,
    http::{HeaderValue, StatusCode},
    response::Response,
};
use chrono::Utc;
use minijinja::Environment;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

pub(crate) fn templates() -> Result<Environment<'static>> {
    let mut templates = Environment::new();
    for (name, source) in [
        (
            "dashboard.html",
            include_str!("../templates/dashboard.html"),
        ),
        (
            "tunnels_partial.html",
            include_str!("../templates/tunnels_partial.html"),
        ),
        (
            "enrollment.html",
            include_str!("../templates/enrollment.html"),
        ),
        ("complete.html", include_str!("../templates/complete.html")),
        (
            "replacement.html",
            include_str!("../templates/replacement.html"),
        ),
    ] {
        templates.add_template(name, source)?;
    }
    Ok(templates)
}

impl State {
    pub fn page(&self, name: &str, values: Value) -> Response {
        let body = match self
            .templates
            .get_template(name)
            .and_then(|template| template.render(values))
        {
            Ok(body) => body,
            Err(error) => {
                if self.config.logs {
                    eprintln!("page render failed: {error}");
                }
                return crate::server::error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not render page",
                );
            }
        };
        let mut response = text_response(StatusCode::OK, "text/html; charset=utf-8", body);
        response
            .headers_mut()
            .insert("cache-control", HeaderValue::from_static("no-store"));
        response.headers_mut().insert("content-security-policy", HeaderValue::from_static(match name {
            "dashboard.html" => "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            "enrollment.html" => "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://github.com; frame-ancestors 'none'",
            "replacement.html" => "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
            _ => "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        }));
        if name == "enrollment.html" {
            let origin = match url::Url::parse(&self.github.authorize_url) {
                Ok(url) => url.origin().ascii_serialization(),
                Err(_) => {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invalid authorization URL",
                    );
                }
            };
            let policy = format!(
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' {origin}; frame-ancestors 'none'"
            );
            match HeaderValue::from_str(&policy) {
                Ok(policy) => {
                    response
                        .headers_mut()
                        .insert("content-security-policy", policy);
                }
                Err(_) => {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invalid authorization URL",
                    );
                }
            }
        }
        response
    }

    pub async fn dashboard(&self, request: Request) -> Response {
        let path = request.uri().path().to_owned();
        let mutation = path == "/logout"
            || path.starts_with("/dashboard/applications/")
            || path == "/dashboard/tunnels/disconnect";
        if mutation && request.method() != "POST" {
            return auth::method_not_allowed("POST");
        }
        let session = match self.require_session(&request) {
            Ok(session) => session,
            Err(response) => return *response,
        };
        if mutation {
            let values = match auth::form(request, 10 << 20).await {
                Ok(values) => values,
                Err(error) => {
                    return crate::server::error(
                        StatusCode::BAD_REQUEST,
                        &format!("invalid form: {error}"),
                    );
                }
            };
            if !session.admin {
                return error(StatusCode::FORBIDDEN, "admin access required");
            }
            if !auth::equal_secret(&session.csrf_token, field(&values, "csrf_token")) {
                return error(StatusCode::FORBIDDEN, "invalid csrf token");
            }
            return self.dashboard_mutation(&path, session, values).await;
        }
        if path == "/dashboard/app.js" {
            let mut response = text_response(
                StatusCode::OK,
                "application/javascript; charset=utf-8",
                include_str!("../templates/dashboard.js"),
            );
            response
                .headers_mut()
                .insert("cache-control", HeaderValue::from_static("no-store"));
            return response;
        }
        let values = match self.dashboard_values(&session) {
            Ok(values) => values,
            Err(_) => {
                return error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not load dashboard",
                );
            }
        };
        self.page(
            if path == "/dashboard/tunnels" {
                "tunnels_partial.html"
            } else {
                "dashboard.html"
            },
            values,
        )
    }

    fn dashboard_values(&self, session: &Session) -> Result<Value> {
        let mut tunnels: Vec<_> = lock(&self.tunnels).values().map(|tunnel| json!({
            "ID":tunnel.id,"PublicURL":tunnel.public_url,"ApplicationName":tunnel.application_name,"InstanceID":tunnel.instance_id,
            "LocalPort":tunnel.local_port,"ConnectedAt":tunnel.connected_at.timestamp(),"Uptime":uptime((Utc::now()-tunnel.connected_at).num_seconds()),"Requests":tunnel.requests.load(Ordering::Relaxed)
        })).collect();
        tunnels.sort_by(|left, right| left["ID"].as_str().cmp(&right["ID"].as_str()));
        let total: u64 = tunnels
            .iter()
            .filter_map(|tunnel| tunnel["Requests"].as_u64())
            .sum();
        let mut applications = Vec::new();
        let mut reservations = Vec::new();
        for profile in self.store.profiles()? {
            let routes = profile
                .settings
                .routes
                .iter()
                .map(|route| format!("{} {}", route.methods.join(","), route.path))
                .collect::<Vec<_>>()
                .join("\n");
            applications.push(json!({"ID":profile.id,"Name":profile.settings.name,"PublicKey":profile.settings.public_key,"PublicKeyFingerprint":profile.public_key_fingerprint,"RequestsPerMinute":profile.settings.requests_per_minute,"RequestBurst":profile.settings.request_burst,"ConcurrentRequests":profile.settings.concurrent_requests,"RoutesText":routes}));
            for (id, instance) in &profile.instances {
                reservations.push(json!({"ProfileID":profile.id,"ProfileName":profile.settings.name,"InstanceID":id,"TunnelID":instance.tunnel_id,"PublicURL":format!("{}://{}/{}",self.config.public_scheme,self.config.domain,instance.tunnel_id),"Enrolled":instance.is_enrolled(),"Revoked":instance.revoked,"GitHubUserID":instance.github_user_id,"GitHubLogin":instance.github_login,"LastUsedAt":instance.last_used_at.format("%Y-%m-%d %H:%M UTC").to_string()}));
            }
        }
        reservations.sort_by(|left, right| {
            left["ProfileName"]
                .as_str()
                .cmp(&right["ProfileName"].as_str())
                .then_with(|| left["TunnelID"].as_str().cmp(&right["TunnelID"].as_str()))
        });
        Ok(
            json!({"Session":{"Login":session.login,"CSRFToken":session.csrf_token},"Tunnels":tunnels,"Applications":applications,"Reservations":reservations,"TotalRequests":total,"BaseURL":format!("{}://{}",self.config.public_scheme,self.config.domain),"Domain":self.config.domain}),
        )
    }

    async fn dashboard_mutation(&self, path: &str, session: Session, values: Form) -> Response {
        let id = field(&values, "id");
        let profile = field(&values, "profile_id");
        let instance = field(&values, "instance_id");
        match path {
            "/logout" => {
                if self.store.delete_session(&session.id).is_err() {
                    return error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "could not delete session",
                    );
                }
                let mut response = auth::redirect("/");
                self.clear_cookie(&mut response, auth::SESSION_COOKIE);
                response
            }
            "/dashboard/applications/create" => {
                match settings(&values).and_then(|settings| self.store.create_profile(settings)) {
                    Ok(_) => auth::redirect("/dashboard#applications"),
                    Err(error) => crate::server::error(StatusCode::BAD_REQUEST, &error.to_string()),
                }
            }
            "/dashboard/applications/update" => {
                let settings = match settings(&values) {
                    Ok(settings) => settings,
                    Err(error) => {
                        return crate::server::error(StatusCode::BAD_REQUEST, &error.to_string());
                    }
                };
                let _gate = self.profile_gate.write().await;
                match self.store.update_profile(id, settings) {
                    Ok(_) => {
                        self.disconnect_profile(id);
                        auth::redirect("/dashboard#applications")
                    }
                    Err(error) => {
                        if self.store.profile(id).ok().flatten().is_none() {
                            not_found()
                        } else {
                            crate::server::error(StatusCode::BAD_REQUEST, &error.to_string())
                        }
                    }
                }
            }
            "/dashboard/applications/delete" => {
                let _gate = self.profile_gate.write().await;
                match self.store.delete_profile(id) {
                    Ok(()) => {
                        self.disconnect_profile(id);
                        auth::redirect("/dashboard#applications")
                    }
                    Err(error) => crate::server::error(StatusCode::NOT_FOUND, &error.to_string()),
                }
            }
            "/dashboard/applications/reservations/delete" => {
                match self.store.unreserve_tunnel(profile, instance) {
                    Ok(true) => auth::redirect("/dashboard#reserved-names"),
                    Ok(false) => not_found(),
                    Err(error) => {
                        crate::server::error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    }
                }
            }
            "/dashboard/applications/instances/revoke" => {
                let revoked = field(&values, "revoked") == "true";
                match self.store.set_instance_revoked(profile, instance, revoked) {
                    Ok(true) => {
                        if revoked {
                            self.disconnect_instance(profile, instance);
                        }
                        auth::redirect("/dashboard#reserved-names")
                    }
                    Ok(false) => not_found(),
                    Err(error) => {
                        crate::server::error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
                    }
                }
            }
            "/dashboard/tunnels/disconnect" => {
                if let Some(tunnel) = lock(&self.tunnels).get(id) {
                    tunnel.closed.cancel();
                    auth::redirect("/dashboard")
                } else {
                    not_found()
                }
            }
            _ => not_found(),
        }
    }

    pub fn disconnect_instance(&self, profile: &str, instance: &str) {
        for tunnel in lock(&self.tunnels)
            .values()
            .filter(|tunnel| tunnel.profile_id == profile && tunnel.instance_id == instance)
        {
            tunnel.closed.cancel();
        }
    }

    fn disconnect_profile(&self, profile: &str) {
        for tunnel in lock(&self.tunnels)
            .values()
            .filter(|tunnel| tunnel.profile_id == profile)
        {
            tunnel.closed.cancel();
        }
    }
}

fn settings(values: &Form) -> Result<ApplicationSettings> {
    Ok(ApplicationSettings {
        name: field(values, "name").into(),
        public_key: field(values, "public_key").into(),
        routes: parse_routes(field(values, "routes"))?,
        requests_per_minute: positive(values, "requests_per_minute", "requests per minute")?,
        request_burst: positive(values, "request_burst", "request burst")?,
        concurrent_requests: positive(values, "concurrent_requests", "concurrent requests")?,
    })
}

fn positive(values: &Form, key: &str, name: &str) -> Result<i64> {
    let value = field(values, key)
        .parse::<i64>()
        .ok()
        .filter(|value| *value > 0);
    let Some(value) = value else {
        bail!("{name} must be a positive integer");
    };
    Ok(value)
}

fn uptime(seconds: i64) -> String {
    match seconds {
        ..60 => format!("{seconds}s"),
        60..3600 => format!("{}m", seconds / 60),
        3600..86400 => format!("{}h {:02}m", seconds / 3600, seconds / 60 % 60),
        _ => format!("{}d {}h", seconds / 86400, seconds / 3600 % 24),
    }
}
