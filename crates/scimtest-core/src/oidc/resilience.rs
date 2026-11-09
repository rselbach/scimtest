use super::*;
use serde::Serialize;
mod presets;
mod token;
use presets::presets;
pub(super) use token::{TokenReservation, token_key};

/// The execution state of an armed fault injection scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResilienceState {
    Armed,
    Running,
    Completed,
    Disarmed,
    Expired,
}
impl ResilienceState {
    /// Returns the state name used in API responses and the inspector.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Disarmed => "disarmed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Clone)]
enum Action {
    Outage,
    Delay,
    StaleJwks,
    Flow(Faults),
}
impl Action {
    fn api_value(&self) -> Value {
        let faults = match self {
            Self::Flow(faults) => faults.clone(),
            _ => Faults::default(),
        };
        let nanos = |value: &Option<String>| {
            value
                .as_deref()
                .and_then(super::faults::duration)
                .and_then(|duration| duration.num_nanoseconds())
                .unwrap_or_default()
        };
        json!({"RunID":"","Faults":{"IDTokenTTL":nanos(&faults.id_token_ttl),"IDTokenTTLSet":faults.id_token_ttl.is_some(),"AssertionTTL":nanos(&faults.assertion_ttl),"AssertionTTLSet":faults.assertion_ttl.is_some(),"ClockSkew":nanos(&faults.clock_skew),"BreakSignature":faults.break_signature,"DropClaims":if faults.drop_claims.is_empty() { Value::Null } else { json!(faults.drop_claims) },"TokenError":faults.token_error,"SAMLStatus":faults.saml_status_value().unwrap_or_default(),"Tamper":if faults.tamper.is_empty() { Value::Null } else { json!(faults.tamper) }},"Status":if matches!(self,Self::Outage) { 503 } else { 0 },"OAuthError":if matches!(self,Self::Outage) { "temporarily_unavailable" } else { "" },"RetryAfter":if matches!(self,Self::Outage) { "5" } else { "" },"Delay":if matches!(self,Self::Delay) { 3_000_000_000i64 } else { 0 },"StaleJWKS":matches!(self,Self::StaleJwks)})
    }
    fn describe(&self) -> String {
        match self {
            Self::Outage => "HTTP 503 with Retry-After 5".into(),
            Self::Delay => "delay 3s".into(),
            Self::StaleJwks => "JWKS without the current signing key".into(),
            Self::Flow(faults) => faults.describe(),
        }
    }
}
#[derive(Clone, Serialize)]
pub struct ResiliencePreset {
    pub id: &'static str,
    pub name: &'static str,
    pub summary: &'static str,
    pub protocol: &'static str,
    pub phase: &'static str,
    pub count: i32,
    pub allow_count: bool,
    pub behavior: String,
    #[serde(skip)]
    action: Action,
}
impl ResiliencePreset {
    pub(crate) fn api_value(&self) -> Value {
        json!({"ID":self.id,"Name":self.name,"Summary":self.summary,"Protocol":self.protocol,"Phase":self.phase,"Action":self.action.api_value(),"DefaultCount":self.count,"AllowCount":self.allow_count})
    }
}
#[derive(Clone, Serialize)]
pub struct ResilienceRun {
    pub id: String,
    pub preset_id: String,
    pub name: String,
    pub summary: String,
    pub protocol: String,
    pub phase: String,
    pub state: ResilienceState,
    pub total: i32,
    pub remaining: i32,
    pub in_flight: i32,
    pub armed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub decisions: Vec<Decision>,
    #[serde(skip)]
    action: Action,
}
#[derive(Clone, Serialize)]
pub struct Decision {
    pub time: DateTime<Utc>,
    pub phase: String,
    pub outcome: String,
    pub detail: String,
}
impl ResilienceRun {
    pub(crate) fn api_value(&self) -> Value {
        json!({"ID":self.id,"PresetID":self.preset_id,"Name":self.name,"Summary":self.summary,"Protocol":self.protocol,"Phase":self.phase,"State":self.state,"Action":self.action.api_value(),"Total":self.total,"Remaining":self.remaining,"InFlight":self.in_flight,"ArmedAt":self.armed_at,"ExpiresAt":self.expires_at,"Decisions":if self.decisions.is_empty() { Value::Null } else { json!(self.decisions.iter().map(|decision| json!({"Time":decision.time.to_rfc3339_opts(chrono::SecondsFormat::Secs,true),"Phase":decision.phase,"Outcome":decision.outcome,"Detail":decision.detail})).collect::<Vec<_>>()) }})
    }
    pub fn active(&self) -> bool {
        matches!(
            self.state,
            ResilienceState::Armed | ResilienceState::Running
        )
    }
    pub fn progress(&self) -> String {
        format!(
            "{} of {} injections applied",
            self.total - self.remaining,
            self.total
        )
    }
    fn decision(&mut self, phase: &str, outcome: &str, detail: &str, now: DateTime<Utc>) {
        self.decisions.push(Decision {
            time: now,
            phase: phase.into(),
            outcome: outcome.into(),
            detail: detail.into(),
        });
        if self.decisions.len() > 20 {
            self.decisions.remove(0);
        }
    }
    fn expire(&mut self, now: DateTime<Utc>) {
        if self.active() && now >= self.expires_at {
            self.state = ResilienceState::Expired;
            self.in_flight = 0;
            self.decision(
                "scenario",
                "expired",
                "No matching flow arrived before the safety timeout",
                now,
            );
        }
    }
}

impl Identity {
    pub fn resilience_presets(&self, id: &str) -> Result<Vec<ResiliencePreset>> {
        let environment = self.0.store.directory(id)?.environment;
        let oidc = environment.settings.supports_oidc();
        let saml = environment.settings.supports_saml();
        Ok(presets()
            .into_iter()
            .filter(|preset| match preset.protocol {
                "oidc" => oidc,
                "saml" => saml,
                _ => true,
            })
            .collect())
    }
    pub fn arm_resilience(
        &self,
        id: &str,
        preset_id: &str,
        mut count: i32,
    ) -> Result<ResilienceRun> {
        let preset = self
            .resilience_presets(id)?
            .into_iter()
            .find(|preset| preset.id == preset_id.trim())
            .ok_or_else(|| {
                ProtocolError::new(
                    "invalid_request",
                    "unknown or unavailable fault injection scenario",
                )
            })?;
        if !preset.allow_count || count == 0 {
            count = preset.count;
        }
        if !(1..=20).contains(&count) {
            return Err(ProtocolError::new(
                "invalid_request",
                "failure count must be between 1 and 20",
            ));
        }
        let now = Utc::now();
        let mut memory = self.memory()?;
        if let Some(current) = memory.resilience.get_mut(id) {
            current.expire(now);
            if current.active() {
                return Err(
                    Error::Conflict("a fault injection scenario is already active".into()).into(),
                );
            }
        }
        let run = ResilienceRun {
            id: random_secret(12),
            preset_id: preset.id.into(),
            name: preset.name.into(),
            summary: preset.summary.into(),
            protocol: preset.protocol.into(),
            phase: preset.phase.into(),
            state: ResilienceState::Armed,
            total: count,
            remaining: count,
            in_flight: 0,
            armed_at: now,
            expires_at: now + Duration::minutes(15),
            decisions: Vec::new(),
            action: preset.action,
        };
        memory.resilience.insert(id.into(), run.clone());
        memory.protocol_event(
            id,
            preset.protocol,
            "scenario",
            "ok",
            "",
            &format!("Armed {}", run.name),
        );
        Ok(run)
    }
    pub fn resilience_run(&self, id: &str) -> Result<Option<ResilienceRun>> {
        self.0.store.directory(id)?;
        let mut memory = self.memory()?;
        if let Some(run) = memory.resilience.get_mut(id) {
            run.expire(Utc::now());
        }
        Ok(memory.resilience.get(id).cloned())
    }
    pub fn disarm_resilience(&self, id: &str) -> Result<bool> {
        self.0.store.directory(id)?;
        let mut memory = self.memory()?;
        let Some(run) = memory.resilience.get_mut(id) else {
            return Ok(false);
        };
        if !run.active() {
            return Ok(false);
        }
        run.state = ResilienceState::Disarmed;
        run.in_flight = 0;
        run.decision(
            "scenario",
            "disarmed",
            "Disarmed by the developer",
            Utc::now(),
        );
        memory.protocol_event(
            id,
            "resilience",
            "scenario",
            "ok",
            "",
            "Disarmed fault injection scenario",
        );
        Ok(true)
    }
    pub fn stale_jwks(&self, id: &str) -> Result<bool> {
        let mut memory = self.memory()?;
        let Some((run_id, Action::StaleJwks)) = memory.reserve_resilience(id, "jwks", Utc::now())
        else {
            return Ok(false);
        };
        let completed = memory.complete_resilience(id, &run_id, "jwks", Utc::now());
        if completed {
            memory.event(
                id,
                "jwks",
                "",
                "Injected JWKS without the current signing key",
            );
        }
        Ok(completed)
    }
}

impl Memory {
    fn resilience_changed(&self) {
        if let Some(revision) = &self.revision {
            revision.send_modify(|value| *value = value.wrapping_add(1));
        }
    }
    pub(super) fn flow_faults(&mut self, id: &str, values: &Parameters) -> Faults {
        let explicit = Faults::from_parameters(values);
        if explicit.active() {
            return explicit;
        }
        let armed = self.take_faults(id, false);
        if armed.active() {
            return armed;
        }
        let now = Utc::now();
        if let Some(run) = self.resilience.get_mut(id) {
            run.expire(now);
            if run.active()
                && run.phase == "flow"
                && let Action::Flow(faults) = run.action.clone()
            {
                run.state = ResilienceState::Completed;
                run.remaining = 0;
                run.decision("flow", "injected", &faults.describe(), now);
                self.resilience_changed();
                return faults;
            }
        }
        Faults::default()
    }
    fn reserve_resilience(
        &mut self,
        id: &str,
        phase: &str,
        now: DateTime<Utc>,
    ) -> Option<(String, Action)> {
        let run = self.resilience.get_mut(id)?;
        run.expire(now);
        if !run.active() || run.phase != phase || run.remaining - run.in_flight < 1 {
            return None;
        }
        run.state = ResilienceState::Running;
        run.in_flight += 1;
        let reserved = (run.id.clone(), run.action.clone());
        self.resilience_changed();
        Some(reserved)
    }
    fn complete_resilience(
        &mut self,
        id: &str,
        run_id: &str,
        phase: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(run) = self.resilience.get_mut(id) else {
            return false;
        };
        run.expire(now);
        if !run.active() || run.id != run_id || run.in_flight < 1 || run.remaining < 1 {
            return false;
        }
        run.in_flight -= 1;
        run.remaining -= 1;
        run.decision(phase, "injected", &run.action.describe(), now);
        if run.remaining == 0 && run.in_flight == 0 {
            run.state = ResilienceState::Completed;
        }
        self.resilience_changed();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{configuration::SettingsPatch, model::EnvironmentInput};

    #[test]
    fn expired_scenarios_do_not_inject_and_can_be_replaced() {
        let temporary = tempfile::tempdir().unwrap();
        let store = Store::open(&temporary.path().join("state.db")).unwrap();
        let environment = store
            .create_environment(EnvironmentInput {
                name: "Greendale".into(),
                settings: SettingsPatch {
                    oidc_enabled: Some(true),
                    oidc_client_id: Some("greendale".into()),
                    ..Default::default()
                },
                ..Default::default()
            })
            .unwrap();
        let identity = Identity::new(store);
        let first = identity
            .arm_resilience(&environment.id, "token-outage", 1)
            .unwrap();
        identity
            .memory()
            .unwrap()
            .resilience
            .get_mut(&environment.id)
            .unwrap()
            .expires_at = Utc::now() - Duration::seconds(1);
        assert!(
            identity
                .memory()
                .unwrap()
                .reserve_resilience(&environment.id, "token", Utc::now())
                .is_none()
        );
        let expired = identity.resilience_run(&environment.id).unwrap().unwrap();
        assert_eq!(expired.state, ResilienceState::Expired);
        assert_eq!(expired.remaining, 1);
        assert_eq!(expired.decisions[0].outcome, "expired");
        let replacement = identity
            .arm_resilience(&environment.id, "token-outage", 2)
            .unwrap();
        assert_ne!(first.id, replacement.id);
        assert_eq!(replacement.state, ResilienceState::Armed);
    }
}
