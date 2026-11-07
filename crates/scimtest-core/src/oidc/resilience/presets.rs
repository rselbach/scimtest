use super::*;

pub(super) fn presets() -> Vec<ResiliencePreset> {
    [
        (
            "token-outage",
            "Token endpoint outage",
            "Return a temporary error before recovering normally.",
            "oidc",
            "token",
            2,
            true,
            Action::Outage,
        ),
        (
            "slow-token",
            "Slow token endpoint",
            "Delay token redemption long enough to expose timeout handling.",
            "oidc",
            "token",
            1,
            false,
            Action::Delay,
        ),
        (
            "stale-jwks",
            "Stale JWKS",
            "Serve a JWKS without the current signing key, like a cached or lagging key set, to test key refetch logic.",
            "oidc",
            "jwks",
            1,
            true,
            Action::StaleJwks,
        ),
        (
            "expired-token",
            "Expired ID token",
            "Issue a correctly formed ID token that is already expired.",
            "oidc",
            "flow",
            1,
            false,
            Action::Flow(Faults {
                id_token_ttl: Some("-1m".into()),
                ..Default::default()
            }),
        ),
        (
            "broken-signature",
            "Invalid signature",
            "Corrupt the token signature, or every SAML signature, without changing its shape.",
            "both",
            "flow",
            1,
            false,
            Action::Flow(Faults {
                break_signature: true,
                ..Default::default()
            }),
        ),
        (
            "missing-email",
            "Missing email claim",
            "Omit email from the ID token and userinfo response.",
            "oidc",
            "flow",
            1,
            false,
            Action::Flow(Faults {
                drop_claims: vec!["email".into()],
                ..Default::default()
            }),
        ),
        (
            "unsigned-id-token",
            "Unsigned ID token",
            "Issue an alg none ID token with no signature.",
            "oidc",
            "flow",
            1,
            false,
            Action::Flow(Faults {
                tamper: vec!["alg_none".into()],
                ..Default::default()
            }),
        ),
        (
            "wrong-audience",
            "Wrong audience",
            "Issue a token or assertion for a different audience.",
            "both",
            "flow",
            1,
            false,
            Action::Flow(Faults {
                tamper: vec!["wrong_audience".into()],
                ..Default::default()
            }),
        ),
        (
            "replayed-assertion",
            "Replayed SAML assertion",
            "Reuse the previous assertion ID in a fresh, signed response.",
            "saml",
            "flow",
            1,
            false,
            Action::Flow(Faults {
                tamper: vec!["replayed_assertion".into()],
                ..Default::default()
            }),
        ),
        (
            "saml-auth-failed",
            "SAML authentication failure",
            "Return an AuthnFailed status instead of a signed assertion.",
            "saml",
            "flow",
            1,
            false,
            Action::Flow(Faults {
                saml_status: "AuthnFailed".into(),
                ..Default::default()
            }),
        ),
    ]
    .into_iter()
    .map(
        |(id, name, summary, protocol, phase, count, allow_count, action)| ResiliencePreset {
            id,
            name,
            summary,
            protocol,
            phase,
            count,
            allow_count,
            behavior: action.describe(),
            action,
        },
    )
    .collect()
}
