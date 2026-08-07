package web

import (
	"net/url"
	"strings"
	"time"
)

// faultOptions describes deliberate misbehavior requested for a single flow so
// an SP or RP can be tested against expired tokens, clock skew, bad
// signatures, missing claims, and error responses without editing code. They
// are parsed from fault_* request parameters and, for OIDC, carried from the
// authorize request to the token response through the authorization code.
type faultOptions struct {
	IDTokenTTL     time.Duration // overrides the ID token lifetime when non-zero
	IDTokenTTLSet  bool
	ClockSkew      time.Duration // added to iat/exp and SAML instants
	BreakSignature bool          // corrupt the ID token / assertion signature
	DropClaims     []string      // claims omitted from the ID token and userinfo
	TokenError     string        // force this OAuth error at the token endpoint
	SAMLStatus     string        // non-success SAML status: Responder or AuthnFailed
}

func parseFaultOptions(values url.Values) faultOptions {
	var faults faultOptions
	if raw := strings.TrimSpace(values.Get("fault_id_token_ttl")); raw != "" {
		if ttl, err := time.ParseDuration(raw); err == nil {
			faults.IDTokenTTL = ttl
			faults.IDTokenTTLSet = true
		}
	}
	if raw := strings.TrimSpace(values.Get("fault_clock_skew")); raw != "" {
		if skew, err := time.ParseDuration(raw); err == nil {
			faults.ClockSkew = skew
		}
	}
	faults.BreakSignature = isTruthy(values.Get("fault_break_signature"))
	if raw := strings.TrimSpace(values.Get("fault_drop_claims")); raw != "" {
		for _, claim := range strings.Split(raw, ",") {
			if trimmed := strings.TrimSpace(claim); trimmed != "" {
				faults.DropClaims = append(faults.DropClaims, trimmed)
			}
		}
	}
	faults.TokenError = strings.TrimSpace(values.Get("fault_token_error"))
	switch strings.ToLower(strings.TrimSpace(values.Get("fault_saml_status"))) {
	case "responder":
		faults.SAMLStatus = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	case "authnfailed":
		faults.SAMLStatus = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	}
	return faults
}

// active reports whether any fault was requested.
func (f faultOptions) active() bool {
	return f.IDTokenTTLSet || f.ClockSkew != 0 || f.BreakSignature ||
		len(f.DropClaims) > 0 || f.TokenError != "" || f.SAMLStatus != ""
}

func (f faultOptions) applyToClaims(claims map[string]any, issued time.Time) {
	for _, claim := range f.DropClaims {
		delete(claims, claim)
	}
	if f.ClockSkew != 0 {
		claims["iat"] = issued.Add(f.ClockSkew).Unix()
	}
	ttl := time.Hour
	if f.IDTokenTTLSet {
		ttl = f.IDTokenTTL
	}
	claims["exp"] = issued.Add(f.ClockSkew).Add(ttl).Unix()
}

// corruptJWTSignature flips the signature segment of a compact JWS so the
// token verifies as tampered while remaining structurally valid.
func corruptJWTSignature(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token
	}
	sig := parts[2]
	if sig == "" {
		return token
	}
	// swap the first character for a different valid base64url character
	replacement := byte('A')
	if sig[0] == 'A' {
		replacement = 'B'
	}
	parts[2] = string(replacement) + sig[1:]
	return strings.Join(parts, ".")
}

func isTruthy(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}
