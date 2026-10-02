package web

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// faultOptions describes deliberate misbehavior requested for a single flow so
// an SP or RP can be tested against expired tokens, clock skew, bad
// signatures, missing claims, and error responses without editing code. They
// are parsed from fault_* request parameters and, for OIDC, carried from the
// authorize request to the token response through the authorization code.
type faultOptions struct {
	IDTokenTTL      time.Duration // overrides the ID token lifetime when non-zero
	IDTokenTTLSet   bool
	AssertionTTL    time.Duration // overrides the SAML assertion lifetime
	AssertionTTLSet bool
	ClockSkew       time.Duration // added to iat, exp, auth_time, and SAML instants
	BreakSignature  bool          // corrupt the ID token / assertion signature
	DropClaims      []string      // claims omitted from the ID token and userinfo
	TokenError      string        // force this OAuth error at the token endpoint
	SAMLStatus      string        // non-success SAML status: Responder or AuthnFailed
	Tamper          []tamperFault // validation rules the response deliberately breaks
}

// tamperFault names one validation rule a relying party or service provider
// must enforce. The tampered response is otherwise valid, so a sign-in that
// still succeeds shows the app skips that check.
type tamperFault string

const (
	tamperWrongIssuer   tamperFault = "wrong_issuer"
	tamperWrongAudience tamperFault = "wrong_audience"
	tamperUnknownKeyID  tamperFault = "unknown_kid"
	tamperAlgNone       tamperFault = "alg_none"
	tamperNonceMismatch tamperFault = "nonce_mismatch"

	tamperWrongDestination     tamperFault = "wrong_destination"
	tamperWrongRecipient       tamperFault = "wrong_recipient"
	tamperInResponseToMismatch tamperFault = "in_response_to_mismatch"
	tamperReplayedAssertion    tamperFault = "replayed_assertion"

	tamperLogoutAlgNone       tamperFault = "logout_alg_none"
	tamperLogoutWrongAudience tamperFault = "logout_wrong_audience"
	tamperLogoutMissingEvents tamperFault = "logout_missing_events"
	tamperLogoutRepeatedJTI   tamperFault = "logout_repeated_jti"
)

// tamperFaultInfo describes a tamper fault for forms and descriptions.
type tamperFaultInfo struct {
	ID       tamperFault
	Protocol string // oidc, saml, or both, like app.Protocol
	Label    string
	Logout   bool // breaks back-channel logout tokens instead of sign-ins
}

var tamperFaults = []tamperFaultInfo{
	{ID: tamperWrongIssuer, Protocol: "both", Label: "Wrong issuer"},
	{ID: tamperWrongAudience, Protocol: "both", Label: "Wrong audience"},
	{ID: tamperUnknownKeyID, Protocol: "oidc", Label: "Unknown signing key ID"},
	{ID: tamperAlgNone, Protocol: "oidc", Label: "Unsigned ID token (alg none)"},
	{ID: tamperNonceMismatch, Protocol: "oidc", Label: "Nonce mismatch"},
	{ID: tamperWrongDestination, Protocol: "saml", Label: "Wrong destination"},
	{ID: tamperWrongRecipient, Protocol: "saml", Label: "Wrong recipient"},
	{ID: tamperInResponseToMismatch, Protocol: "saml", Label: "InResponseTo mismatch"},
	{ID: tamperReplayedAssertion, Protocol: "saml", Label: "Replayed assertion ID"},
	{ID: tamperLogoutAlgNone, Protocol: "oidc", Label: "Logout token: unsigned (alg none)", Logout: true},
	{ID: tamperLogoutWrongAudience, Protocol: "oidc", Label: "Logout token: wrong audience", Logout: true},
	{ID: tamperLogoutMissingEvents, Protocol: "oidc", Label: "Logout token: missing events", Logout: true},
	{ID: tamperLogoutRepeatedJTI, Protocol: "oidc", Label: "Logout token: repeated jti", Logout: true},
}

func tamperFaultInfoByID(id tamperFault) (tamperFaultInfo, bool) {
	for _, info := range tamperFaults {
		if info.ID == id {
			return info, true
		}
	}
	return tamperFaultInfo{}, false
}

// tamperFaultsFor lists the tamper faults that apply to an app protocol.
func tamperFaultsFor(protocol string) []tamperFaultInfo {
	var faults []tamperFaultInfo
	for _, info := range tamperFaults {
		if protocol == "both" || info.Protocol == "both" || info.Protocol == protocol {
			faults = append(faults, info)
		}
	}
	return faults
}

func parseFaultOptions(values url.Values) faultOptions {
	faults, _ := parseFaultOptionsWithWarnings(values)
	return faults
}

// parseFaultOptionsWithWarnings additionally reports values that were
// requested but unusable, so a typo does not silently produce a healthy flow.
func parseFaultOptionsWithWarnings(values url.Values) (faultOptions, []string) {
	var faults faultOptions
	var warnings []string
	if raw := strings.TrimSpace(values.Get("fault_id_token_ttl")); raw != "" {
		ttl, err := time.ParseDuration(raw)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("ignored invalid fault_id_token_ttl %q", raw))
		} else {
			faults.IDTokenTTL = ttl
			faults.IDTokenTTLSet = true
		}
	}
	if raw := strings.TrimSpace(values.Get("fault_assertion_ttl")); raw != "" {
		ttl, err := time.ParseDuration(raw)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("ignored invalid fault_assertion_ttl %q", raw))
		} else {
			faults.AssertionTTL = ttl
			faults.AssertionTTLSet = true
		}
	}
	if raw := strings.TrimSpace(values.Get("fault_clock_skew")); raw != "" {
		skew, err := time.ParseDuration(raw)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("ignored invalid fault_clock_skew %q", raw))
		} else {
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
	switch raw := strings.TrimSpace(values.Get("fault_saml_status")); strings.ToLower(raw) {
	case "responder":
		faults.SAMLStatus = "urn:oasis:names:tc:SAML:2.0:status:Responder"
	case "authnfailed":
		faults.SAMLStatus = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"
	case "":
	default:
		warnings = append(warnings, fmt.Sprintf("ignored invalid fault_saml_status %q; use Responder or AuthnFailed", raw))
	}
	// Form checkboxes repeat the parameter; URLs and the API join values
	// with commas.
	for _, raw := range values["fault_tamper"] {
		for _, name := range strings.Split(raw, ",") {
			fault := tamperFault(strings.TrimSpace(name))
			if fault == "" || slices.Contains(faults.Tamper, fault) {
				continue
			}
			if _, ok := tamperFaultInfoByID(fault); !ok {
				warnings = append(warnings, fmt.Sprintf("ignored unknown fault_tamper %q", fault))
				continue
			}
			faults.Tamper = append(faults.Tamper, fault)
		}
	}
	return faults, warnings
}

// active reports whether any fault was requested.
func (f faultOptions) active() bool {
	return f.IDTokenTTLSet || f.AssertionTTLSet || f.ClockSkew != 0 || f.BreakSignature ||
		len(f.DropClaims) > 0 || f.TokenError != "" || f.SAMLStatus != "" ||
		len(f.Tamper) > 0
}

func (f faultOptions) tampers(fault tamperFault) bool {
	return slices.Contains(f.Tamper, fault)
}

// splitLogout separates the tamper faults that break back-channel logout
// tokens from the faults that apply to sign-ins.
func (f faultOptions) splitLogout() (signIn, logout faultOptions) {
	signIn = f
	signIn.Tamper = nil
	for _, fault := range f.Tamper {
		if info, _ := tamperFaultInfoByID(fault); info.Logout {
			logout.Tamper = append(logout.Tamper, fault)
			continue
		}
		signIn.Tamper = append(signIn.Tamper, fault)
	}
	return signIn, logout
}

// describe renders the requested faults for banners and flow records.
func (f faultOptions) describe() string {
	var parts []string
	if f.IDTokenTTLSet {
		parts = append(parts, "ID token TTL "+f.IDTokenTTL.String())
	}
	if f.AssertionTTLSet {
		parts = append(parts, "assertion TTL "+f.AssertionTTL.String())
	}
	if f.ClockSkew != 0 {
		parts = append(parts, "clock skew "+f.ClockSkew.String())
	}
	if f.BreakSignature {
		parts = append(parts, "broken signature")
	}
	if len(f.DropClaims) > 0 {
		parts = append(parts, "dropped claims "+strings.Join(f.DropClaims, ","))
	}
	if f.TokenError != "" {
		parts = append(parts, "token error "+f.TokenError)
	}
	if f.SAMLStatus != "" {
		parts = append(parts, "SAML status "+f.SAMLStatus[strings.LastIndex(f.SAMLStatus, ":")+1:])
	}
	if len(f.Tamper) > 0 {
		names := make([]string, len(f.Tamper))
		for i, fault := range f.Tamper {
			names[i] = string(fault)
		}
		parts = append(parts, "tamper "+strings.Join(names, ","))
	}
	return strings.Join(parts, "; ")
}

// Armed faults apply to the next flow regardless of where it starts, which
// URL parameters cannot do for SP-initiated sign-ins. They are consumed by
// the first flow that reaches code or response issuance.

func (a *webApp) armFaults(slug string, faults faultOptions) {
	a.faultMu.Lock()
	defer a.faultMu.Unlock()
	if a.armedFaults == nil {
		a.armedFaults = make(map[string]faultOptions)
	}
	a.armedFaults[slug] = faults
}

// peekArmedFaults reports the armed faults without consuming them.
func (a *webApp) peekArmedFaults(slug string) faultOptions {
	a.faultMu.Lock()
	defer a.faultMu.Unlock()
	return a.armedFaults[slug]
}

// takeArmedFaults consumes the armed faults so they apply to one flow only.
// Logout token faults stay armed for the next back-channel logout.
func (a *webApp) takeArmedFaults(slug string) faultOptions {
	a.faultMu.Lock()
	defer a.faultMu.Unlock()
	signIn, logout := a.armedFaults[slug].splitLogout()
	a.rearmFaults(slug, logout)
	return signIn
}

// takeArmedLogoutFaults consumes the armed logout token faults so they apply
// to one logout token only. Sign-in faults stay armed.
func (a *webApp) takeArmedLogoutFaults(slug string) faultOptions {
	a.faultMu.Lock()
	defer a.faultMu.Unlock()
	signIn, logout := a.armedFaults[slug].splitLogout()
	a.rearmFaults(slug, signIn)
	return logout
}

// rearmFaults leaves faults armed for slug, or disarms it when none remain.
// The caller holds faultMu.
func (a *webApp) rearmFaults(slug string, faults faultOptions) {
	if !faults.active() {
		delete(a.armedFaults, slug)
		return
	}
	a.armedFaults[slug] = faults
}

func (a *webApp) disarmFaults(slug string) {
	a.faultMu.Lock()
	defer a.faultMu.Unlock()
	delete(a.armedFaults, slug)
}

// flowFaults resolves the faults for a flow: explicit fault_* parameters
// win, otherwise armed faults are consumed.
func (a *webApp) flowFaults(slug string, values url.Values) faultOptions {
	faults, _ := parseFaultOptions(values).splitLogout()
	if faults.active() {
		return faults
	}
	faults = a.takeArmedFaults(slug)
	if faults.active() {
		return faults
	}
	return a.takeResilienceFlowFaults(slug, time.Now())
}

func supportsAnyIDP(foundApp app) bool { return supportsOIDC(foundApp) || supportsSAML(foundApp) }

func inspectorReturnPath(r *http.Request, foundApp app) string {
	switch r.FormValue("return_tab") {
	case "oidc-inspector":
		return dashboardURL("oidc-inspector", map[string]string{"environment": foundApp.ID})
	case "saml-inspector":
		return dashboardURL("saml-inspector", map[string]string{"environment": foundApp.ID})
	}
	if ref, err := url.Parse(r.Referer()); err == nil {
		tab := normalizedTab(ref.Query().Get("tab"))
		if ref.Path == "/" && (tab == "oidc-inspector" || tab == "saml-inspector") {
			return dashboardURL(tab, map[string]string{"environment": foundApp.ID})
		}
		if strings.HasPrefix(ref.Path, "/inspect/") {
			return ref.Path
		}
	}
	if supportsOIDC(foundApp) {
		return "/inspect/oidc/" + url.PathEscape(foundApp.Slug)
	}
	return "/inspect/saml/" + url.PathEscape(foundApp.Slug)
}

func (a *webApp) handleFaultArm(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsAnyIDP)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	faults, warnings := parseFaultOptionsWithWarnings(r.Form)
	for _, warning := range warnings {
		a.recordFlowEvent(foundApp.Slug, "fault", "arm", "failed", "", warning)
	}
	if faults.active() {
		a.armFaults(foundApp.Slug, faults)
		a.recordFlowEvent(foundApp.Slug, "fault", "arm", "ok", "", "Armed for the next flow: "+faults.describe())
	}
	http.Redirect(w, r, inspectorReturnPath(r, foundApp), http.StatusSeeOther)
}

func (a *webApp) handleFaultDisarm(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsAnyIDP)
	if !ok {
		return
	}
	a.disarmFaults(foundApp.Slug)
	a.recordFlowEvent(foundApp.Slug, "fault", "arm", "ok", "", "Disarmed")
	http.Redirect(w, r, inspectorReturnPath(r, foundApp), http.StatusSeeOther)
}

func (f faultOptions) applyToClaims(claims map[string]any, issued time.Time) {
	f.dropClaims(claims)
	if f.tampers(tamperWrongIssuer) {
		claims["iss"] = nearMiss(claims["iss"])
	}
	if f.tampers(tamperWrongAudience) {
		claims["aud"] = nearMiss(claims["aud"])
	}
	if f.tampers(tamperNonceMismatch) {
		claims["nonce"] = nearMiss(claims["nonce"])
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

func (f faultOptions) dropClaims(claims map[string]any) {
	for _, claim := range f.DropClaims {
		delete(claims, claim)
	}
}

// nearMiss derives a wrong value that still starts with the right one, so an
// app comparing prefixes is caught along with one that never compares.
func nearMiss(value any) string {
	if text, ok := value.(string); ok && text != "" {
		return text + "-wrong"
	}
	return "scimtest-wrong"
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
