package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// authnStrength is how strongly the chooser says a user authenticated. It
// decides the OIDC acr and amr claims and the SAML AuthnContextClassRef.
type authnStrength struct {
	ID    string
	Label string
	AMR   []string // RFC 8176 authentication method references
	// Contexts are the acr values and SAML authentication context classes
	// that mean this strength. A flow echoes the one the app requested and
	// otherwise sends the first.
	Contexts []string
}

// authnStrengths lists the strengths the chooser offers. The first is the
// default.
var authnStrengths = []authnStrength{
	{
		ID:    "password",
		Label: "Password",
		AMR:   []string{"pwd"},
		Contexts: []string{
			"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			"urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
			"https://refeds.org/profile/sfa",
		},
	},
	{
		ID:    "mfa",
		Label: "Password + MFA",
		AMR:   []string{"pwd", "otp", "mfa"},
		Contexts: []string{
			"https://refeds.org/profile/mfa",
			"http://schemas.openid.net/pape/policies/2007/06/multi-factor",
			"http://schemas.microsoft.com/claims/multipleauthn",
		},
	},
}

func authnStrengthByID(id string) (authnStrength, bool) {
	for _, strength := range authnStrengths {
		if strength.ID == id {
			return strength, true
		}
	}
	return authnStrength{}, false
}

// supportedAuthnContexts lists every context a request can name.
func supportedAuthnContexts() []string {
	var contexts []string
	for _, strength := range authnStrengths {
		contexts = append(contexts, strength.Contexts...)
	}
	return contexts
}

// context returns the first requested context this strength satisfies, or
// its default.
func (s authnStrength) context(requested []string) string {
	for _, value := range requested {
		if slices.Contains(s.Contexts, value) {
			return value
		}
	}
	return s.Contexts[0]
}

// chosenAuthnStrength returns the strength named by authn_strength, else the
// first one the app requested, else the default.
func chosenAuthnStrength(values url.Values, requested []string) (authnStrength, error) {
	if id := strings.TrimSpace(values.Get("authn_strength")); id != "" {
		if strength, ok := authnStrengthByID(id); ok {
			return strength, nil
		}
		ids := make([]string, len(authnStrengths))
		for i, strength := range authnStrengths {
			ids[i] = strength.ID
		}
		return authnStrength{}, fmt.Errorf("authn_strength must be one of %s", strings.Join(ids, ", "))
	}
	for _, value := range requested {
		for _, strength := range authnStrengths {
			if slices.Contains(strength.Contexts, value) {
				return strength, nil
			}
		}
	}
	return authnStrengths[0], nil
}

// authnRequest is what an app asked of the sign-in.
type authnRequest struct {
	Passive bool // prompt=none: answer without showing the chooser
	// FreshReason names the parameter that rules out reusing a remembered
	// sign-in, such as prompt=login or ForceAuthn.
	FreshReason string
	MaxAge      time.Duration // oldest reusable sign-in when positive
	Contexts    []string      // acr_values or requested context classes, preferred first
}

// reuseBlocker reports why the request cannot reuse session, or "" when it
// can.
func (r authnRequest) reuseBlocker(session signIn, now time.Time) string {
	if r.FreshReason != "" {
		return r.FreshReason
	}
	if r.MaxAge > 0 && now.Sub(session.Time) > r.MaxAge {
		return "max_age=" + strconv.FormatInt(int64(r.MaxAge/time.Second), 10)
	}
	return ""
}

// signIn records who authenticated, when, and how strongly. The chooser
// cookie remembers the latest one per environment so a later flow can reuse
// it instead of signing in again.
type signIn struct {
	UserID   string
	Time     time.Time
	Strength authnStrength
}

// statement reports the sign-in to an app that requested contexts.
func (s signIn) statement(requested []string) authnStatement {
	return authnStatement{Time: s.Time, Context: s.Strength.context(requested), Methods: s.Strength.AMR}
}

// authnStatement says when and how a user authenticated: auth_time, acr, and
// amr in an ID token, AuthnInstant and AuthnContextClassRef in a SAML
// assertion.
type authnStatement struct {
	Time    time.Time
	Context string
	Methods []string
}

// addClaims adds auth_time, acr, and amr to ID token claims. skew shifts
// auth_time along with the token's other instants.
func (s authnStatement) addClaims(claims map[string]any, skew time.Duration) {
	claims["auth_time"] = s.Time.Add(skew).Unix()
	claims["acr"] = s.Context
	claims["amr"] = s.Methods
}

func signInCookieName(slug string) string { return "scimtest_chooser_" + slug }

// rememberSignIn records the sign-in for an environment so the chooser can
// preselect its user and offer to reuse it.
func rememberSignIn(w http.ResponseWriter, slug string, session signIn) {
	http.SetCookie(w, &http.Cookie{
		Name: signInCookieName(slug),
		Value: url.Values{
			"user":     {session.UserID},
			"time":     {strconv.FormatInt(session.Time.Unix(), 10)},
			"strength": {session.Strength.ID},
		}.Encode(),
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// rememberedSignIn returns the browser's last sign-in for an environment
// while its user is still active.
func rememberedSignIn(r *http.Request, users []user, slug string) (user, signIn, bool) {
	cookie, err := r.Cookie(signInCookieName(slug))
	if err != nil {
		return user{}, signIn{}, false
	}
	values, err := url.ParseQuery(cookie.Value)
	if err != nil {
		return user{}, signIn{}, false
	}
	seconds, err := strconv.ParseInt(values.Get("time"), 10, 64)
	if err != nil {
		return user{}, signIn{}, false
	}
	strength, ok := authnStrengthByID(values.Get("strength"))
	if !ok {
		return user{}, signIn{}, false
	}
	found, ok := userByID(users, values.Get("user"))
	if !ok || !found.Active || found.Deleted {
		return user{}, signIn{}, false
	}
	return found, signIn{UserID: found.ID, Time: time.Unix(seconds, 0), Strength: strength}, true
}

// chooserSignIn turns a chooser selection into a sign-in: the remembered one
// when continue_session is set, otherwise a fresh one at the chosen strength.
func chooserSignIn(r *http.Request, users []user, app app, values url.Values, request authnRequest, now time.Time) (user, signIn, error) {
	if isTruthy(values.Get("continue_session")) {
		found, session, ok := rememberedSignIn(r, users, app.Slug)
		if !ok {
			return user{}, signIn{}, errors.New("there is no remembered sign-in to reuse")
		}
		if reason := request.reuseBlocker(session, now); reason != "" {
			return user{}, signIn{}, fmt.Errorf("the app requires a fresh sign-in (%s)", reason)
		}
		return found, session, nil
	}
	found, ok := chooserUser(users, app, values)
	if !ok || !found.Active || found.Deleted {
		return user{}, signIn{}, errors.New("active user is required")
	}
	strength, err := chosenAuthnStrength(values, request.Contexts)
	if err != nil {
		return user{}, signIn{}, err
	}
	return found, signIn{UserID: found.ID, Time: now, Strength: strength}, nil
}
