package web

import (
	"errors"
	"net/http"
	"slices"
	"time"
)

// idpSessionLifetime bounds an IdP session after its latest sign-in, and the
// cookie that names it.
const idpSessionLifetime = 30 * 24 * time.Hour

// idpSession is one browser's sign-in at an environment's IdP. OIDC and SAML
// sign-ins from that browser share it, ID tokens carry its ID as sid, and
// later flows can reuse its sign-in until it ends. Sessions live in memory,
// like tokens, so restarting scimtest ends them all.
type idpSession struct {
	ID        string
	AppSlug   string
	User      string // the user's label at the latest sign-in
	SignIn    signIn // the latest sign-in
	Started   time.Time
	Protocols []string // protocols that signed in through it, in first-use order
	EndReason string   // why it ended; empty while it is live

	// OIDCIssuer is the iss of the ID tokens issued in the session. It stays
	// empty until the app redeems a code, and ending a session that has it
	// sends a back-channel logout token.
	OIDCIssuer string

	// SAMLSessionIndex is the SessionIndex the session's SAML assertions
	// carry, and SAMLNameID and SAMLNameIDFormat are the NameID the SP
	// received at the latest SAML sign-in. They stay empty until a SAML
	// sign-in completes. Single Logout matches LogoutRequests against them.
	SAMLSessionIndex string
	SAMLNameID       string
	SAMLNameIDFormat string
}

// idpSessionView is a live session as the OIDC inspector and the API show it.
type idpSessionView struct {
	SessionID     string   `json:"session_id"`
	UserID        string   `json:"user_id"`
	User          string   `json:"user"`
	SignedInAt    string   `json:"signed_in_at"`
	AuthnStrength string   `json:"authn_strength"`
	Method        string   `json:"-"`
	Protocols     []string `json:"protocols"`
	StartedAt     string   `json:"started_at"`

	SAMLSessionIndex string `json:"saml_session_index,omitempty"`
	SAMLNameID       string `json:"saml_name_id,omitempty"`
}

func (s idpSession) view() idpSessionView {
	return idpSessionView{
		SessionID:     s.ID,
		UserID:        s.SignIn.UserID,
		User:          s.User,
		SignedInAt:    s.SignIn.Time.UTC().Format(time.RFC3339),
		AuthnStrength: s.SignIn.Strength.ID,
		Method:        s.SignIn.Strength.Label,
		Protocols:     s.Protocols,
		StartedAt:     s.Started.UTC().Format(time.RFC3339),

		SAMLSessionIndex: s.SAMLSessionIndex,
		SAMLNameID:       s.SAMLNameID,
	}
}

// browserIdPSession returns the live session that the browser's cookie names
// for slug.
func (a *webApp) browserIdPSession(r *http.Request, slug string) (idpSession, bool) {
	cookie, err := r.Cookie(signInCookieName(slug))
	if err != nil {
		return idpSession{}, false
	}
	return a.liveIdPSession(slug, cookie.Value)
}

// liveIdPSession returns slug's session id while it is live.
func (a *webApp) liveIdPSession(slug, id string) (idpSession, bool) {
	a.expireIdPSessions(time.Now())
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	session, ok := a.idpSessions[id]
	if !ok || session.AppSlug != slug {
		return idpSession{}, false
	}
	return session, true
}

// liveIdPSessions lists slug's live sessions, latest sign-in first.
func (a *webApp) liveIdPSessions(slug string) []idpSessionView {
	a.expireIdPSessions(time.Now())
	a.sessionMu.Lock()
	var sessions []idpSession
	for _, session := range a.idpSessions {
		if session.AppSlug == slug {
			sessions = append(sessions, session)
		}
	}
	a.sessionMu.Unlock()
	slices.SortFunc(sessions, func(x, y idpSession) int { return y.SignIn.Time.Compare(x.SignIn.Time) })
	views := make([]idpSessionView, len(sessions))
	for i, session := range sessions {
		views[i] = session.view()
	}
	return views
}

// joinIdPSession records a completed sign-in in the browser's session for
// slug, sets the cookie that names the session, and returns its ID. A sign-in
// by the session's own user updates the session, so reusing it or signing in
// again keeps the sid. A sign-in by another user ends the browser's session
// and starts a new one.
func (a *webApp) joinIdPSession(w http.ResponseWriter, r *http.Request, slug string, user user, signIn signIn, protocol string) (string, error) {
	current, live := a.browserIdPSession(r, slug)
	if live && current.SignIn.UserID != user.ID {
		a.endAppIdPSessions(slug, current.ID, "replaced by a sign-in as "+userLabel(user))
	}
	a.sessionMu.Lock()
	session, ok := a.idpSessions[current.ID]
	if !ok || session.SignIn.UserID != user.ID {
		id, err := randomSecret(24)
		if err != nil {
			a.sessionMu.Unlock()
			return "", err
		}
		session = idpSession{ID: id, AppSlug: slug, Started: time.Now()}
	}
	session.User = userLabel(user)
	session.SignIn = signIn
	if !slices.Contains(session.Protocols, protocol) {
		session.Protocols = append(slices.Clone(session.Protocols), protocol)
	}
	if a.idpSessions == nil {
		a.idpSessions = make(map[string]idpSession)
	}
	a.idpSessions[session.ID] = session
	a.sessionMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     signInCookieName(slug),
		Value:    session.ID,
		Path:     "/",
		MaxAge:   int(idpSessionLifetime / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return session.ID, nil
}

// noteIDTokenIssued records that sessionID issued an ID token under issuer.
func (a *webApp) noteIDTokenIssued(sessionID, issuer string) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	session, ok := a.idpSessions[sessionID]
	if !ok {
		return
	}
	session.OIDCIssuer = issuer
	a.idpSessions[sessionID] = session
}

// noteSAMLSignIn records the NameID that a SAML sign-in in sessionID sent,
// and returns the session's SessionIndex. The session's first SAML sign-in
// creates it, and later ones reuse it.
func (a *webApp) noteSAMLSignIn(sessionID, nameID, nameIDFormat string) (string, error) {
	a.sessionMu.Lock()
	defer a.sessionMu.Unlock()
	session, ok := a.idpSessions[sessionID]
	if !ok {
		return "", errors.New("the IdP session ended during sign-in")
	}
	if session.SAMLSessionIndex == "" {
		index, err := newID("saml-session")
		if err != nil {
			return "", err
		}
		session.SAMLSessionIndex = index
	}
	session.SAMLNameID = nameID
	session.SAMLNameIDFormat = nameIDFormat
	a.idpSessions[sessionID] = session
	return session.SAMLSessionIndex, nil
}

// handleOIDCSessionEnd ends one IdP session, or every session in the
// environment, as an administrator would.
func (a *webApp) handleOIDCSessionEnd(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.endAppIdPSessions(foundApp.Slug, r.FormValue("session_id"), "ended from the OIDC inspector")
	http.Redirect(w, r, inspectorReturnPath(r, foundApp), http.StatusSeeOther)
}

// forgetIdPSession deletes the browser's cookie for slug's session.
func forgetIdPSession(w http.ResponseWriter, slug string) {
	http.SetCookie(w, &http.Cookie{
		Name:     signInCookieName(slug),
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// endIdPSessions ends every live session for which reason returns a non-empty
// reason, records each in the environment's flow activity, sends back-channel
// logout tokens for them, and returns them with EndReason set. Every way a
// session ends goes through here: the end session endpoint, the inspector and
// the API, user deactivation or deletion, a sign-in that replaces the
// browser's session, and expiry.
func (a *webApp) endIdPSessions(reason func(idpSession) string) []idpSession {
	a.sessionMu.Lock()
	var ended []idpSession
	for id, session := range a.idpSessions {
		session.EndReason = reason(session)
		if session.EndReason == "" {
			continue
		}
		delete(a.idpSessions, id)
		ended = append(ended, session)
	}
	a.sessionMu.Unlock()
	slices.SortFunc(ended, func(x, y idpSession) int { return x.Started.Compare(y.Started) })
	for _, session := range ended {
		a.recordFlowEvent(session.AppSlug, "idp", "session", "ok", session.User, "Session "+session.ID+" ended: "+session.EndReason)
	}
	a.sendBackchannelLogouts(ended)
	return ended
}

// endAppIdPSessions ends slug's session sessionID, or all of slug's sessions
// when sessionID is empty.
func (a *webApp) endAppIdPSessions(slug, sessionID, reason string) []idpSession {
	return a.endIdPSessions(func(session idpSession) string {
		if session.AppSlug != slug || (sessionID != "" && session.ID != sessionID) {
			return ""
		}
		return reason
	})
}

// endInactiveUserSessions ends the environment's sessions whose user state no
// longer has as active, and returns them.
func (a *webApp) endInactiveUserSessions(state appState) []idpSession {
	found, ok := appByID(state.Apps, state.Environment.ID)
	if !ok {
		return nil
	}
	return a.endIdPSessions(func(session idpSession) string {
		if session.AppSlug != found.Slug {
			return ""
		}
		current, ok := userByID(state.Users, session.SignIn.UserID)
		switch {
		case !ok || current.Deleted:
			return "user deleted"
		case !current.Active:
			return "user deactivated"
		}
		return ""
	})
}

// expireIdPSessions ends sessions whose latest sign-in is older than
// idpSessionLifetime.
func (a *webApp) expireIdPSessions(now time.Time) {
	a.endIdPSessions(func(session idpSession) string {
		if session.SignIn.Time.Add(idpSessionLifetime).After(now) {
			return ""
		}
		return "expired"
	})
}
