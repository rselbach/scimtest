package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rselbach/scimtest/internal/auth"
	"github.com/rselbach/scimtest/internal/protocol"
)

const (
	enrollmentLifetime     = 10 * time.Minute
	enrollmentPollSeconds  = 2
	pendingEnrollmentLimit = 1000
	oauthIntentLimit       = 1000
	oauthIntentsPerIPLimit = 20
	oauthIntentLifetime    = 10 * time.Minute

	enrollmentConfirmCookieName = "scimtest_enroll_confirm"
)

type oauthIntentKind uint8

const (
	oauthIntentDashboard oauthIntentKind = iota + 1
	oauthIntentEnrollment
)

type oauthIntent struct {
	kind           oauthIntentKind
	enrollmentHash [32]byte
	codeVerifier   string
	clientIP       string
	expiresAt      time.Time
}

type pendingEnrollment struct {
	userCode           string
	browserHandoffHash [32]byte
	profileID          string
	instanceID         string
	instancePublicKey  string
	legacyInstanceID   string
	clientIP           string
	createdAt          time.Time
	expiresAt          time.Time
	approvedAt         time.Time
	actor              enrollmentActor
}

type enrollmentPageData struct {
	UserCode             string
	CSRFToken            string
	ApplicationName      string
	InstanceFingerprint  string
	ShowVerificationCode bool
}

const enrollmentPageStyles = `<style>
    :root {
      color-scheme: light;
      --bg: #f4f5f7;
      --card: #ffffff;
      --line: #e5e7eb;
      --line-strong: #d1d5db;
      --text: #1f2328;
      --text-strong: #0c0c0d;
      --muted: #6b7280;
      --accent: #1563ff;
      --accent-strong: #1051d8;
      --accent-soft: #e7eeff;
      --success: #00853e;
      --success-soft: #dcefe2;
      --topbar: #0c0c0d;
      --radius: 6px;
      --radius-lg: 8px;
      --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Helvetica, Arial, sans-serif;
    }
    *, *::before, *::after { box-sizing: border-box; }
    html, body { min-height: 100%; }
    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
      font-size: 13.5px;
      line-height: 1.5;
    }
    .topbar {
      display: flex;
      align-items: center;
      gap: 12px;
      height: 52px;
      padding: 0 16px;
      border-bottom: 1px solid #16171b;
      background: var(--topbar);
      color: #fff;
    }
    .brand { display: inline-flex; align-items: center; gap: 9px; font-size: 14px; font-weight: 600; letter-spacing: -.01em; }
    .brand-glyph { display: inline-flex; align-items: center; justify-content: center; width: 26px; height: 26px; }
    .topbar-context { margin-left: auto; color: #aeb4bf; font-size: 11px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase; }
    .shell { display: grid; min-height: calc(100vh - 52px); padding: 48px 20px 64px; place-items: center; }
    .card {
      width: min(100%, 600px);
      overflow: hidden;
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      background: var(--card);
      box-shadow: 0 1px 3px rgba(15, 23, 42, .06), 0 1px 2px rgba(15, 23, 42, .03);
    }
    .card-body { padding: 32px; }
    .heading { display: flex; align-items: flex-start; gap: 14px; }
    .page-icon {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      flex: 0 0 auto;
      width: 40px;
      height: 40px;
      border: 1px solid var(--line);
      border-radius: var(--radius-lg);
      color: var(--text-strong);
      box-shadow: 0 1px 2px rgba(15, 23, 42, .04);
    }
    .page-icon.success { border-color: #b9ddc7; background: var(--success-soft); color: var(--success); }
    .eyebrow { margin-bottom: 2px; color: var(--accent); font-size: 10.5px; font-weight: 700; letter-spacing: .08em; text-transform: uppercase; }
    .eyebrow.success { color: var(--success); }
    h1 { margin: 0; color: var(--text-strong); font-size: 24px; line-height: 1.2; letter-spacing: -.015em; }
    h2 { margin: 0; color: var(--text-strong); font-size: 13px; }
    p { margin: 0; }
    .lede { margin: 14px 0 24px; color: var(--muted); font-size: 14px; }
    .verification {
      padding: 16px;
      border: 1px solid #cbd9ff;
      border-radius: var(--radius);
      background: linear-gradient(135deg, #f3f7ff, #fff 72%);
    }
    .verification-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .required { color: var(--accent); font-size: 10.5px; font-weight: 700; letter-spacing: .06em; text-transform: uppercase; }
    .verification p { margin-top: 4px; color: var(--muted); font-size: 12.5px; }
    .verification-code {
      display: block;
      margin-top: 14px;
      padding: 12px 14px;
      overflow-wrap: anywhere;
      border: 1px solid #c7d5ff;
      border-radius: var(--radius);
      background: var(--card);
      color: var(--text-strong);
      font: 700 18px/1.35 var(--mono);
      letter-spacing: .06em;
      text-align: center;
    }
    .details { display: grid; margin: 24px 0 0; border-top: 1px solid var(--line); }
    .details div { display: grid; grid-template-columns: 150px minmax(0, 1fr); gap: 16px; padding: 12px 0; border-bottom: 1px solid var(--line); }
    .details dt { color: var(--muted); font-weight: 600; }
    .details dd { min-width: 0; margin: 0; color: var(--text-strong); font-weight: 500; overflow-wrap: anywhere; }
    .details code { font: 12px/1.5 var(--mono); }
    .caution { display: flex; gap: 9px; margin: 20px 0; color: var(--muted); font-size: 12.5px; }
    .caution svg { flex: 0 0 auto; margin-top: 1px; color: var(--accent); }
    form { margin: 0; }
    .primary {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      min-height: 40px;
      padding: 0 16px;
      border: 1px solid var(--accent);
      border-radius: var(--radius);
      background: var(--accent);
      color: #fff;
      font: inherit;
      font-size: 13px;
      font-weight: 600;
      line-height: 1;
      cursor: pointer;
      transition: background-color 80ms, border-color 80ms;
    }
    .primary:hover { border-color: var(--accent-strong); background: var(--accent-strong); }
    .primary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    .card-footer { padding: 13px 32px; border-top: 1px solid var(--line); background: #f9fafb; color: var(--muted); font-size: 12px; }
    .complete-card .lede { margin-bottom: 20px; }
    .next-step { display: flex; align-items: center; gap: 9px; padding: 12px 14px; border: 1px solid #b9ddc7; border-radius: var(--radius); background: var(--success-soft); color: #0e5b32; font-weight: 600; }
    .status-dot { width: 7px; height: 7px; flex: 0 0 auto; border-radius: 50%; background: var(--success); }
    @media (max-width: 520px) {
      .topbar-context { display: none; }
      .shell { align-items: start; padding: 24px 12px 40px; }
      .card-body { padding: 24px 20px; }
      .details div { grid-template-columns: 1fr; gap: 3px; }
      .primary { width: 100%; }
      .card-footer { padding: 13px 20px; }
    }
    @media (prefers-reduced-motion: reduce) {
      .primary { transition: none; }
    }
  </style>`

var enrollmentTemplate = template.Must(template.New("enrollment").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Authorize scimtest installation</title>
` + enrollmentPageStyles + `
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <span class="brand-glyph" aria-hidden="true">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3.5 10a8 8 0 0 1 13.6-5.5L19 7"/><polyline points="19 3 19 7 15 7"/>
          <path d="M20.5 14a8 8 0 0 1-13.6 5.5L5 17"/><polyline points="5 21 5 17 9 17"/>
        </svg>
      </span>
      scimtest
    </div>
    <span class="topbar-context">installation authorization</span>
  </header>
  <div class="shell">
    <main class="card">
      <div class="card-body">
        <div class="heading">
          <span class="page-icon" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10 2.5l6 2.4v4.4c0 3.8-2.4 6.6-6 8.2-3.6-1.6-6-4.4-6-8.2V4.9z"/><path d="M7.3 10l1.7 1.7 3.8-4"/>
            </svg>
          </span>
          <div>
            <div class="eyebrow">New installation</div>
            <h1>Authorize this installation</h1>
          </div>
        </div>
        <p class="lede">GitHub confirms who is responsible for this installation before scimtest assigns it a public tunnel.</p>

        {{if .ShowVerificationCode}}<section class="verification" aria-labelledby="verification-heading">
          <div class="verification-head">
            <h2 id="verification-heading">Match this code</h2>
            <span class="required">Required</span>
          </div>
          <p>Compare it with the verification code shown by scimtest on this computer.</p>
          <code class="verification-code">{{.UserCode}}</code>
        </section>{{end}}

        <dl class="details">
          <div><dt>Application</dt><dd>{{.ApplicationName}}</dd></div>
          <div><dt>Installation fingerprint</dt><dd><code>{{.InstanceFingerprint}}</code></dd></div>
        </dl>

        {{if .ShowVerificationCode}}<div class="caution">
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="8" r="6.25"/><path d="M8 7v3.5M8 4.7v.1"/></svg>
          <p>If the codes do not match, close this page. Continuing would authorize a different installation.</p>
        </div>{{end}}

        <form method="post" action="/enroll">
          <input type="hidden" name="code" value="{{.UserCode}}">
          <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
          <button class="primary" type="submit">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .7a11.5 11.5 0 0 0-3.6 22.4c.6.1.8-.2.8-.5v-2c-3.4.7-4.1-1.4-4.1-1.4-.6-1.4-1.4-1.8-1.4-1.8-1.1-.8.1-.8.1-.8 1.3.1 1.9 1.3 1.9 1.3 1.1 1.9 2.9 1.4 3.6 1.1.1-.8.4-1.4.8-1.7-2.7-.3-5.5-1.3-5.5-5.7 0-1.3.5-2.3 1.2-3.1-.1-.3-.5-1.5.1-3.1 0 0 1-.3 3.2 1.2a11 11 0 0 1 5.8 0C15.3 5.1 16.3 5.4 16.3 5.4c.6 1.6.2 2.8.1 3.1.8.8 1.2 1.8 1.2 3.1 0 4.4-2.8 5.4-5.5 5.7.4.4.8 1.1.8 2.2v3.1c0 .3.2.6.8.5A11.5 11.5 0 0 0 12 .7z"/></svg>
            Continue with GitHub
          </button>
        </form>
      </div>
      <div class="card-footer">This authorization request expires after 10 minutes.</div>
    </main>
  </div>
</body>
</html>`))

var enrollmentCompleteTemplate = template.Must(template.New("enrollment-complete").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>scimtest installation authorized</title>
` + enrollmentPageStyles + `
</head>
<body>
  <header class="topbar">
    <div class="brand">
      <span class="brand-glyph" aria-hidden="true">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
          <path d="M3.5 10a8 8 0 0 1 13.6-5.5L19 7"/><polyline points="19 3 19 7 15 7"/>
          <path d="M20.5 14a8 8 0 0 1-13.6 5.5L5 17"/><polyline points="5 21 5 17 9 17"/>
        </svg>
      </span>
      scimtest
    </div>
    <span class="topbar-context">installation authorization</span>
  </header>
  <div class="shell">
    <main class="card complete-card">
      <div class="card-body">
        <div class="heading">
          <span class="page-icon success" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="10" r="7.5"/><path d="M6.5 10.1l2.2 2.2 4.8-5"/></svg>
          </span>
          <div>
            <div class="eyebrow success">Authorization complete</div>
            <h1>Installation authorized</h1>
          </div>
        </div>
        <p class="lede">Your GitHub identity has been linked to this scimtest installation.</p>
        <div class="next-step"><span class="status-dot" aria-hidden="true"></span>scimtest is finishing setup on this computer.</div>
      </div>
      <div class="card-footer">You can close this browser tab.</div>
    </main>
  </div>
</body>
</html>`))

func (s *Server) beginEnrollment(profileID, instanceID, instancePublicKey, legacyInstanceID, clientIP string) (protocol.Message, error) {
	if !s.githubConfigured() {
		return protocol.Message{}, errors.New("installation authorization is unavailable because GitHub OAuth is not configured")
	}
	deviceCode, err := randomHex(32)
	if err != nil {
		return protocol.Message{}, errors.New("could not create installation authorization")
	}
	deviceHash := sha256.Sum256([]byte(deviceCode))
	userCode, err := randomHex(12)
	if err != nil {
		return protocol.Message{}, errors.New("could not create installation authorization")
	}
	browserHandoff, err := randomHex(32)
	if err != nil {
		return protocol.Message{}, errors.New("could not create installation authorization")
	}
	browserHandoffHash := sha256.Sum256([]byte(browserHandoff))

	now := time.Now().UTC()
	clientIP = enrollmentIPKey(clientIP)
	binding := enrollmentBinding(profileID, instanceID, instancePublicKey, legacyInstanceID)
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(now)

	if oldHash, exists := s.pendingByBinding[binding]; exists {
		if old, ok := s.pendingEnrollments[oldHash]; ok {
			s.deletePendingEnrollmentLocked(oldHash, old)
		}
	}
	pendingFromIP := 0
	for _, pending := range s.pendingEnrollments {
		if pending.clientIP == clientIP && pending.approvedAt.IsZero() {
			pendingFromIP++
		}
	}
	if len(s.pruneEnrollmentsLocked(clientIP, now))+pendingFromIP >= enrollmentsPerIPLimit {
		return protocol.Message{}, errors.New(enrollmentThrottledMessage)
	}
	if len(s.pendingEnrollments) >= pendingEnrollmentLimit {
		return protocol.Message{}, errors.New("too many pending installation authorizations; try again later")
	}
	for attempts := 0; ; attempts++ {
		if _, exists := s.pendingEnrollments[deviceHash]; !exists {
			break
		}
		if attempts == maxRandomIDAttempts-1 {
			return protocol.Message{}, errors.New("could not create installation authorization")
		}
		deviceCode, err = randomHex(32)
		if err != nil {
			return protocol.Message{}, errors.New("could not create installation authorization")
		}
		deviceHash = sha256.Sum256([]byte(deviceCode))
	}
	for attempts := 0; ; attempts++ {
		if _, exists := s.pendingByUserCode[userCode]; !exists {
			break
		}
		if attempts == maxRandomIDAttempts-1 {
			return protocol.Message{}, errors.New("could not create installation authorization")
		}
		userCode, err = randomHex(12)
		if err != nil {
			return protocol.Message{}, errors.New("could not create installation authorization")
		}
	}
	for attempts := 0; ; attempts++ {
		if _, exists := s.pendingByHandoff[browserHandoffHash]; !exists {
			break
		}
		if attempts == maxRandomIDAttempts-1 {
			return protocol.Message{}, errors.New("could not create installation authorization")
		}
		browserHandoff, err = randomHex(32)
		if err != nil {
			return protocol.Message{}, errors.New("could not create installation authorization")
		}
		browserHandoffHash = sha256.Sum256([]byte(browserHandoff))
	}
	pending := pendingEnrollment{
		userCode:           userCode,
		browserHandoffHash: browserHandoffHash,
		profileID:          profileID,
		instanceID:         instanceID,
		instancePublicKey:  instancePublicKey,
		legacyInstanceID:   legacyInstanceID,
		clientIP:           clientIP,
		createdAt:          now,
		expiresAt:          now.Add(enrollmentLifetime),
	}
	s.pendingEnrollments[deviceHash] = pending
	s.pendingByUserCode[userCode] = deviceHash
	s.pendingByBinding[binding] = deviceHash
	s.pendingByHandoff[browserHandoffHash] = deviceHash

	return protocol.Message{
		Type:                        protocol.TypeEnrollmentRequired,
		EnrollmentURL:               s.cfg.PublicScheme + "://" + s.dashboardDomain() + "/enroll?code=" + userCode,
		EnrollmentBrowserHandoffURL: s.cfg.PublicScheme + "://" + s.dashboardDomain() + "/enroll/browser?handoff=" + browserHandoff,
		EnrollmentStatusURL:         s.cfg.PublicScheme + "://" + s.cfg.Domain + "/api/enroll/status",
		EnrollmentDeviceCode:        deviceCode,
		EnrollmentVerificationCode:  userCode,
		EnrollmentPollSeconds:       enrollmentPollSeconds,
	}, nil
}

func (s *Server) handleEnrollmentStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	deviceCode, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok || !validHexToken(deviceCode, 64) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "missing enrollment credential", http.StatusUnauthorized)
		return
	}
	deviceHash := sha256.Sum256([]byte(deviceCode))

	s.enrollMu.Lock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(time.Now().UTC())
	pending, exists := s.pendingEnrollments[deviceHash]
	s.enrollMu.Unlock()
	if !exists {
		http.Error(w, "installation authorization not found", http.StatusNotFound)
		return
	}
	status := "pending"
	if !pending.approvedAt.IsZero() {
		status = "approved"
	}
	if err := json.NewEncoder(w).Encode(protocol.EnrollmentStatus{Status: status}); err != nil {
		s.logger().Warn("enrollment status response failed", "err", err)
	}
}

func (s *Server) handleEnrollmentAuthorization(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.renderEnrollmentAuthorization(w, r)
	case http.MethodPost:
		s.startEnrollmentAuthorization(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleEnrollmentBrowserHandoff(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	handoff := r.URL.Query().Get("handoff")
	deviceHash, handoffHash, exists := s.takeEnrollmentBrowserHandoff(handoff)
	if !exists {
		http.Error(w, "installation authorization is invalid or expired", http.StatusGone)
		return
	}
	if !s.beginGitHubOAuth(w, r, oauthIntent{kind: oauthIntentEnrollment, enrollmentHash: deviceHash}) {
		s.restoreEnrollmentBrowserHandoff(handoffHash, deviceHash)
	}
}

func (s *Server) renderEnrollmentAuthorization(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("code")
	pending, exists := s.pendingEnrollmentByUserCode(userCode)
	if !exists {
		http.Error(w, "installation authorization is invalid or expired", http.StatusGone)
		return
	}
	profile, exists := s.store.ApplicationProfile(pending.profileID)
	if !exists {
		http.Error(w, "application profile not found", http.StatusNotFound)
		return
	}
	csrfToken, err := randomHex(24)
	if err != nil {
		http.Error(w, "could not create confirmation", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(enrollmentConfirmCookieName),
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(enrollmentLifetime.Seconds()),
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://github.com; frame-ancestors 'none'")
	if err := enrollmentTemplate.Execute(w, enrollmentPageData{
		UserCode:             userCode,
		CSRFToken:            csrfToken,
		ApplicationName:      profile.Name,
		InstanceFingerprint:  pending.instanceID,
		ShowVerificationCode: r.URL.Query().Get("presentation") != "desktop",
	}); err != nil {
		s.logger().Error("enrollment page render failed", "err", err)
	}
}

func (s *Server) startEnrollmentAuthorization(w http.ResponseWriter, r *http.Request) {
	if !s.allowedDashboardMutation(r) {
		http.Error(w, "invalid confirmation origin", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid confirmation", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie(s.cookieName(enrollmentConfirmCookieName))
	csrfToken := r.PostForm.Get("csrf_token")
	if err != nil || cookie.Value == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(csrfToken)) != 1 {
		http.Error(w, "invalid confirmation", http.StatusBadRequest)
		return
	}
	clearCookie(w, s.cookieName(enrollmentConfirmCookieName), s.cookieSecure())
	userCode := r.PostForm.Get("code")
	_, deviceHash, exists := s.pendingEnrollmentAndHashByUserCode(userCode)
	if !exists {
		http.Error(w, "installation authorization is invalid or expired", http.StatusGone)
		return
	}
	s.beginGitHubOAuth(w, r, oauthIntent{kind: oauthIntentEnrollment, enrollmentHash: deviceHash})
}

func (s *Server) beginGitHubOAuth(w http.ResponseWriter, r *http.Request, intent oauthIntent) bool {
	if !s.githubConfigured() {
		http.Error(w, "GitHub OAuth is not configured", http.StatusServiceUnavailable)
		return false
	}
	state, err := randomHex(24)
	if err != nil {
		http.Error(w, "could not create login state", http.StatusInternalServerError)
		return false
	}
	codeVerifier, err := randomHex(32)
	if err != nil {
		http.Error(w, "could not create login state", http.StatusInternalServerError)
		return false
	}
	verifierHash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(verifierHash[:])

	now := time.Now().UTC()
	clientIP := enrollmentIPKey(s.clientIP(r))
	s.enrollMu.Lock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(now)
	intentsFromIP := 0
	for state, existing := range s.oauthIntents {
		if intent.kind == oauthIntentEnrollment && existing.kind == oauthIntentEnrollment && existing.enrollmentHash == intent.enrollmentHash {
			delete(s.oauthIntents, state)
			continue
		}
		if existing.clientIP == clientIP {
			intentsFromIP++
		}
	}
	if intentsFromIP >= oauthIntentsPerIPLimit {
		s.enrollMu.Unlock()
		http.Error(w, "too many pending logins from this network; try again later", http.StatusTooManyRequests)
		return false
	}
	if len(s.oauthIntents) >= oauthIntentLimit {
		var oldestState string
		var oldestExpiry time.Time
		for state, existing := range s.oauthIntents {
			if oldestState == "" || existing.expiresAt.Before(oldestExpiry) {
				oldestState = state
				oldestExpiry = existing.expiresAt
			}
		}
		delete(s.oauthIntents, oldestState)
	}
	intent.codeVerifier = codeVerifier
	intent.clientIP = clientIP
	intent.expiresAt = now.Add(oauthIntentLifetime)
	s.oauthIntents[state] = intent
	s.enrollMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(stateCookieName),
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(oauthIntentLifetime.Seconds()),
	})
	http.Redirect(w, r, s.github.AuthorizeURL(state, s.callbackURL(), codeChallenge), http.StatusFound)
	return true
}

func (s *Server) takeEnrollmentBrowserHandoff(handoff string) ([32]byte, [32]byte, bool) {
	if !validHexToken(handoff, 64) {
		return [32]byte{}, [32]byte{}, false
	}
	handoffHash := sha256.Sum256([]byte(handoff))
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(time.Now().UTC())
	deviceHash, exists := s.pendingByHandoff[handoffHash]
	if !exists {
		return [32]byte{}, [32]byte{}, false
	}
	pending, exists := s.pendingEnrollments[deviceHash]
	if !exists || !pending.approvedAt.IsZero() {
		delete(s.pendingByHandoff, handoffHash)
		return [32]byte{}, [32]byte{}, false
	}
	delete(s.pendingByHandoff, handoffHash)
	return deviceHash, handoffHash, true
}

func (s *Server) restoreEnrollmentBrowserHandoff(handoffHash, deviceHash [32]byte) {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(time.Now().UTC())
	pending, exists := s.pendingEnrollments[deviceHash]
	if !exists || !pending.approvedAt.IsZero() || pending.browserHandoffHash != handoffHash {
		return
	}
	if _, exists := s.pendingByHandoff[handoffHash]; !exists {
		s.pendingByHandoff[handoffHash] = deviceHash
	}
}

func (s *Server) takeOAuthIntent(state string) (oauthIntent, bool) {
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(time.Now().UTC())
	intent, exists := s.oauthIntents[state]
	if exists {
		delete(s.oauthIntents, state)
	}
	return intent, exists
}

func (s *Server) approveEnrollment(deviceHash [32]byte, user auth.GitHubUser) error {
	if user.ID <= 0 || strings.TrimSpace(user.Login) == "" {
		return errors.New("GitHub returned an invalid user")
	}
	now := time.Now().UTC()
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(now)
	pending, exists := s.pendingEnrollments[deviceHash]
	if !exists {
		return errors.New("installation authorization is invalid or expired")
	}
	if !pending.approvedAt.IsZero() {
		return errors.New("installation authorization was already used")
	}
	if err := s.pruneIdleApplicationInstances(pending.profileID, now); err != nil {
		return fmt.Errorf("prune idle installations: %w", err)
	}
	limit := s.cfg.MaxInstallationsPerUser
	if limit <= 0 {
		limit = 5
	}
	count := s.enrollmentCountLocked(deviceHash, pending.profileID, user.ID)
	if count >= limit {
		return errInstallationLimitReached
	}
	s.approvePendingEnrollmentLocked(deviceHash, pending, user, now)
	return nil
}

func (s *Server) enrollmentCountLocked(deviceHash [32]byte, profileID string, userID int64) int {
	count := s.store.CountApplicationInstancesByGitHubUserID(profileID, userID)
	for hash, other := range s.pendingEnrollments {
		if hash != deviceHash && other.profileID == profileID && other.actor.GitHubUserID == userID && !other.approvedAt.IsZero() {
			count++
		}
	}
	return count
}

func (s *Server) approvePendingEnrollmentLocked(deviceHash [32]byte, pending pendingEnrollment, user auth.GitHubUser, now time.Time) {
	pending.actor = enrollmentActor{GitHubUserID: user.ID, GitHubLogin: user.Login}
	pending.approvedAt = now
	s.pendingEnrollments[deviceHash] = pending
	delete(s.pendingByHandoff, pending.browserHandoffHash)
	s.deleteReplacementIntentsForEnrollmentLocked(deviceHash)
	s.enrollments[pending.clientIP] = append(s.pruneEnrollmentsLocked(pending.clientIP, now), now)
}

func (s *Server) consumeEnrollmentGrant(grant, profileID, instanceID, instancePublicKey, legacyInstanceID string) error {
	if !validHexToken(grant, 64) {
		return errors.New("invalid or unapproved installation grant")
	}
	deviceHash := sha256.Sum256([]byte(grant))
	now := time.Now().UTC()
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(now)
	pending, exists := s.pendingEnrollments[deviceHash]
	if !exists || pending.approvedAt.IsZero() {
		return errors.New("invalid or unapproved installation grant")
	}
	if pending.profileID != profileID || pending.instanceID != instanceID || pending.instancePublicKey != instancePublicKey || pending.legacyInstanceID != legacyInstanceID {
		return errors.New("installation grant does not match this installation")
	}
	if err := s.store.EnrollApplicationInstance(profileID, instanceID, instancePublicKey, pending.actor); err != nil {
		return err
	}
	s.deletePendingEnrollmentLocked(deviceHash, pending)
	s.logger().Info("application instance enrolled",
		"profile_id", profileID,
		"instance_id", instanceID,
		"legacy_instance_id", legacyInstanceID,
		"github_user_id", pending.actor.GitHubUserID,
		"github_login", pending.actor.GitHubLogin,
		"client_ip", pending.clientIP,
	)
	return nil
}

func (s *Server) pendingEnrollmentByUserCode(userCode string) (pendingEnrollment, bool) {
	pending, _, exists := s.pendingEnrollmentAndHashByUserCode(userCode)
	return pending, exists
}

func (s *Server) pendingEnrollmentAndHashByUserCode(userCode string) (pendingEnrollment, [32]byte, bool) {
	if !validHexToken(userCode, 24) {
		return pendingEnrollment{}, [32]byte{}, false
	}
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(time.Now().UTC())
	deviceHash, exists := s.pendingByUserCode[userCode]
	if !exists {
		return pendingEnrollment{}, [32]byte{}, false
	}
	pending, exists := s.pendingEnrollments[deviceHash]
	return pending, deviceHash, exists
}

func (s *Server) initializeEnrollmentStateLocked() {
	if s.enrollments == nil {
		s.enrollments = make(map[string][]time.Time)
	}
	if s.pendingEnrollments == nil {
		s.pendingEnrollments = make(map[[32]byte]pendingEnrollment)
	}
	if s.pendingByUserCode == nil {
		s.pendingByUserCode = make(map[string][32]byte)
	}
	if s.pendingByBinding == nil {
		s.pendingByBinding = make(map[string][32]byte)
	}
	if s.pendingByHandoff == nil {
		s.pendingByHandoff = make(map[[32]byte][32]byte)
	}
	if s.oauthIntents == nil {
		s.oauthIntents = make(map[string]oauthIntent)
	}
	if s.replacementIntents == nil {
		s.replacementIntents = make(map[[32]byte]enrollmentReplacementIntent)
	}
}

func (s *Server) pruneEnrollmentStateLocked(now time.Time) {
	for hash, pending := range s.pendingEnrollments {
		if !now.Before(pending.expiresAt) {
			s.deletePendingEnrollmentLocked(hash, pending)
		}
	}
	for state, intent := range s.oauthIntents {
		if !now.Before(intent.expiresAt) {
			delete(s.oauthIntents, state)
		}
	}
	for hash, intent := range s.replacementIntents {
		if !now.Before(intent.expiresAt) {
			delete(s.replacementIntents, hash)
		}
	}
	for clientIP := range s.enrollments {
		s.pruneEnrollmentsLocked(clientIP, now)
	}
}

func (s *Server) pruneEnrollmentsLocked(clientIP string, now time.Time) []time.Time {
	cutoff := now.Add(-enrollmentWindow)
	recent := s.enrollments[clientIP][:0]
	for _, at := range s.enrollments[clientIP] {
		if at.After(cutoff) {
			recent = append(recent, at)
		}
	}
	if len(recent) == 0 {
		delete(s.enrollments, clientIP)
		return nil
	}
	s.enrollments[clientIP] = recent
	return recent
}

func (s *Server) deletePendingEnrollmentLocked(hash [32]byte, pending pendingEnrollment) {
	delete(s.pendingEnrollments, hash)
	s.deleteReplacementIntentsForEnrollmentLocked(hash)
	if current, exists := s.pendingByHandoff[pending.browserHandoffHash]; exists && current == hash {
		delete(s.pendingByHandoff, pending.browserHandoffHash)
	}
	if current, exists := s.pendingByUserCode[pending.userCode]; exists && current == hash {
		delete(s.pendingByUserCode, pending.userCode)
	}
	binding := enrollmentBinding(pending.profileID, pending.instanceID, pending.instancePublicKey, pending.legacyInstanceID)
	if current, exists := s.pendingByBinding[binding]; exists && current == hash {
		delete(s.pendingByBinding, binding)
	}
}

func (s *Server) githubConfigured() bool {
	return s.github.ClientID != "" && s.github.ClientSecret != ""
}

func enrollmentBinding(profileID, instanceID, instancePublicKey, legacyInstanceID string) string {
	return strings.Join([]string{profileID, instanceID, instancePublicKey, legacyInstanceID}, "\x00")
}

func enrollmentIPKey(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return strings.ToLower(strings.TrimSpace(value))
	}
	if ipv4 := ip.To4(); ipv4 != nil {
		return ipv4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

func (s *Server) dashboardOriginMatches(value string) bool {
	origin, err := url.Parse(value)
	if err != nil || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	expected, err := url.Parse(s.cfg.PublicScheme + "://" + s.dashboardDomain())
	if err != nil {
		return false
	}
	return strings.EqualFold(origin.Scheme, expected.Scheme) &&
		strings.EqualFold(origin.Hostname(), expected.Hostname()) &&
		originPort(origin) == originPort(expected)
}

// allowedDashboardMutation accepts a dashboard POST if it is same-origin with
// this request. The configured dashboard origin is the usual case. Loopback
// management hosts are also allowed when Host and Origin match, because
// baseHostOnly already admits them. Missing Origin is allowed only when the
// browser labels the request same-origin.
func (s *Server) allowedDashboardMutation(r *http.Request) bool {
	originValue := strings.TrimSpace(r.Header.Get("Origin"))
	if s.dashboardOriginMatches(originValue) {
		return true
	}
	if !s.isDashboardHost(r.Host) {
		return false
	}
	if originValue == "" {
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	if strings.EqualFold(originValue, "null") {
		return false
	}
	origin, err := url.Parse(originValue)
	if err != nil || origin.User != nil || strings.Trim(origin.Path, "/") != "" || origin.RawQuery != "" || origin.Fragment != "" {
		return false
	}
	if origin.Scheme != "http" && origin.Scheme != "https" {
		return false
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	return sameHost(origin.Host, r.Host) && originPort(origin) == hostPort(r.Host, origin.Scheme)
}

func originPort(value *url.URL) string {
	if port := value.Port(); port != "" {
		return port
	}
	if value.Scheme == "https" {
		return "443"
	}
	return "80"
}

func hostPort(host, scheme string) string {
	if _, port, err := net.SplitHostPort(host); err == nil {
		return port
	}
	if scheme == "https" {
		return "443"
	}
	return "80"
}

func bearerToken(value string) (string, bool) {
	scheme, token, found := strings.Cut(strings.TrimSpace(value), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func validHexToken(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}
