package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/rselbach/scimtest/internal/auth"
)

const (
	enrollmentReplacementCookieName = "scimtest_enrollment_replacement"
	enrollmentReplacementLifetime   = 10 * time.Minute
)

var (
	errInstallationLimitReached       = errors.New("this account has reached scimtest's installation limit for this application")
	errEnrollmentReplacementExpired   = errors.New("installation replacement is invalid or expired")
	errEnrollmentReplacementForbidden = errors.New("the selected installation cannot be replaced")
)

type enrollmentReplacementIntent struct {
	enrollmentHash [32]byte
	githubUserID   int64
	githubLogin    string
	csrfToken      string
	expiresAt      time.Time
}

type enrollmentReplacementOption struct {
	InstanceID  string
	DisplayName string
	Activity    string
	Created     string
	Connected   bool
	Pending     bool
	Recommended bool
	lastUsedAt  time.Time
}

type enrollmentReplacementPageData struct {
	ApplicationName     string
	GitHubLogin         string
	InstanceFingerprint string
	Limit               int
	CSRFToken           string
	Notice              string
	Options             []enrollmentReplacementOption
}

const enrollmentReplacementStyles = `<style>
    .replacement-card { width: min(100%, 720px); }
    .replacement-summary {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin: 0 0 24px;
      border-top: 1px solid var(--line);
      border-bottom: 1px solid var(--line);
    }
    .replacement-summary div { min-width: 0; padding: 12px 14px 12px 0; }
    .replacement-summary div + div { padding-left: 14px; border-left: 1px solid var(--line); }
    .replacement-summary dt { color: var(--muted); font-size: 11px; font-weight: 600; }
    .replacement-summary dd { margin: 3px 0 0; overflow-wrap: anywhere; color: var(--text-strong); font-weight: 600; }
    .replacement-summary code { font: 11px/1.45 var(--mono); }
    .notice { margin: 0 0 16px; padding: 10px 12px; border: 1px solid #e8c66f; border-radius: var(--radius); background: #fff9e9; color: #684d08; }
    .installation-list { display: grid; gap: 10px; margin-top: 10px; }
    .installation-option {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 18px;
      align-items: center;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: #fff;
    }
    .installation-option.recommended { border-color: #b8caff; box-shadow: inset 3px 0 0 var(--accent); }
    .installation-title { display: flex; flex-wrap: wrap; align-items: center; gap: 7px; }
    .installation-title code { color: var(--text-strong); font: 700 13px/1.4 var(--mono); }
    .badge { display: inline-flex; align-items: center; min-height: 20px; padding: 0 7px; border-radius: 999px; background: var(--accent-soft); color: var(--accent-strong); font-size: 9.5px; font-weight: 700; letter-spacing: .05em; text-transform: uppercase; }
    .badge.connected { background: #fff0e8; color: #9a3412; }
    .installation-meta { display: flex; flex-wrap: wrap; gap: 5px 14px; margin-top: 6px; color: var(--muted); font-size: 11.5px; }
    .installation-note { margin-top: 7px; color: #9a3412; font-size: 11.5px; }
    .secondary, .danger {
      min-height: 38px;
      padding: 0 13px;
      border-radius: var(--radius);
      background: #fff;
      font: inherit;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
    }
    .secondary { border: 1px solid var(--line-strong); color: var(--text-strong); }
    .secondary:hover { border-color: #9ca3af; background: #f9fafb; }
    .danger { border: 1px solid #e7a48c; color: #9a3412; }
    .danger:hover { border-color: #c65d37; background: #fff7f3; }
    .secondary:focus-visible, .danger:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
    @media (max-width: 640px) {
      .replacement-summary { grid-template-columns: 1fr; }
      .replacement-summary div { padding: 10px 0; }
      .replacement-summary div + div { padding-left: 0; border-top: 1px solid var(--line); border-left: 0; }
      .installation-option { grid-template-columns: 1fr; }
      .installation-option button { width: 100%; }
    }
    @media (prefers-reduced-motion: reduce) {
      .secondary, .danger { transition: none; }
    }
  </style>`

var enrollmentReplacementTemplate = template.Must(template.New("enrollment-replacement").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Make room for this scimtest installation</title>
` + enrollmentPageStyles + enrollmentReplacementStyles + `
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
    <span class="topbar-context">installation limit</span>
  </header>
  <div class="shell">
    <main class="card replacement-card">
      <div class="card-body">
        <div class="heading">
          <span class="page-icon" aria-hidden="true">
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
              <path d="M10 2.5l6 2.4v4.4c0 3.8-2.4 6.6-6 8.2-3.6-1.6-6-4.4-6-8.2V4.9z"/><path d="M6.8 10h6.4M10 6.8v6.4"/>
            </svg>
          </span>
          <div>
            <div class="eyebrow">Installation limit reached</div>
            <h1>Make room for this installation</h1>
          </div>
        </div>
        <p class="lede">@{{.GitHubLogin}} already has {{.Limit}} authorized installations for this application. Choose one to deactivate, then scimtest will finish authorizing this computer.</p>

        <dl class="replacement-summary">
          <div><dt>Application</dt><dd>{{.ApplicationName}}</dd></div>
          <div><dt>GitHub account</dt><dd>@{{.GitHubLogin}}</dd></div>
          <div><dt>New fingerprint</dt><dd><code>{{.InstanceFingerprint}}</code></dd></div>
        </dl>

        {{if .Notice}}<p class="notice" role="status">{{.Notice}}</p>{{end}}

        <section aria-labelledby="installation-list-heading">
          <h2 id="installation-list-heading">Choose an installation to deactivate</h2>
          <div class="installation-list">
            {{range .Options}}
            <article class="installation-option{{if .Recommended}} recommended{{end}}">
              <div>
                <div class="installation-title">
                  <code>{{.DisplayName}}</code>
                  {{if .Recommended}}<span class="badge">Recommended</span>{{end}}
                  {{if .Connected}}<span class="badge connected">Connected now</span>{{end}}
                  {{if .Pending}}<span class="badge">Setup pending</span>{{end}}
                </div>
                <div class="installation-meta">
                  <span>{{.Activity}}</span>
                  <span>Created {{.Created}}</span>
                </div>
                {{if .Connected}}<p class="installation-note">Continuing will disconnect this installation immediately.</p>{{end}}
              </div>
              <form method="post" action="/enroll/replace">
                <input type="hidden" name="csrf_token" value="{{$.CSRFToken}}">
                <input type="hidden" name="instance_id" value="{{.InstanceID}}">
                <button class="{{if .Connected}}danger{{else if .Recommended}}primary{{else}}secondary{{end}}" type="submit">
                  {{if .Connected}}Disconnect and continue{{else}}Deactivate and continue{{end}}
                </button>
              </form>
            </article>
            {{end}}
          </div>
        </section>
      </div>
      <div class="card-footer">Nothing changes until you choose an installation. Close this tab to cancel.</div>
    </main>
  </div>
</body>
</html>`))

func (s *Server) renderEnrollmentReplacement(w http.ResponseWriter, deviceHash [32]byte, user auth.GitHubUser, notice string) error {
	s.enrollMu.Lock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(time.Now().UTC())
	pending, exists := s.pendingEnrollments[deviceHash]
	approvedPending := make([]pendingEnrollment, 0)
	if exists {
		for hash, other := range s.pendingEnrollments {
			if hash != deviceHash && other.profileID == pending.profileID && other.actor.GitHubUserID == user.ID && !other.approvedAt.IsZero() {
				approvedPending = append(approvedPending, other)
			}
		}
	}
	s.enrollMu.Unlock()
	if !exists || !pending.approvedAt.IsZero() {
		return errEnrollmentReplacementExpired
	}
	profile, exists := s.store.ApplicationProfile(pending.profileID)
	if !exists {
		return errors.New("application profile not found")
	}
	active := s.activeApplicationInstanceIDs(pending.profileID)
	options := make([]enrollmentReplacementOption, 0)
	for instanceID, instance := range profile.Instances {
		if !instance.Enrolled() || instance.Revoked || instance.GitHubUserID != user.ID {
			continue
		}
		displayName := instance.TunnelID
		if displayName == "" {
			displayName = instanceID
		}
		options = append(options, enrollmentReplacementOption{
			InstanceID:  instanceID,
			DisplayName: displayName,
			Activity:    "Last used " + formatEnrollmentReplacementTime(instance.LastUsedAt),
			Created:     formatEnrollmentReplacementTime(instance.CreatedAt),
			Connected:   active[instanceID],
			lastUsedAt:  instance.LastUsedAt,
		})
	}
	for _, other := range approvedPending {
		options = append(options, enrollmentReplacementOption{
			InstanceID:  other.instanceID,
			DisplayName: other.instanceID,
			Activity:    "Authorization approved; never connected",
			Created:     formatEnrollmentReplacementTime(other.createdAt),
			Pending:     true,
			lastUsedAt:  time.Time{},
		})
	}
	if len(options) == 0 {
		return errors.New("no existing installation is available to replace")
	}
	sort.Slice(options, func(i, j int) bool {
		if options[i].Connected != options[j].Connected {
			return !options[i].Connected
		}
		if !options[i].lastUsedAt.Equal(options[j].lastUsedAt) {
			return options[i].lastUsedAt.Before(options[j].lastUsedAt)
		}
		return options[i].InstanceID < options[j].InstanceID
	})
	for i := range options {
		if !options[i].Connected {
			options[i].Recommended = true
			break
		}
	}
	token, csrfToken, maxAge, err := s.createEnrollmentReplacementIntent(deviceHash, user)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(enrollmentReplacementCookieName),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cookieSecure(),
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
	return enrollmentReplacementTemplate.Execute(w, enrollmentReplacementPageData{
		ApplicationName:     profile.Name,
		GitHubLogin:         strings.TrimSpace(user.Login),
		InstanceFingerprint: pending.instanceID,
		Limit:               s.installationLimit(),
		CSRFToken:           csrfToken,
		Notice:              notice,
		Options:             options,
	})
}

func (s *Server) createEnrollmentReplacementIntent(deviceHash [32]byte, user auth.GitHubUser) (string, string, int, error) {
	token, err := randomHex(32)
	if err != nil {
		return "", "", 0, errors.New("could not create installation replacement")
	}
	tokenHash := sha256.Sum256([]byte(token))
	csrfToken, err := randomHex(24)
	if err != nil {
		return "", "", 0, errors.New("could not create installation replacement")
	}
	now := time.Now().UTC()
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(now)
	pending, exists := s.pendingEnrollments[deviceHash]
	if !exists || !pending.approvedAt.IsZero() {
		return "", "", 0, errEnrollmentReplacementExpired
	}
	for attempts := 0; ; attempts++ {
		if _, exists := s.replacementIntents[tokenHash]; !exists {
			break
		}
		if attempts == maxRandomIDAttempts-1 {
			return "", "", 0, errors.New("could not create installation replacement")
		}
		token, err = randomHex(32)
		if err != nil {
			return "", "", 0, errors.New("could not create installation replacement")
		}
		tokenHash = sha256.Sum256([]byte(token))
	}
	s.deleteReplacementIntentsForEnrollmentLocked(deviceHash)
	expiresAt := now.Add(enrollmentReplacementLifetime)
	if pending.expiresAt.Before(expiresAt) {
		expiresAt = pending.expiresAt
	}
	s.replacementIntents[tokenHash] = enrollmentReplacementIntent{
		enrollmentHash: deviceHash,
		githubUserID:   user.ID,
		githubLogin:    strings.TrimSpace(user.Login),
		csrfToken:      csrfToken,
		expiresAt:      expiresAt,
	}
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		delete(s.replacementIntents, tokenHash)
		return "", "", 0, errEnrollmentReplacementExpired
	}
	return token, csrfToken, maxAge, nil
}

func (s *Server) handleEnrollmentReplacement(w http.ResponseWriter, r *http.Request) {
	if !s.allowedDashboardMutation(r) {
		http.Error(w, "invalid replacement origin", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid installation replacement", http.StatusBadRequest)
		return
	}
	instanceID := r.PostForm.Get("instance_id")
	if !instanceIDRE.MatchString(instanceID) {
		http.Error(w, "invalid installation replacement", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie(s.cookieName(enrollmentReplacementCookieName))
	if err != nil || !validHexToken(cookie.Value, 64) {
		http.Error(w, errEnrollmentReplacementExpired.Error(), http.StatusGone)
		return
	}
	tokenHash := sha256.Sum256([]byte(cookie.Value))
	s.enrollMu.Lock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(time.Now().UTC())
	intent, exists := s.replacementIntents[tokenHash]
	if !exists {
		s.enrollMu.Unlock()
		http.Error(w, errEnrollmentReplacementExpired.Error(), http.StatusGone)
		return
	}
	if subtle.ConstantTimeCompare([]byte(intent.csrfToken), []byte(r.PostForm.Get("csrf_token"))) != 1 {
		s.enrollMu.Unlock()
		http.Error(w, "invalid installation replacement", http.StatusBadRequest)
		return
	}
	delete(s.replacementIntents, tokenHash)
	s.enrollMu.Unlock()
	clearCookie(w, s.cookieName(enrollmentReplacementCookieName), s.cookieSecure())

	profileID, disconnect, replaceErr := s.replaceEnrollment(intent, instanceID)
	if replaceErr != nil {
		if errors.Is(replaceErr, errEnrollmentReplacementForbidden) {
			user := auth.GitHubUser{ID: intent.githubUserID, Login: intent.githubLogin}
			if renderErr := s.renderEnrollmentReplacement(w, intent.enrollmentHash, user, "That installation is no longer available. Choose another."); renderErr == nil {
				return
			}
		}
		status := http.StatusInternalServerError
		if errors.Is(replaceErr, errEnrollmentReplacementExpired) {
			status = http.StatusGone
		}
		http.Error(w, replaceErr.Error(), status)
		return
	}
	if disconnect {
		s.disconnectApplicationInstance(profileID, instanceID)
	}
	s.renderEnrollmentComplete(w)
}

func (s *Server) replaceEnrollment(intent enrollmentReplacementIntent, instanceID string) (string, bool, error) {
	now := time.Now().UTC()
	s.enrollMu.Lock()
	defer s.enrollMu.Unlock()
	s.initializeEnrollmentStateLocked()
	s.pruneEnrollmentStateLocked(now)
	pending, exists := s.pendingEnrollments[intent.enrollmentHash]
	if !exists || !pending.approvedAt.IsZero() {
		return "", false, errEnrollmentReplacementExpired
	}
	if err := s.pruneIdleApplicationInstances(pending.profileID, now); err != nil {
		return "", false, err
	}
	user := auth.GitHubUser{ID: intent.githubUserID, Login: intent.githubLogin}
	disconnect := false
	replaced := false
	if s.enrollmentCountLocked(intent.enrollmentHash, pending.profileID, intent.githubUserID) >= s.installationLimit() {
		changed, err := s.store.RevokeApplicationInstanceForGitHubUser(pending.profileID, instanceID, intent.githubUserID)
		if err != nil {
			return "", false, err
		}
		if changed {
			disconnect = true
		} else if !s.deleteApprovedPendingEnrollmentForUserLocked(intent.enrollmentHash, pending.profileID, instanceID, intent.githubUserID) {
			return "", false, errEnrollmentReplacementForbidden
		}
		replaced = true
	}
	s.approvePendingEnrollmentLocked(intent.enrollmentHash, pending, user, now)
	s.logger().Info("installation replacement approved",
		"profile_id", pending.profileID,
		"replacement_instance_id", instanceID,
		"new_instance_id", pending.instanceID,
		"github_user_id", intent.githubUserID,
		"github_login", intent.githubLogin,
		"replaced", replaced,
	)
	return pending.profileID, disconnect, nil
}

func (s *Server) deleteApprovedPendingEnrollmentForUserLocked(currentHash [32]byte, profileID, instanceID string, userID int64) bool {
	for hash, pending := range s.pendingEnrollments {
		if hash == currentHash || pending.profileID != profileID || pending.instanceID != instanceID || pending.actor.GitHubUserID != userID || pending.approvedAt.IsZero() {
			continue
		}
		s.deletePendingEnrollmentLocked(hash, pending)
		return true
	}
	return false
}

func (s *Server) installationLimit() int {
	if s.cfg.MaxInstallationsPerUser > 0 {
		return s.cfg.MaxInstallationsPerUser
	}
	return 5
}

func (s *Server) pruneIdleApplicationInstances(profileID string, now time.Time) error {
	active := s.activeApplicationInstanceIDs(profileID)
	pruned, err := s.store.PruneIdleApplicationInstances(profileID, now.Add(-applicationInstanceMaxIdle), active)
	if err != nil {
		return err
	}
	if pruned > 0 {
		s.logger().Info("idle application installations pruned", "profile_id", profileID, "count", pruned)
	}
	return nil
}

func (s *Server) activeApplicationInstanceIDs(profileID string) map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	active := make(map[string]bool)
	for _, tunnel := range s.tunnels {
		if tunnel.applicationProfileID == profileID {
			active[tunnel.instanceID] = true
		}
	}
	return active
}

func (s *Server) deleteReplacementIntentsForEnrollmentLocked(deviceHash [32]byte) {
	for tokenHash, intent := range s.replacementIntents {
		if intent.enrollmentHash == deviceHash {
			delete(s.replacementIntents, tokenHash)
		}
	}
}

func (s *Server) renderEnrollmentComplete(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	if err := enrollmentCompleteTemplate.Execute(w, nil); err != nil {
		s.logger().Error("enrollment completion page render failed", "err", err)
	}
}

func formatEnrollmentReplacementTime(value time.Time) string {
	if value.IsZero() {
		return "never"
	}
	return value.UTC().Format("Jan 2, 2006 at 15:04 UTC")
}
