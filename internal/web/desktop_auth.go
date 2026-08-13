package web

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
)

type desktopAuthView struct {
	State string
	Error string
}

func (a *webApp) githubAccountGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.githubAccountConnected() {
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			a.renderDesktopAuth(w)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/assets/"):
			next.ServeHTTP(w, r)
		case r.Method == http.MethodGet && r.URL.Path == instanceReadyPath:
			next.ServeHTTP(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/desktop/auth/start":
			next.ServeHTTP(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/desktop/auth/retry":
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "GitHub account sign-in is required", http.StatusUnauthorized)
		}
	})
}

func (a *webApp) githubAccountConnected() bool {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	// Desktop uses the per-installation key flow. A registered tunnel means
	// the server found the GitHub-enrolled key and accepted its challenge.
	return a.tunnel != nil
}

func (a *webApp) githubAccountView() githubAccountView {
	if !a.requireGitHubAccount {
		return githubAccountView{}
	}
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	if a.tunnel == nil {
		return githubAccountView{}
	}
	view := githubAccountView{Linked: true}
	if a.tunnel.GitHubUserID > 0 {
		view.Login = strings.TrimSpace(a.tunnel.GitHubLogin)
	}
	return view
}

func (a *webApp) desktopAuthView() desktopAuthView {
	a.tunnelMu.Lock()
	defer a.tunnelMu.Unlock()
	view := desktopAuthView{}
	switch {
	case a.tunnel != nil:
		view.State = "connected"
	case a.tunnelEnrollmentURL != "":
		view.State = "authorizing"
	case a.tunnelLastError != "":
		view.State = "failed"
		view.Error = strings.ReplaceAll(
			humanTunnelError(a.tunnelLastError),
			"; scimtest keeps working locally",
			"; sign-in is required before the desktop app can unlock",
		)
	case a.tunnelSupported:
		view.State = "connecting"
	default:
		view.State = "unavailable"
		view.Error = "This build has no application profile for GitHub sign-in."
	}
	return view
}

func desktopEnrollmentURL(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	enrollmentURL, err := url.Parse(value)
	if err != nil {
		return value
	}
	query := enrollmentURL.Query()
	query.Set("presentation", "desktop")
	enrollmentURL.RawQuery = query.Encode()
	return enrollmentURL.String()
}

func (a *webApp) renderDesktopAuth(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := pageTemplate.ExecuteTemplate(w, "desktop_auth.html", a.desktopAuthView()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *webApp) handleDesktopAuthStart(w http.ResponseWriter, r *http.Request) {
	if !a.requireGitHubAccount {
		http.NotFound(w, r)
		return
	}
	a.tunnelMu.Lock()
	enrollmentURL := strings.TrimSpace(a.tunnelEnrollmentURL)
	a.tunnelMu.Unlock()
	if enrollmentURL == "" {
		http.Error(w, "GitHub authorization is not ready; try again", http.StatusConflict)
		return
	}
	opener := a.browserOpen
	if opener == nil {
		opener = OpenBrowser
	}
	if err := opener(enrollmentURL); err != nil {
		http.Error(w, fmt.Sprintf("open GitHub authorization: %v", err), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *webApp) handleDesktopAuthRetry(w http.ResponseWriter, r *http.Request) {
	a.retryAutomaticTunnel()
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *webApp) handleDesktopAuthLogout(w http.ResponseWriter, r *http.Request) {
	if !a.requireGitHubAccount {
		http.NotFound(w, r)
		return
	}
	identity, err := loadTunnelApplicationIdentity()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if identity == nil {
		http.Error(w, "GitHub account sign-in is unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := a.logoutGitHubAccount(*identity); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *webApp) logoutGitHubAccount(identity tunnelApplicationIdentity) error {
	a.tunnelMu.Lock()
	if a.tunnelClosing {
		a.tunnelMu.Unlock()
		return errors.New("scimtest is shutting down")
	}
	if a.tunnelResetting {
		a.tunnelMu.Unlock()
		return errors.New("GitHub account sign-out is already in progress")
	}
	a.tunnelResetting = true
	attempt := a.tunnelStarting
	a.tunnelMu.Unlock()

	if attempt != nil {
		attempt.cancel()
		<-attempt.done
	}

	a.mu.Lock()
	if _, _, err := rotateTunnelInstanceIdentity(); err != nil {
		a.mu.Unlock()
		a.tunnelMu.Lock()
		a.tunnelResetting = false
		a.tunnelMu.Unlock()
		return fmt.Errorf("sign out of GitHub: %w", err)
	}
	a.mu.Unlock()

	a.tunnelMu.Lock()
	tunnel := a.tunnel
	a.tunnel = nil
	a.tunnelLastError = ""
	a.tunnelEnrollmentURL = ""
	a.tunnelEnrollmentCode = ""
	a.tunnelResetting = false
	closing := a.tunnelClosing
	a.tunnelMu.Unlock()

	if tunnel != nil && tunnel.Tunnel != nil {
		if err := tunnel.Tunnel.Close(); err != nil {
			log.Printf("close signed-out tunnel: %v", err)
		}
	}
	if !closing {
		go a.startAutomaticTunnel(identity)
	}
	return nil
}
