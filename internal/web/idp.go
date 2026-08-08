package web

import (
	"errors"
	"net/http"
	"strings"
)

func appForProtocol(w http.ResponseWriter, r *http.Request, supports func(app) bool) (appState, app, bool) {
	state, err := loadStateForAppSlug(r.PathValue("slug"))
	if err != nil {
		if errors.Is(err, errAppNotFound) {
			http.NotFound(w, r)
			return appState{}, app{}, false
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return appState{}, app{}, false
	}
	found, ok := appBySlug(state.Apps, r.PathValue("slug"))
	if !ok || !supports(found) {
		http.NotFound(w, r)
		return appState{}, app{}, false
	}
	return state, found, true
}

func effectiveIDPBaseURL(r *http.Request, state appState) string {
	configured := strings.TrimRight(strings.TrimSpace(state.Config.IDPBaseURL), "/")
	if configured != "" {
		return configured
	}
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	if state.Config.TrustForwardedHeaders {
		if forwardedProto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); forwardedProto == "http" || forwardedProto == "https" {
			proto = forwardedProto
		}
	}
	host := r.Host
	if host == "" {
		return "http://localhost:8080"
	}
	return proto + "://" + host
}

func oidcIssuer(baseURL string, app app) string {
	return baseURL + "/oidc/" + app.Slug
}
