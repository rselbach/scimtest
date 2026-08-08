package web

import (
	"encoding/json"
	"net/http"
	"time"
)

// maxInspections bounds the per-slug flow history kept for the inspectors,
// enough to compare a few runs before and after a configuration tweak.
const maxInspections = 10

type oidcInspection struct {
	Stage       string
	ClientID    string
	User        string
	RedirectURI string
	Scope       string
	PKCE        bool
	Claims      string
	IDToken     string
	UpdatedAt   string
}

func (a *webApp) rememberOIDCInspection(app app, user user, code authCode, stage string, claims map[string]any, idToken string, now time.Time) error {
	claimsJSON := ""
	if claims != nil {
		encoded, err := json.MarshalIndent(claims, "", "  ")
		if err != nil {
			return err
		}
		claimsJSON = string(encoded)
	}
	inspection := oidcInspection{
		Stage:       stage,
		ClientID:    code.ClientID,
		User:        userLabel(user),
		RedirectURI: code.RedirectURI,
		Scope:       code.Scope,
		PKCE:        code.CodeChallenge != "",
		Claims:      claimsJSON,
		IDToken:     idToken,
		UpdatedAt:   now.Format(time.RFC3339),
	}

	a.oidcInspectorMu.Lock()
	defer a.oidcInspectorMu.Unlock()
	if a.oidcInspections == nil {
		a.oidcInspections = make(map[string][]oidcInspection)
	}
	entries := a.oidcInspections[app.Slug]
	// The token stage completes the flow the authorize stage started, so it
	// replaces that entry instead of appearing as a second flow.
	if claimsJSON != "" && len(entries) > 0 && entries[0].Claims == "" && entries[0].ClientID == inspection.ClientID && entries[0].User == inspection.User {
		entries[0] = inspection
	} else {
		entries = append([]oidcInspection{inspection}, entries...)
		if len(entries) > maxInspections {
			entries = entries[:maxInspections]
		}
	}
	a.oidcInspections[app.Slug] = entries
	return nil
}

func (a *webApp) handleOIDCInspector(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}

	a.oidcInspectorMu.Lock()
	entries := append([]oidcInspection(nil), a.oidcInspections[foundApp.Slug]...)
	a.oidcInspectorMu.Unlock()
	data := struct {
		App        app
		Inspection oidcInspection
		Found      bool
		History    []oidcInspection
		Events     []flowEvent
	}{App: foundApp, Events: a.flowEvents(foundApp.Slug)}
	if len(entries) > 0 {
		data.Inspection = entries[0]
		data.Found = true
		data.History = entries[1:]
	}
	if err := pageTemplate.ExecuteTemplate(w, "oidc-inspector.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
