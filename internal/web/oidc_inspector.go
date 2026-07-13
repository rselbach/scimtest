package web

import (
	"encoding/json"
	"net/http"
	"time"
)

type oidcInspection struct {
	Stage       string
	ClientID    string
	User        string
	RedirectURI string
	Scope       string
	PKCE        bool
	Claims      string
	UpdatedAt   string
}

func (a *webApp) rememberOIDCInspection(app app, user user, code authCode, stage string, claims map[string]any, now time.Time) error {
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
		UpdatedAt:   now.Format(time.RFC3339),
	}

	a.oidcInspectorMu.Lock()
	defer a.oidcInspectorMu.Unlock()
	if a.oidcInspections == nil {
		a.oidcInspections = make(map[string]oidcInspection)
	}
	a.oidcInspections[app.Slug] = inspection
	return nil
}

func (a *webApp) handleOIDCInspector(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsOIDC)
	if !ok {
		return
	}

	a.oidcInspectorMu.Lock()
	inspection, found := a.oidcInspections[foundApp.Slug]
	a.oidcInspectorMu.Unlock()
	data := struct {
		App        app
		Inspection oidcInspection
		Found      bool
	}{App: foundApp, Inspection: inspection, Found: found}
	if err := pageTemplate.ExecuteTemplate(w, "oidc-inspector.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
