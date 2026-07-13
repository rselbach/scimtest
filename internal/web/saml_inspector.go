package web

import (
	"net/http"
	"time"
)

type samlInspection struct {
	User         string
	ACSURL       string
	InResponseTo string
	ResponseXML  string
	UpdatedAt    string
}

func (a *webApp) rememberSAMLInspection(app app, user user, context samlResponseContext, response string, now time.Time) {
	inspection := samlInspection{
		User:         userLabel(user),
		ACSURL:       context.ACSURL,
		InResponseTo: context.InResponseTo,
		ResponseXML:  response,
		UpdatedAt:    now.Format(time.RFC3339),
	}

	a.samlInspectorMu.Lock()
	defer a.samlInspectorMu.Unlock()
	if a.samlInspections == nil {
		a.samlInspections = make(map[string]samlInspection)
	}
	a.samlInspections[app.Slug] = inspection
}

func (a *webApp) handleSAMLInspector(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}

	a.samlInspectorMu.Lock()
	inspection, found := a.samlInspections[foundApp.Slug]
	a.samlInspectorMu.Unlock()
	data := struct {
		App        app
		Inspection samlInspection
		Found      bool
	}{App: foundApp, Inspection: inspection, Found: found}
	if err := pageTemplate.ExecuteTemplate(w, "saml-inspector.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
