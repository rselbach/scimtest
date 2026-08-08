package web

import (
	"net/http"
	"time"
)

type samlInspection struct {
	User            string
	ACSURL          string
	InResponseTo    string
	ResponseXML     string
	EncodedResponse string
	UpdatedAt       string
}

func (a *webApp) rememberSAMLInspection(app app, user user, context samlResponseContext, response string, encoded string, now time.Time) {
	inspection := samlInspection{
		User:            userLabel(user),
		ACSURL:          context.ACSURL,
		InResponseTo:    context.InResponseTo,
		ResponseXML:     response,
		EncodedResponse: encoded,
		UpdatedAt:       now.Format(time.RFC3339),
	}

	a.samlInspectorMu.Lock()
	defer a.samlInspectorMu.Unlock()
	if a.samlInspections == nil {
		a.samlInspections = make(map[string][]samlInspection)
	}
	entries := append([]samlInspection{inspection}, a.samlInspections[app.Slug]...)
	if len(entries) > maxInspections {
		entries = entries[:maxInspections]
	}
	a.samlInspections[app.Slug] = entries
}

func (a *webApp) handleSAMLInspector(w http.ResponseWriter, r *http.Request) {
	_, foundApp, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}

	a.samlInspectorMu.Lock()
	entries := append([]samlInspection(nil), a.samlInspections[foundApp.Slug]...)
	a.samlInspectorMu.Unlock()
	data := struct {
		App        app
		Inspection samlInspection
		Found      bool
		History    []samlInspection
		Events     []flowEvent
	}{App: foundApp, Events: a.flowEvents(foundApp.Slug)}
	if len(entries) > 0 {
		data.Inspection = entries[0]
		data.Found = true
		data.History = entries[1:]
	}
	if err := pageTemplate.ExecuteTemplate(w, "saml-inspector.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
