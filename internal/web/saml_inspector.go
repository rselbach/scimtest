package web

import (
	"net/http"
	"net/url"
	"time"
)

type samlInspection struct {
	User                  string
	ACSURL                string
	InResponseTo          string
	AssertionID           string
	ResponseXML           string
	PlaintextAssertionXML string
	EncodedResponse       string
	Faults                string
	UpdatedAt             string
}

type samlInspectorPageData struct {
	App         app
	Inspection  samlInspection
	Found       bool
	History     []samlInspection
	Events      []flowEvent
	SigningKeys []signingKeyView
	ArmedFaults string
	ReturnTab   string
	Sessions    []idpSessionView // live sessions with a SAML sign-in
	Logouts     []samlLogout     // IdP-initiated LogoutRequests, newest first
}

func (a *webApp) rememberSAMLInspection(app app, user user, context samlResponseContext, posted samlPostedResponse, encoded string, faults faultOptions, now time.Time) {
	inspection := samlInspection{
		User:                  userLabel(user),
		ACSURL:                context.ACSURL,
		InResponseTo:          context.InResponseTo,
		AssertionID:           context.AssertionID,
		ResponseXML:           posted.XML,
		PlaintextAssertionXML: posted.PlaintextAssertion,
		EncodedResponse:       encoded,
		Faults:                faults.describe(),
		UpdatedAt:             now.Format(time.RFC3339),
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
	request := r.Clone(r.Context())
	request.URL = &url.URL{Path: "/", RawQuery: url.Values{
		"environment": {foundApp.ID},
		"tab":         {"saml-inspector"},
	}.Encode()}
	a.handleIndex(w, request)
}

func (a *webApp) buildSAMLInspectorPageData(foundApp app) *samlInspectorPageData {
	a.samlInspectorMu.Lock()
	entries := append([]samlInspection(nil), a.samlInspections[foundApp.Slug]...)
	a.samlInspectorMu.Unlock()
	data := &samlInspectorPageData{
		App:         foundApp,
		Events:      a.flowEvents(foundApp.Slug),
		ArmedFaults: a.peekArmedFaults(foundApp.Slug).describe(),
		ReturnTab:   "saml-inspector",
		Logouts:     a.recentSAMLLogouts(foundApp.Slug),
	}
	for _, session := range a.liveIdPSessions(foundApp.Slug) {
		if session.SAMLSessionIndex != "" {
			data.Sessions = append(data.Sessions, session)
		}
	}
	if len(entries) > 0 {
		data.Inspection = entries[0]
		data.Found = true
		data.History = entries[1:]
	}
	return data
}
