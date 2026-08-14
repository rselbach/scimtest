package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFailedTokenExchangeAppearsInInspector(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{
		Users: []user{{ID: "usr-1", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy", Active: true}},
		Apps: []app{{
			ID:               "app-1",
			Name:             "Example",
			Slug:             "example",
			Protocol:         "oidc",
			OIDCClientID:     "example-client",
			OIDCClientSecret: "secret",
			OIDCRedirectURIs: []string{"http://client.test/callback"},
		}},
	}))

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"no-such-code"},
		"redirect_uri": {"http://client.test/callback"},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oidc/example/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth("example-client", "secret")
	tokenRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(tokenRec, tokenReq)
	r.Equal(http.StatusBadRequest, tokenRec.Code)

	inspectorRec := httptest.NewRecorder()
	svc.routes().ServeHTTP(inspectorRec, httptest.NewRequest(http.MethodGet, "/inspect/oidc/example", nil))
	r.Equal(http.StatusOK, inspectorRec.Code)
	r.Contains(inspectorRec.Body.String(), "invalid_grant: authorization code is invalid or expired")
	r.Contains(inspectorRec.Body.String(), "Recent activity")
	r.Contains(inspectorRec.Body.String(), `id="app-shell"`)
	r.Contains(inspectorRec.Body.String(), `<h1>OIDC Inspector</h1>`)
	r.Contains(inspectorRec.Body.String(), `class="side-item active" href="/?environment=app-1&amp;tab=oidc-inspector"`)
	r.Contains(inspectorRec.Body.String(), `<input type="hidden" name="tab" value="oidc-inspector">`)
	r.Contains(inspectorRec.Body.String(), `name="return_tab" value="oidc-inspector"`)
	r.NotContains(inspectorRec.Body.String(), `name="fault_saml_status"`)
	r.Contains(inspectorRec.Body.String(), `class="flow-activity-wrap"`)
	r.Contains(inspectorRec.Body.String(), "data-flow-activity-row")
	r.Contains(inspectorRec.Body.String(), `aria-controls="flow-activity-detail-0"`)
	r.Contains(inspectorRec.Body.String(), `id="flow-activity-detail-0" aria-hidden="true"`)
	r.Contains(inspectorRec.Body.String(), `/assets/flow_activity.js?v=1`)
}

func TestFlowEventRingIsBoundedAndNewestFirst(t *testing.T) {
	r := require.New(t)
	svc := &webApp{}
	for i := 0; i < maxFlowEvents+5; i++ {
		svc.recordFlowEvent("example", "oidc", "token", "failed", "", strings.Repeat("x", i+1))
	}
	events := svc.flowEvents("example")
	r.Len(events, maxFlowEvents)
	r.Equal(strings.Repeat("x", maxFlowEvents+5), events[0].Detail, "newest event must come first")
}

func TestInspectorHidesActionsWhenEnvironmentDoesNotSupportProtocol(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	r.NoError(saveState(appState{Apps: []app{{
		ID:         "app-1",
		Name:       "Greendale SAML",
		Slug:       "greendale-saml",
		Protocol:   "saml",
		SAMLACSURL: "https://greendale.test/saml/acs",
	}}}))

	response := httptest.NewRecorder()
	svc.routes().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/?tab=oidc-inspector&environment=app-1", nil))

	r.Equal(http.StatusOK, response.Code)
	r.Contains(response.Body.String(), "OIDC is not set up for Greendale SAML")
	r.NotContains(response.Body.String(), "Test with built-in RP")
}
