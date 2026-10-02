package web

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
)

const (
	testSPSLOURL     = "https://sp.greendale.test/slo"
	testIDPSLOURL    = "http://idp.test/saml/greendale/slo"
	testIDPEntityID  = "http://idp.test/saml/greendale/metadata"
	testEmailNameIDs = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
)

func TestSAMLMetadataAdvertisesSingleLogout(t *testing.T) {
	r := require.New(t)
	svc := sloTestApp(t, nil)
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/saml/greendale/metadata", nil))
	r.Equal(http.StatusOK, rec.Code, rec.Body.String())

	descriptor := findElementByLocalName(mustParseXML(t, rec.Body.String()).Root(), "IDPSSODescriptor")
	r.NotNil(descriptor)
	var order []string
	locations := map[string]string{}
	for _, child := range descriptor.ChildElements() {
		order = append(order, elementLocalName(child))
		if elementLocalName(child) == "SingleLogoutService" {
			locations[child.SelectAttrValue("Binding", "")] = child.SelectAttrValue("Location", "")
		}
	}
	r.Equal(map[string]string{samlHTTPRedirectBinding: testIDPSLOURL, samlHTTPPostBinding: testIDPSLOURL}, locations)
	r.Equal([]string{"KeyDescriptor", "SingleLogoutService", "SingleLogoutService", "NameIDFormat", "SingleSignOnService", "SingleSignOnService"}, order)
}

func TestSAMLAssertionCarriesSessionIndex(t *testing.T) {
	r := require.New(t)
	svc := sloTestApp(t, nil)
	cookie, index := samlLogoutSignIn(t, svc, "usr-troy")
	r.NotEmpty(index)
	sessions := svc.liveIdPSessions("greendale")
	r.Len(sessions, 1)
	r.Equal(index, sessions[0].SAMLSessionIndex)
	r.Equal("troy@greendale.edu", sessions[0].SAMLNameID)

	_, again := samlLogoutSignIn(t, svc, "usr-troy", cookie)
	r.Equal(index, again, "a sign-in in the same session keeps its SessionIndex")

	_, replaced := samlLogoutSignIn(t, svc, "usr-abed", cookie)
	r.NotEqual(index, replaced, "another user's sign-in starts a new session")
}

func TestSPInitiatedSAMLLogout(t *testing.T) {
	tests := map[string]struct {
		binding string
		signed  bool
	}{
		"redirect":        {binding: samlHTTPRedirectBinding},
		"post":            {binding: samlHTTPPostBinding},
		"signed redirect": {binding: samlHTTPRedirectBinding, signed: true},
		"signed post":     {binding: samlHTTPPostBinding, signed: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			var signer *testSPSigner
			if tc.signed {
				signer = newTestSPSigner(t)
			}
			svc := sloTestApp(t, signer)
			svc.trafficRecord.Store(true)
			cookie, index := samlLogoutSignIn(t, svc, "usr-troy")

			rec := sendSAMLLogoutMessage(t, svc, "greendale", tc.binding, "SAMLRequest", newTestLogoutRequest(index).xml(), "study-room", signer, cookie)

			response, relayState := receivedSAMLLogoutMessage(t, svc, rec, tc.binding, "SAMLResponse")
			r.Equal("LogoutResponse", elementLocalName(response))
			r.Equal("_logout-troy", response.SelectAttrValue("InResponseTo", ""))
			r.Equal(testSPSLOURL, response.SelectAttrValue("Destination", ""))
			r.Equal(testIDPEntityID, childElementTextByLocalName(response, "Issuer"))
			r.Equal(samlStatus{Code: samlStatusSuccess}, testSAMLStatus(response))
			r.Equal("study-room", relayState)
			r.Empty(svc.liveIdPSessions("greendale"))
			r.True(cookieCleared(rec, signInCookieName("greendale")), "the browser's session cookie is cleared")
			r.Contains(flowDetails(svc, "greendale"), "LogoutRequest _logout-troy from the SP ended session "+index)

			transcript := samlLogoutTranscript(t, svc)
			r.Contains(transcript, "LogoutRequest from SP")
			r.Contains(transcript, "<samlp:SessionIndex>"+index+"</samlp:SessionIndex>")
			r.Contains(transcript, "LogoutResponse to "+testSPSLOURL)
			r.Contains(transcript, `InResponseTo="_logout-troy"`)
		})
	}
}

func TestSPInitiatedSAMLLogoutScope(t *testing.T) {
	tests := map[string]struct {
		indexes   func(first, second string) []string
		wantEnded int
	}{
		"one SessionIndex ends that session":        {indexes: func(first, _ string) []string { return []string{first} }, wantEnded: 1},
		"both SessionIndex values end both":         {indexes: func(first, second string) []string { return []string{first, second} }, wantEnded: 2},
		"no SessionIndex ends every NameID session": {indexes: func(string, string) []string { return nil }, wantEnded: 2},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := sloTestApp(t, nil)
			_, first := samlLogoutSignIn(t, svc, "usr-troy")
			_, second := samlLogoutSignIn(t, svc, "usr-troy")
			samlLogoutSignIn(t, svc, "usr-abed")
			request := newTestLogoutRequest(first)
			request.SessionIndexes = tc.indexes(first, second)

			rec := sendSAMLLogoutMessage(t, svc, "greendale", samlHTTPRedirectBinding, "SAMLRequest", request.xml(), "", nil)

			response, _ := receivedSAMLLogoutMessage(t, svc, rec, samlHTTPRedirectBinding, "SAMLResponse")
			r.Equal(samlStatusSuccess, testSAMLStatus(response).Code)
			r.Len(svc.liveIdPSessions("greendale"), 3-tc.wantEnded)
		})
	}
}

func TestSPInitiatedSAMLLogoutRejectsUntrustedRequests(t *testing.T) {
	pinned := newTestSPSigner(t)
	tests := map[string]struct {
		binding  string
		pin      bool
		signWith *testSPSigner
		noSLOURL bool
		edit     func(*testLogoutRequest)
		rawXML   string
		want     string
	}{
		"wrong issuer":   {edit: func(l *testLogoutRequest) { l.Issuer = "urn:city-college:sp" }, want: `issuer "urn:city-college:sp" does not match`},
		"missing issuer": {edit: func(l *testLogoutRequest) { l.Issuer = "" }, want: "Issuer is required"},
		"missing NameID": {edit: func(l *testLogoutRequest) { l.NameID = "" }, want: "NameID is required"},
		"not a LogoutRequest": {
			rawXML: `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_request-troy"/>`,
			want:   "must contain a LogoutRequest",
		},
		"no Single Logout URL":          {noSLOURL: true, want: "Single Logout URL"},
		"unsigned redirect when pinned": {pin: true, want: "requires SigAlg"},
		"unsigned post when pinned":     {binding: samlHTTPPostBinding, pin: true, want: "LogoutRequest signature is required"},
		"signed by another key":         {pin: true, signWith: newTestSPSigner(t), want: "invalid SAML LogoutRequest signature"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			var pin *testSPSigner
			if tc.pin {
				pin = pinned
			}
			svc := sloTestApp(t, pin)
			if tc.noSLOURL {
				state, err := loadState()
				r.NoError(err)
				state.Apps[0].SAMLSLOURL = ""
				r.NoError(saveState(state))
			}
			_, index := samlLogoutSignIn(t, svc, "usr-troy")
			request := newTestLogoutRequest(index)
			if tc.edit != nil {
				tc.edit(&request)
			}
			requestXML := request.xml()
			if tc.rawXML != "" {
				requestXML = tc.rawXML
			}
			binding := tc.binding
			if binding == "" {
				binding = samlHTTPRedirectBinding
			}

			rec := sendSAMLLogoutMessage(t, svc, "greendale", binding, "SAMLRequest", requestXML, "", tc.signWith)

			r.Equal(http.StatusBadRequest, rec.Code, rec.Body.String())
			r.Contains(rec.Body.String(), tc.want)
			r.Len(svc.liveIdPSessions("greendale"), 1)
			r.Equal("failed", svc.flowEvents("greendale")[0].Outcome)
		})
	}
}

func TestSPInitiatedSAMLLogoutAnswersErrors(t *testing.T) {
	tests := map[string]struct {
		edit          func(*testLogoutRequest)
		withCookie    bool
		wantStatus    samlStatus
		wantMessage   string
		wantLiveAfter int
	}{
		"NameID of another user for the SessionIndex": {
			edit:          func(l *testLogoutRequest) { l.NameID = "abed@greendale.edu" },
			wantStatus:    samlStatus{Code: samlStatusRequester, SubCode: samlStatusUnknownPrincipal},
			wantMessage:   `NameID "abed@greendale.edu" (` + testEmailNameIDs + `) does not match the NameID "troy@greendale.edu"`,
			wantLiveAfter: 1,
		},
		"NameID format that differs": {
			edit:          func(l *testLogoutRequest) { l.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" },
			wantStatus:    samlStatus{Code: samlStatusRequester, SubCode: samlStatusUnknownPrincipal},
			wantMessage:   "does not match the NameID",
			wantLiveAfter: 1,
		},
		"unknown SessionIndex": {
			edit:          func(l *testLogoutRequest) { l.SessionIndexes = []string{"saml-session_unknown"} },
			wantStatus:    samlStatus{Code: samlStatusRequester},
			wantMessage:   `SessionIndex saml-session_unknown matches no live session for NameID "troy@greendale.edu"`,
			wantLiveAfter: 1,
		},
		"NameID that differs from the browser's session": {
			edit:          func(l *testLogoutRequest) { l.NameID, l.SessionIndexes = "abed@greendale.edu", nil },
			withCookie:    true,
			wantStatus:    samlStatus{Code: samlStatusRequester, SubCode: samlStatusUnknownPrincipal},
			wantMessage:   "does not match this browser's session",
			wantLiveAfter: 1,
		},
		"another destination": {
			edit:          func(l *testLogoutRequest) { l.Destination = "https://evil.example/slo" },
			wantStatus:    samlStatus{Code: samlStatusRequester},
			wantMessage:   `destination "https://evil.example/slo" does not match ` + testIDPSLOURL,
			wantLiveAfter: 1,
		},
		"stale IssueInstant": {
			edit:          func(l *testLogoutRequest) { l.IssueInstant = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) },
			wantStatus:    samlStatus{Code: samlStatusRequester},
			wantMessage:   "is more than 5m0s old",
			wantLiveAfter: 1,
		},
		"future IssueInstant": {
			edit:          func(l *testLogoutRequest) { l.IssueInstant = time.Now().Add(time.Hour).UTC().Format(time.RFC3339) },
			wantStatus:    samlStatus{Code: samlStatusRequester},
			wantMessage:   "is in the future",
			wantLiveAfter: 1,
		},
		"expired": {
			edit: func(l *testLogoutRequest) {
				l.NotOnOrAfter = time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
			},
			wantStatus:    samlStatus{Code: samlStatusRequester},
			wantMessage:   "expired at",
			wantLiveAfter: 1,
		},
		"NameID with no live session": {
			edit:          func(l *testLogoutRequest) { l.NameID, l.SessionIndexes = "abed@greendale.edu", nil },
			wantStatus:    samlStatus{Code: samlStatusSuccess},
			wantLiveAfter: 1,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := sloTestApp(t, nil)
			cookie, index := samlLogoutSignIn(t, svc, "usr-troy")
			request := newTestLogoutRequest(index)
			tc.edit(&request)
			var cookies []*http.Cookie
			if tc.withCookie {
				cookies = append(cookies, cookie)
			}

			rec := sendSAMLLogoutMessage(t, svc, "greendale", samlHTTPRedirectBinding, "SAMLRequest", request.xml(), "", nil, cookies...)

			response, _ := receivedSAMLLogoutMessage(t, svc, rec, samlHTTPRedirectBinding, "SAMLResponse")
			status := testSAMLStatus(response)
			r.Equal(tc.wantStatus.Code, status.Code)
			r.Equal(tc.wantStatus.SubCode, status.SubCode)
			r.Contains(status.Message, tc.wantMessage)
			r.Len(svc.liveIdPSessions("greendale"), tc.wantLiveAfter)
			wantOutcome := "failed"
			if tc.wantStatus.Code == samlStatusSuccess {
				wantOutcome = "ok"
			}
			r.Equal(wantOutcome, svc.flowEvents("greendale")[0].Outcome)
		})
	}
}

func TestSPInitiatedSAMLLogoutSendsBackchannelLogout(t *testing.T) {
	r := require.New(t)
	receiver := newLogoutReceiver(t, http.StatusOK)
	svc := backchannelTestApp(t, receiver.URL, true)
	state, err := loadState()
	r.NoError(err)
	state.Apps[0].Protocol = "both"
	state.Apps[0].SAMLEntityID = "urn:greendale:sp"
	state.Apps[0].SAMLACSURL = "https://sp.greendale.test/acs"
	state.Apps[0].SAMLSLOURL = testSPSLOURL
	r.NoError(saveState(state))
	cookie, _ := backchannelSignIn(t, svc, "usr-1")
	signedIn := postSAMLSSOTo(t, svc, "example", url.Values{"user_id": {"usr-1"}}, cookie)
	postedSAMLAssertion(t, signedIn)
	index := svc.liveIdPSessions("example")[0].SAMLSessionIndex
	request := newTestLogoutRequest(index)
	request.Destination = ""

	rec := sendSAMLLogoutMessage(t, svc, "example", samlHTTPPostBinding, "SAMLRequest", request.xml(), "", nil, cookie)
	svc.logoutDeliveries.Wait()

	response, _ := receivedSAMLLogoutMessage(t, svc, rec, samlHTTPPostBinding, "SAMLResponse")
	r.Equal(samlStatusSuccess, testSAMLStatus(response).Code)
	tokens := receiver.tokens()
	r.Len(tokens, 1)
	r.Equal(cookie.Value, logoutTokenClaims(r, tokens[0])["sid"])
	r.Contains(flowDetails(svc, "example"), "ended: SAML logout from the SP")
}

func TestIdPInitiatedSAMLLogout(t *testing.T) {
	tests := map[string]struct {
		binding     string
		formBinding string
		answer      string
		wantOutcome string
		wantPage    string
	}{
		"redirect, SP signs out": {binding: samlHTTPRedirectBinding, formBinding: "redirect", answer: samlStatusSuccess, wantOutcome: "ok", wantPage: "answered Success"},
		"post, SP signs out":     {binding: samlHTTPPostBinding, formBinding: "post", answer: samlStatusSuccess, wantOutcome: "ok", wantPage: "answered Success"},
		"SP reports a failure": {
			binding: samlHTTPRedirectBinding, formBinding: "redirect", answer: "urn:oasis:names:tc:SAML:2.0:status:Responder",
			wantOutcome: "failed", wantPage: "answered Responder",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := sloTestApp(t, nil)
			svc.trafficRecord.Store(true)
			cookie, index := samlLogoutSignIn(t, svc, "usr-troy")

			rec := sendSAMLInspectorLogout(t, svc, cookie.Value, tc.formBinding)

			request, _ := receivedSAMLLogoutMessage(t, svc, rec, tc.binding, "SAMLRequest")
			r.Equal("LogoutRequest", elementLocalName(request))
			r.Equal(testIDPEntityID, childElementTextByLocalName(request, "Issuer"))
			r.Equal(testSPSLOURL, request.SelectAttrValue("Destination", ""))
			r.Equal(samlLogoutReasonAdmin, request.SelectAttrValue("Reason", ""))
			r.NotEmpty(request.SelectAttrValue("NotOnOrAfter", ""))
			nameID := childElementByLocalName(request, "NameID")
			r.Equal("troy@greendale.edu", nameID.Text())
			r.Equal(testEmailNameIDs, nameID.SelectAttrValue("Format", ""))
			r.Equal(index, childElementTextByLocalName(request, "SessionIndex"))
			r.Empty(svc.liveIdPSessions("greendale"), "the IdP ends the session before the SP answers")
			requestID := request.SelectAttrValue("ID", "")
			logout, ok := svc.samlLogoutResult("greendale", requestID)
			r.True(ok)
			r.Equal(samlLogoutPending, logout.Outcome)
			r.Contains(samlLogoutTranscript(t, svc), "<samlp:SessionIndex>"+index+"</samlp:SessionIndex>")

			answer := sendSAMLLogoutMessage(t, svc, "greendale", tc.binding, "SAMLResponse", testSPLogoutResponse(requestID, tc.answer), "", nil)

			r.Equal(http.StatusOK, answer.Code, answer.Body.String())
			r.Contains(answer.Body.String(), "Troy Barnes is signed out of Greendale.")
			r.Contains(answer.Body.String(), tc.wantPage)
			logout, _ = svc.samlLogoutResult("greendale", requestID)
			r.Equal(tc.wantOutcome, logout.Outcome)
			r.Equal(tc.answer, logout.Status)
			r.Equal(tc.wantOutcome, svc.flowEvents("greendale")[0].Outcome)
			page := svc.buildSAMLInspectorPageData(app{Slug: "greendale"})
			r.Equal(requestID, page.Logouts[0].RequestID)

			replay := sendSAMLLogoutMessage(t, svc, "greendale", tc.binding, "SAMLResponse", testSPLogoutResponse(requestID, tc.answer), "", nil)
			r.Equal(http.StatusBadRequest, replay.Code)
			r.Contains(replay.Body.String(), "does not match a pending LogoutRequest")
		})
	}
}

func TestIdPInitiatedSAMLLogoutRejectsBadResponses(t *testing.T) {
	pinned := newTestSPSigner(t)
	tests := map[string]struct {
		pin      bool
		signWith *testSPSigner
		edit     func(responseXML string) string
		want     string
	}{
		"unsigned when pinned": {pin: true, want: "requires SigAlg"},
		"signed":               {pin: true, signWith: pinned},
		"wrong issuer": {
			edit: func(responseXML string) string {
				return strings.Replace(responseXML, "urn:greendale:sp", "urn:city-college:sp", 1)
			},
			want: `issuer "urn:city-college:sp" does not match`,
		},
		"another destination": {
			edit: func(responseXML string) string {
				return strings.Replace(responseXML, testIDPSLOURL, "https://evil.example/slo", 1)
			},
			want: "destination",
		},
		"no status": {
			edit: func(responseXML string) string {
				return strings.Replace(responseXML, `<samlp:StatusCode Value="`+samlStatusSuccess+`"/>`, "", 1)
			},
			want: "has no StatusCode",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			var pin *testSPSigner
			if tc.pin {
				pin = pinned
			}
			svc := sloTestApp(t, pin)
			cookie, _ := samlLogoutSignIn(t, svc, "usr-troy")
			request, _ := receivedSAMLLogoutMessage(t, svc, sendSAMLInspectorLogout(t, svc, cookie.Value, "redirect"), samlHTTPRedirectBinding, "SAMLRequest")
			requestID := request.SelectAttrValue("ID", "")
			responseXML := testSPLogoutResponse(requestID, samlStatusSuccess)
			if tc.edit != nil {
				responseXML = tc.edit(responseXML)
			}

			answer := sendSAMLLogoutMessage(t, svc, "greendale", samlHTTPRedirectBinding, "SAMLResponse", responseXML, "", tc.signWith)

			logout, _ := svc.samlLogoutResult("greendale", requestID)
			if tc.want == "" {
				r.Equal(http.StatusOK, answer.Code, answer.Body.String())
				r.Equal("ok", logout.Outcome)
				return
			}
			r.Equal(http.StatusBadRequest, answer.Code, answer.Body.String())
			r.Contains(answer.Body.String(), tc.want)
			r.Equal("pending", logout.Outcome)
			r.Contains(flowDetails(svc, "greendale"), "rejected: ")
		})
	}
}

func TestIdPInitiatedSAMLLogoutPreconditions(t *testing.T) {
	tests := map[string]struct {
		noSLOURL  bool
		sessionID string
		binding   string
		want      string
	}{
		"no Single Logout URL": {noSLOURL: true, want: "Single Logout URL"},
		"unknown session":      {sessionID: "not-a-session", want: `session "not-a-session" is not live`},
		"unknown binding":      {binding: "soap", want: `binding must be redirect or post, not "soap"`},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := sloTestApp(t, nil)
			if tc.noSLOURL {
				state, err := loadState()
				r.NoError(err)
				state.Apps[0].SAMLSLOURL = ""
				r.NoError(saveState(state))
			}
			cookie, _ := samlLogoutSignIn(t, svc, "usr-troy")
			sessionID := cookie.Value
			if tc.sessionID != "" {
				sessionID = tc.sessionID
			}

			rec := sendSAMLInspectorLogout(t, svc, sessionID, tc.binding)

			r.Equal(http.StatusSeeOther, rec.Code, rec.Body.String())
			event := svc.flowEvents("greendale")[0]
			r.Equal("failed", event.Outcome)
			r.Contains(event.Detail, tc.want)
			r.Len(svc.liveIdPSessions("greendale"), 1)
			r.Empty(svc.recentSAMLLogouts("greendale"))
		})
	}
}

func TestSAMLInspectorListsSAMLSessions(t *testing.T) {
	r := require.New(t)
	svc := sloTestApp(t, nil)
	_, index := samlLogoutSignIn(t, svc, "usr-troy")

	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/inspect/saml/greendale", nil))

	r.Equal(http.StatusOK, rec.Code, rec.Body.String())
	body := rec.Body.String()
	r.Contains(body, `action="/inspect/saml/greendale/sessions/logout"`)
	r.Contains(body, index)
	r.Contains(body, "Send LogoutRequest")
}

func TestAPISAMLLogout(t *testing.T) {
	r := require.New(t)
	svc, handler := newAcceptanceAPI(t)
	created := acceptanceEnvironment(t, handler, `{"name":"Greendale","saml_enabled":true,"saml_entity_id":"urn:greendale:sp","saml_acs_url":"https://sp.greendale.test/acs","saml_slo_url":"`+testSPSLOURL+`"}`)
	troy := acceptanceUser(t, handler, created.ID)
	base := "/api/v1/environments/" + created.ID
	acceptanceRequest(t, handler, http.MethodPost, base+"/saml/sign-in", `{"user_id":"`+troy.ID+`"}`, http.StatusOK)
	var listed struct {
		Sessions []idpSessionView `json:"sessions"`
	}
	r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base+"/sessions", "", http.StatusOK).Body.Bytes(), &listed))
	r.Len(listed.Sessions, 1)
	session := listed.Sessions[0]
	r.NotEmpty(session.SAMLSessionIndex)
	r.Equal("troy@greendale.edu", session.SAMLNameID)

	missing := acceptanceRequest(t, handler, http.MethodPost, base+"/saml/logout", `{"session_id":"not-a-session"}`, http.StatusNotFound)
	r.Contains(missing.Body.String(), "not found")

	var started struct {
		RequestID string            `json:"request_id"`
		Binding   string            `json:"binding"`
		URL       string            `json:"url"`
		Form      map[string]string `json:"form"`
	}
	r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodPost, base+"/saml/logout", `{"session_id":"`+session.SessionID+`","binding":"post"}`, http.StatusOK).Body.Bytes(), &started))
	r.Equal("HTTP-POST", started.Binding)
	r.Equal(testSPSLOURL, started.URL)
	requestXML, err := base64.StdEncoding.DecodeString(started.Form["SAMLRequest"])
	r.NoError(err)
	r.Contains(string(requestXML), `ID="`+started.RequestID+`"`)
	r.Contains(string(requestXML), "<samlp:SessionIndex>"+session.SAMLSessionIndex+"</samlp:SessionIndex>")

	var logouts struct {
		Logouts []samlLogout `json:"logouts"`
	}
	r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base+"/saml/logouts", "", http.StatusOK).Body.Bytes(), &logouts))
	r.Len(logouts.Logouts, 1)
	r.Equal(started.RequestID, logouts.Logouts[0].RequestID)
	r.Equal(samlLogoutPending, logouts.Logouts[0].Outcome)
	r.Empty(svc.liveIdPSessions(created.Slug))
}

func TestSAMLSingleLogoutSettings(t *testing.T) {
	r := require.New(t)
	_, handler := newAcceptanceAPI(t)
	created := acceptanceEnvironment(t, handler, `{"name":"Greendale","saml_enabled":true,"saml_acs_url":"https://sp.greendale.test/acs","saml_slo_url":"`+testSPSLOURL+`"}`)
	r.Equal(testSPSLOURL, created.SAMLSLOURL)
	base := "/api/v1/environments/" + created.ID
	get := func() app {
		var got app
		r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base, "", http.StatusOK).Body.Bytes(), &got))
		return got
	}

	invalid := acceptanceRequest(t, handler, http.MethodPatch, base, `{"saml_slo_url":"/slo"}`, http.StatusBadRequest)
	r.Contains(invalid.Body.String(), "Single Logout URL")

	var connection struct {
		SAML struct {
			SLOURL   string `json:"slo_url"`
			SPSLOURL string `json:"sp_slo_url"`
		} `json:"saml"`
	}
	r.NoError(json.Unmarshal(acceptanceRequest(t, handler, http.MethodGet, base+"/connection", "", http.StatusOK).Body.Bytes(), &connection))
	r.Equal("http://127.0.0.1:8080/saml/"+created.Slug+"/slo", connection.SAML.SLOURL)
	r.Equal(testSPSLOURL, connection.SAML.SPSLOURL)

	backup := acceptanceRequest(t, handler, http.MethodGet, base+"/backup", "", http.StatusOK).Body.String()
	acceptanceRequest(t, handler, http.MethodPatch, base, `{"saml_slo_url":"https://sp.greendale.test/other"}`, http.StatusOK)
	acceptanceRequest(t, handler, http.MethodPost, base+"/restore", backup, http.StatusOK)
	r.Equal(testSPSLOURL, get().SAMLSLOURL)

	acceptanceRequest(t, handler, http.MethodPatch, base, `{"saml_enabled":false}`, http.StatusOK)
	r.Empty(get().SAMLSLOURL)
}

// testSPSigner is an SP's request-signing key and certificate.
type testSPSigner struct {
	key     *rsa.PrivateKey
	certDER []byte
}

func newTestSPSigner(t *testing.T) *testSPSigner {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	certDER, err := selfSignedCert(key)
	require.NoError(t, err)
	return &testSPSigner{key: key, certDER: certDER}
}

// sloTestApp is troyGreendaleSAMLState with Abed Nadir and the SP's Single
// Logout URL. With pinned set, the environment requires the SP's messages to
// carry that signer's signature.
func sloTestApp(t *testing.T, pinned *testSPSigner) *webApp {
	t.Helper()
	setTestStateFile(t)
	svc := newTestIDPApp(t)
	state, _ := troyGreendaleSAMLState("")
	state.Users = append(state.Users, user{ID: "usr-abed", GivenName: "Abed", FamilyName: "Nadir", Email: "abed@greendale.edu", Username: "anadir", Active: true})
	state.Apps[0].SAMLSLOURL = testSPSLOURL
	if pinned != nil {
		state.Apps[0].SAMLRequestCertPEM = certificatePEM(pinned.certDER)
	}
	require.NoError(t, saveState(state))
	return svc
}

// samlLogoutSignIn signs userID in to greendale over SAML and returns the
// session cookie and the SessionIndex the assertion carried.
func samlLogoutSignIn(t *testing.T, svc *webApp, userID string, cookies ...*http.Cookie) (*http.Cookie, string) {
	t.Helper()
	rec := postSAMLSSO(t, svc, url.Values{"user_id": {userID}}, cookies...)
	statement := findElementByLocalName(postedSAMLAssertion(t, rec), "AuthnStatement")
	require.NotNil(t, statement)
	return sessionCookie(t, rec), statement.SelectAttrValue("SessionIndex", "")
}

func postSAMLSSOTo(t *testing.T, svc *webApp, slug string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/saml/"+slug+"/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	return rec
}

// testLogoutRequest is an SP-initiated LogoutRequest. Empty attributes are
// left out.
type testLogoutRequest struct {
	ID, Issuer, Destination, IssueInstant, NotOnOrAfter, NameID, Format string
	SessionIndexes                                                      []string
}

// newTestLogoutRequest logs Troy out of the session with sessionIndex.
func newTestLogoutRequest(sessionIndex string) testLogoutRequest {
	return testLogoutRequest{
		ID:           "_logout-troy",
		Issuer:       "urn:greendale:sp",
		Destination:  testIDPSLOURL,
		IssueInstant: time.Now().UTC().Format(time.RFC3339),
		NameID:       "troy@greendale.edu",
		Format:       testEmailNameIDs,
		SessionIndexes: []string{
			sessionIndex,
		},
	}
}

func (l testLogoutRequest) xml() string {
	var b strings.Builder
	b.WriteString(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Version="2.0"`)
	for _, attribute := range [][2]string{{"ID", l.ID}, {"IssueInstant", l.IssueInstant}, {"Destination", l.Destination}, {"NotOnOrAfter", l.NotOnOrAfter}} {
		if attribute[1] != "" {
			fmt.Fprintf(&b, ` %s="%s"`, attribute[0], xmlEscape(attribute[1]))
		}
	}
	b.WriteString(">")
	if l.Issuer != "" {
		b.WriteString("<saml:Issuer>" + xmlEscape(l.Issuer) + "</saml:Issuer>")
	}
	if l.NameID != "" {
		b.WriteString(`<saml:NameID Format="` + xmlEscape(l.Format) + `">` + xmlEscape(l.NameID) + "</saml:NameID>")
	}
	for _, index := range l.SessionIndexes {
		b.WriteString("<samlp:SessionIndex>" + xmlEscape(index) + "</samlp:SessionIndex>")
	}
	b.WriteString("</samlp:LogoutRequest>")
	return b.String()
}

// testSPLogoutResponse is the SP's answer to the LogoutRequest inResponseTo.
func testSPLogoutResponse(inResponseTo, status string) string {
	return fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout-response-troy" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>urn:greendale:sp</saml:Issuer><samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status></samlp:LogoutResponse>`,
		time.Now().UTC().Format(time.RFC3339), testIDPSLOURL, inResponseTo, status)
}

// sendSAMLLogoutMessage delivers an SP's logout message to slug's Single
// Logout service over binding, as the browser would. With signer set, it
// signs the message for that binding.
func sendSAMLLogoutMessage(t *testing.T, svc *webApp, slug, binding, param, messageXML, relayState string, signer *testSPSigner, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if binding == samlHTTPRedirectBinding {
		query := param + "=" + url.QueryEscape(encodeRedirectSAMLRequest(t, messageXML))
		if relayState != "" {
			query += "&RelayState=" + url.QueryEscape(relayState)
		}
		if signer != nil {
			query += "&SigAlg=" + url.QueryEscape(rsaSHA256SignatureMethod)
			digest := sha256.Sum256([]byte(query))
			signature, err := rsa.SignPKCS1v15(rand.Reader, signer.key, crypto.SHA256, digest[:])
			require.NoError(t, err)
			query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(signature))
		}
		req = httptest.NewRequest(http.MethodGet, "/saml/"+slug+"/slo?"+query, nil)
	} else {
		if signer != nil {
			doc := mustParseXML(t, messageXML)
			ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.certDER})
			require.NoError(t, err)
			ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
			signed, err := ctx.SignEnveloped(doc.Root())
			require.NoError(t, err)
			doc.SetRoot(signed)
			messageXML, err = doc.WriteToString()
			require.NoError(t, err)
		}
		form := url.Values{param: {base64.StdEncoding.EncodeToString([]byte(messageXML))}}
		if relayState != "" {
			form.Set("RelayState", relayState)
		}
		req = httptest.NewRequest(http.MethodPost, "/saml/"+slug+"/slo", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	return rec
}

// sendSAMLInspectorLogout presses Send LogoutRequest in the SAML inspector.
func sendSAMLInspectorLogout(t *testing.T, svc *webApp, sessionID, binding string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"return_tab": {"saml-inspector"}, "session_id": {sessionID}, "binding": {binding}}
	req := httptest.NewRequest(http.MethodPost, "/inspect/saml/greendale/sessions/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	svc.routes().ServeHTTP(rec, req)
	return rec
}

// receivedSAMLLogoutMessage reads the logout message that the IdP sent the
// browser to the SP with, checks its signature against the IdP certificate
// without scimtest's own validators, and returns its root and RelayState.
func receivedSAMLLogoutMessage(t *testing.T, svc *webApp, rec *httptest.ResponseRecorder, binding, param string) (*etree.Element, string) {
	t.Helper()
	return receivedSAMLLogoutMessageWithCertificate(t, rec, binding, param, svc.certDER)
}

func receivedSAMLLogoutMessageWithCertificate(t *testing.T, rec *httptest.ResponseRecorder, binding, param string, certDER []byte) (*etree.Element, string) {
	t.Helper()
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	if binding == samlHTTPRedirectBinding {
		require.Equal(t, http.StatusFound, rec.Code, rec.Body.String())
		location, err := url.Parse(rec.Header().Get("Location"))
		require.NoError(t, err)
		require.Equal(t, testSPSLOURL, location.Scheme+"://"+location.Host+location.Path)
		signedQuery, rawSignature, found := strings.Cut(location.RawQuery, "&Signature=")
		require.True(t, found, location.RawQuery)
		require.True(t, strings.HasPrefix(signedQuery, param+"="), signedQuery)
		encodedSignature, err := url.QueryUnescape(rawSignature)
		require.NoError(t, err)
		signature, err := base64.StdEncoding.DecodeString(encodedSignature)
		require.NoError(t, err)
		digest := sha256.Sum256([]byte(signedQuery))
		require.NoError(t, rsa.VerifyPKCS1v15(cert.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], signature))
		query := location.Query()
		require.Equal(t, rsaSHA256SignatureMethod, query.Get("SigAlg"))
		compressed, err := base64.StdEncoding.DecodeString(query.Get(param))
		require.NoError(t, err)
		messageXML, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
		require.NoError(t, err)
		root := mustParseXML(t, string(messageXML)).Root()
		require.Nil(t, findElementByLocalName(root, "Signature"), "HTTP-Redirect messages carry no XML signature")
		return root, query.Get("RelayState")
	}
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Contains(t, rec.Body.String(), `action="`+testSPSLOURL+`"`)
	messageXML, err := base64.StdEncoding.DecodeString(hiddenInputValue(rec.Body.String(), param))
	require.NoError(t, err)
	root := mustParseXML(t, string(messageXML)).Root()
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	_, err = validator.Validate(root)
	require.NoError(t, err)
	return root, hiddenInputValue(rec.Body.String(), "RelayState")
}

func testSAMLStatus(response *etree.Element) samlStatus {
	status := childElementByLocalName(response, "Status")
	code := childElementByLocalName(status, "StatusCode")
	result := samlStatus{Code: code.SelectAttrValue("Value", ""), Message: childElementTextByLocalName(status, "StatusMessage")}
	if sub := childElementByLocalName(code, "StatusCode"); sub != nil {
		result.SubCode = sub.SelectAttrValue("Value", "")
	}
	return result
}

// samlLogoutTranscript returns the newest Single Logout transcript in the
// Traffic view.
func samlLogoutTranscript(t *testing.T, svc *webApp) string {
	t.Helper()
	for _, transcript := range svc.traffic.snapshot() {
		if strings.Contains(transcript, "===== SAML Single Logout ") {
			return transcript
		}
	}
	t.Fatal("no SAML Single Logout transcript recorded")
	return ""
}

func cookieCleared(rec *httptest.ResponseRecorder, name string) bool {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name && cookie.MaxAge < 0 {
			return true
		}
	}
	return false
}

func TestInvalidSAMLLogoutResponseDoesNotConsumePendingRequest(t *testing.T) {
	for name, binding := range map[string]string{"redirect": samlHTTPRedirectBinding, "post": samlHTTPPostBinding} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			signer := newTestSPSigner(t)
			svc := sloTestApp(t, signer)
			cookie, _ := samlLogoutSignIn(t, svc, "usr-troy")
			request, _ := receivedSAMLLogoutMessage(t, svc, sendSAMLInspectorLogout(t, svc, cookie.Value, name), binding, "SAMLRequest")
			requestID := request.SelectAttrValue("ID", "")
			responseXML := testSPLogoutResponse(requestID, samlStatusSuccess)
			bad := sendSAMLLogoutMessage(t, svc, "greendale", binding, "SAMLResponse", responseXML, "", nil)
			r.Equal(http.StatusBadRequest, bad.Code, bad.Body.String())
			valid := sendSAMLLogoutMessage(t, svc, "greendale", binding, "SAMLResponse", responseXML, "", signer)
			r.Equal(http.StatusOK, valid.Code, valid.Body.String())
			logout, found := svc.samlLogoutResult("greendale", requestID)
			r.True(found)
			r.Equal("ok", logout.Outcome)
		})
	}
}

func TestSAMLLogoutUsesRotatedEnvironmentKey(t *testing.T) {
	for name, binding := range map[string]string{"redirect": samlHTTPRedirectBinding, "post": samlHTTPPostBinding} {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			svc := sloTestApp(t, nil)
			cookie, _ := samlLogoutSignIn(t, svc, "usr-troy")
			state, err := loadStateForAppSlug("greendale")
			r.NoError(err)
			_, err = svc.rotateEnvironmentSigningKey(state.Apps[0], 0, time.Now())
			r.NoError(err)
			certificates := samlMetadataCertificates(t, svc.routes(), "greendale")
			r.Len(certificates, 1)
			r.NotEqual(svc.certDER, certificates[0])
			sent := sendSAMLInspectorLogout(t, svc, cookie.Value, name)
			receivedSAMLLogoutMessageWithCertificate(t, sent, binding, "SAMLRequest", certificates[0])
			cookie, sessionIndex := samlLogoutSignIn(t, svc, "usr-troy")
			answer := sendSAMLLogoutMessage(t, svc, "greendale", binding, "SAMLRequest", newTestLogoutRequest(sessionIndex).xml(), "", nil, cookie)
			response, _ := receivedSAMLLogoutMessageWithCertificate(t, answer, binding, "SAMLResponse", certificates[0])
			r.True(testSAMLStatus(response).success())
		})
	}
}
