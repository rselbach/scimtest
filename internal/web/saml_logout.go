package web

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// SAML Single Logout (SAML 2.0 Profiles, section 4.4) over the HTTP-Redirect
// and HTTP-POST bindings. An SP-initiated LogoutRequest arrives at
// /saml/{slug}/slo and ends the IdP sessions it names. An IdP-initiated one
// starts from the SAML inspector or the API and travels through the tester's
// browser; the SP's LogoutResponse comes back to the same endpoint.

const (
	samlHTTPRedirectBinding    = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	samlStatusSuccess          = "urn:oasis:names:tc:SAML:2.0:status:Success"
	samlStatusRequester        = "urn:oasis:names:tc:SAML:2.0:status:Requester"
	samlStatusUnknownPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
	samlLogoutReasonAdmin      = "urn:oasis:names:tc:SAML:2.0:logout:admin"

	// samlLogoutClockSkew is the clock difference tolerated in an SP's
	// IssueInstant and NotOnOrAfter.
	samlLogoutClockSkew = 3 * time.Minute
	// samlLogoutMessageLifetime bounds how old an SP's logout message may
	// be, and sets NotOnOrAfter on the LogoutRequests scimtest sends.
	samlLogoutMessageLifetime = 5 * time.Minute

	samlLogoutPending = "pending"
)

// samlLogoutMessage is a Single Logout message as it arrived at the
// SingleLogoutService.
type samlLogoutMessage struct {
	Binding    string // samlHTTPRedirectBinding or samlHTTPPostBinding
	Param      string // SAMLRequest or SAMLResponse
	Encoded    string
	RelayState string
	XML        string
	Root       *etree.Element
}

// samlLogoutRequest is an SP-initiated LogoutRequest.
type samlLogoutRequest struct {
	ID             string
	NameID         string
	NameIDFormat   string
	SessionIndexes []string
}

// samlStatus is the Status of a SAML protocol response.
type samlStatus struct {
	Code    string
	SubCode string
	Message string
}

func (s samlStatus) success() bool { return s.Code == samlStatusSuccess }

// String names the status codes by their last URN segment, then the message.
func (s samlStatus) String() string {
	text := s.Code[strings.LastIndex(s.Code, ":")+1:]
	if s.SubCode != "" {
		text += "/" + s.SubCode[strings.LastIndex(s.SubCode, ":")+1:]
	}
	if s.Message != "" {
		text += ": " + s.Message
	}
	return text
}

func (s samlStatus) xml() string {
	var b strings.Builder
	b.WriteString(`<samlp:Status><samlp:StatusCode Value="` + xmlEscape(s.Code) + `"`)
	if s.SubCode != "" {
		b.WriteString(`><samlp:StatusCode Value="` + xmlEscape(s.SubCode) + `"/></samlp:StatusCode>`)
	} else {
		b.WriteString(`/>`)
	}
	if s.Message != "" {
		b.WriteString(`<samlp:StatusMessage>` + xmlEscape(s.Message) + `</samlp:StatusMessage>`)
	}
	b.WriteString(`</samlp:Status>`)
	return b.String()
}

// samlOutboundMessage is a signed Single Logout message for the browser to
// carry to the SP.
type samlOutboundMessage struct {
	ID          string
	Binding     string
	Param       string // SAMLRequest or SAMLResponse
	Destination string
	XML         string // as sent; HTTP-Redirect signs the URL instead
	RelayState  string
	URL         string // HTTP-Redirect: Destination with the signed query
	Encoded     string // HTTP-POST: the base64 form value
}

// deliver sends the browser on to the SP: a redirect for HTTP-Redirect, or
// an auto-submitting form for HTTP-POST.
func (m samlOutboundMessage) deliver(w http.ResponseWriter, r *http.Request) {
	if m.Binding == samlHTTPRedirectBinding {
		http.Redirect(w, r, m.URL, http.StatusFound)
		return
	}
	renderPostBack(w, m.Destination, map[string]string{m.Param: m.Encoded, "RelayState": m.RelayState})
}

// samlLogout is a LogoutRequest scimtest sent to an SP, and the SP's answer.
type samlLogout struct {
	RequestID   string `json:"request_id"`
	SessionID   string `json:"session_id"`
	User        string `json:"user"`
	Binding     string `json:"binding"`
	Destination string `json:"destination"`
	SentAt      string `json:"sent_at"`
	Outcome     string `json:"outcome"`          // pending, ok, or failed
	Status      string `json:"status,omitempty"` // the SP's top-level StatusCode
	Detail      string `json:"detail,omitempty"`
	AnsweredAt  string `json:"answered_at,omitempty"`
}

// samlLogoutTraffic is one decoded message in a Single Logout transcript.
type samlLogoutTraffic struct {
	Heading string
	XML     string
}

// handleSAMLSLO is the IdP's SingleLogoutService for the HTTP-Redirect (GET)
// and HTTP-POST bindings. A SAMLRequest is an SP-initiated LogoutRequest. A
// SAMLResponse answers a LogoutRequest that scimtest sent.
func (a *webApp) handleSAMLSLO(w http.ResponseWriter, r *http.Request) {
	if !a.allowTunneledChooser(w, r) {
		return
	}
	state, app, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}
	message, err := readSAMLLogoutMessage(r)
	if err != nil {
		a.failFlow(w, app, "saml", "logout", http.StatusBadRequest, err.Error())
		return
	}
	baseURL := a.effectiveIDPBaseURL(r, state)
	if message.Param == "SAMLResponse" {
		a.serveSAMLLogoutResponse(w, r, app, baseURL, message)
		return
	}
	a.serveSAMLLogoutRequest(w, r, app, baseURL, message)
}

// readSAMLLogoutMessage reads the one SAMLRequest or SAMLResponse that a
// Single Logout request carries: in the URL for HTTP-Redirect, or in the form
// body for HTTP-POST.
func readSAMLLogoutMessage(r *http.Request) (samlLogoutMessage, error) {
	values := r.URL.Query()
	message := samlLogoutMessage{Binding: samlHTTPRedirectBinding}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return samlLogoutMessage{}, err
		}
		values = r.PostForm
		message.Binding = samlHTTPPostBinding
	}
	request, response := values.Get("SAMLRequest"), values.Get("SAMLResponse")
	switch {
	case request != "" && response != "":
		return samlLogoutMessage{}, errors.New("send either SAMLRequest or SAMLResponse, not both")
	case request != "":
		message.Param, message.Encoded = "SAMLRequest", request
	case response != "":
		message.Param, message.Encoded = "SAMLResponse", response
	default:
		return samlLogoutMessage{}, errors.New("SAMLRequest or SAMLResponse is required")
	}
	message.RelayState = values.Get("RelayState")
	doc, err := parseSAMLRequestDocument(message.Encoded)
	if err != nil {
		return samlLogoutMessage{}, err
	}
	message.Root = doc.Root()
	message.XML, err = doc.WriteToString()
	if err != nil {
		return samlLogoutMessage{}, fmt.Errorf("serialize %s: %w", message.Param, err)
	}
	return message, nil
}

// serveSAMLLogoutRequest handles SP-initiated Single Logout. A request that
// is malformed, comes from another issuer, or fails signature checks gets a
// plain 400. Any other request comes from the environment's SP, so it gets a
// signed LogoutResponse through the same binding, with an error status when
// it names the wrong session.
func (a *webApp) serveSAMLLogoutRequest(w http.ResponseWriter, r *http.Request, app app, baseURL string, message samlLogoutMessage) {
	request, err := parseSAMLLogoutRequest(message.Root)
	if err == nil && strings.TrimSpace(app.SAMLSLOURL) == "" {
		err = errors.New("set the SP's Single Logout URL on the environment before sending LogoutRequests")
	}
	var signed bool
	if err == nil {
		signed, err = verifySAMLLogoutSender(r, app, message, "LogoutRequest")
	}
	if err != nil {
		a.recordSAMLLogoutTraffic("Rejected with HTTP 400: "+err.Error(), samlLogoutTraffic{"LogoutRequest from SP (" + samlBindingName(message.Binding) + ")", message.XML})
		a.failFlow(w, app, "saml", "logout", http.StatusBadRequest, err.Error())
		return
	}

	browserID := browserSessionID(r, app.Slug)
	var status samlStatus
	var ended []idpSession
	if err := checkSAMLLogoutMessage(message.Root, "LogoutRequest", samlSLOEndpoint(baseURL, app.Slug), signed, time.Now()); err != nil {
		status = samlStatus{Code: samlStatusRequester, Message: err.Error()}
	} else {
		var targets []idpSession
		targets, status = matchSAMLLogoutSessions(a.liveSAMLSessions(app.Slug), request, browserID)
		ended = a.endIdPSessions(func(session idpSession) string {
			if !slices.ContainsFunc(targets, func(target idpSession) bool { return target.ID == session.ID }) {
				return ""
			}
			return "SAML logout from the SP"
		})
	}
	if slices.ContainsFunc(ended, func(session idpSession) bool { return session.ID == browserID }) {
		forgetIdPSession(w, app.Slug)
	}

	responseXML, err := buildSAMLLogoutResponse(samlIDPEntityID(baseURL, app.Slug), app.SAMLSLOURL, request.ID, status, time.Now())
	if err == nil {
		var response samlOutboundMessage
		response, err = a.encodeSAMLLogoutMessage(app, message.Binding, "SAMLResponse", app.SAMLSLOURL, responseXML, message.RelayState)
		if err == nil {
			a.recordSPInitiatedLogout(app, request, message, response, status, ended)
			response.deliver(w, r)
			return
		}
	}
	a.failFlow(w, app, "saml", "logout", http.StatusInternalServerError, err.Error())
}

// recordSPInitiatedLogout records an SP-initiated logout's outcome in flow
// activity and the Traffic view.
func (a *webApp) recordSPInitiatedLogout(app app, request samlLogoutRequest, message samlLogoutMessage, response samlOutboundMessage, status samlStatus, ended []idpSession) {
	binding := samlBindingName(message.Binding)
	var users, sessions []string
	for _, session := range ended {
		users = append(users, session.User)
		sessions = append(sessions, session.SAMLSessionIndex)
	}
	outcome, detail := "ok", fmt.Sprintf("LogoutRequest %s from the SP ended session %s; answered Success via %s", request.ID, strings.Join(sessions, ", "), binding)
	switch {
	case !status.success():
		outcome, detail = "failed", fmt.Sprintf("LogoutRequest %s from the SP answered %s via %s", request.ID, status, binding)
	case len(ended) == 0:
		detail = fmt.Sprintf("LogoutRequest %s from the SP matched no live session; answered Success via %s", request.ID, binding)
	}
	a.recordFlowEvent(app.Slug, "saml", "logout", outcome, strings.Join(users, ", "), detail)
	a.recordSAMLLogoutTraffic(detail,
		samlLogoutTraffic{"LogoutRequest from SP (" + binding + ")", message.XML},
		samlLogoutTraffic{"LogoutResponse to " + response.Destination + " (" + binding + ")", response.XML},
	)
}

// parseSAMLLogoutRequest reads a LogoutRequest's ID, NameID, and
// SessionIndex values.
func parseSAMLLogoutRequest(root *etree.Element) (samlLogoutRequest, error) {
	if elementLocalName(root) != "LogoutRequest" || root.NamespaceURI() != samlProtocolXMLNS {
		return samlLogoutRequest{}, errors.New("SAMLRequest must contain a LogoutRequest; AuthnRequests go to the SSO URL")
	}
	request := samlLogoutRequest{ID: strings.TrimSpace(root.SelectAttrValue("ID", ""))}
	if request.ID == "" {
		return samlLogoutRequest{}, errors.New("SAML LogoutRequest ID is required")
	}
	for _, child := range root.ChildElements() {
		switch elementLocalName(child) {
		case "NameID":
			request.NameID = strings.TrimSpace(child.Text())
			request.NameIDFormat = strings.TrimSpace(child.SelectAttrValue("Format", ""))
		case "EncryptedID", "BaseID":
			return samlLogoutRequest{}, fmt.Errorf("SAML LogoutRequest %s is not supported; send the NameID from the assertion", elementLocalName(child))
		case "SessionIndex":
			request.SessionIndexes = append(request.SessionIndexes, strings.TrimSpace(child.Text()))
		}
	}
	if request.NameID == "" {
		return samlLogoutRequest{}, errors.New("SAML LogoutRequest NameID is required")
	}
	return request, nil
}

// verifySAMLLogoutSender checks that a logout message comes from the
// environment's SP. Its Issuer must be present, and must match the SP entity
// ID when one is set. When the environment pins a request-signing
// certificate, the message must be signed for its binding, as AuthnRequests
// must. It reports whether a signature was verified.
func verifySAMLLogoutSender(r *http.Request, app app, message samlLogoutMessage, kind string) (bool, error) {
	issuer := childElementTextByLocalName(message.Root, "Issuer")
	expected := strings.TrimSpace(app.SAMLEntityID)
	switch {
	case issuer == "":
		return false, fmt.Errorf("SAML %s Issuer is required", kind)
	case expected != "" && issuer != expected:
		return false, fmt.Errorf("SAML %s issuer %q does not match the configured app", kind, issuer)
	}
	cert, err := parseSAMLRequestCertificate(app.SAMLRequestCertPEM)
	if err != nil || cert == nil {
		return false, err
	}
	if message.Binding == samlHTTPRedirectBinding {
		return true, validateRedirectSAMLSignature(r.URL.RawQuery, message.Param, kind, cert)
	}
	return true, validatePOSTSAMLSignature(message.Encoded, kind, cert)
}

// checkSAMLLogoutMessage checks a logout message's Destination and
// timestamps. A signed message must name its Destination.
func checkSAMLLogoutMessage(root *etree.Element, kind, wantDestination string, signed bool, now time.Time) error {
	destination := strings.TrimSpace(root.SelectAttrValue("Destination", ""))
	switch {
	case destination == "" && signed:
		return fmt.Errorf("signed SAML %s must carry Destination %s", kind, wantDestination)
	case destination != "" && destination != wantDestination:
		return fmt.Errorf("SAML %s destination %q does not match %s", kind, destination, wantDestination)
	}
	rawIssued := strings.TrimSpace(root.SelectAttrValue("IssueInstant", ""))
	issued, err := time.Parse(time.RFC3339, rawIssued)
	switch {
	case rawIssued == "":
		return fmt.Errorf("SAML %s IssueInstant is required", kind)
	case err != nil:
		return fmt.Errorf("SAML %s IssueInstant %q is not a UTC xs:dateTime", kind, rawIssued)
	case issued.After(now.Add(samlLogoutClockSkew)):
		return fmt.Errorf("SAML %s IssueInstant %s is in the future", kind, rawIssued)
	case issued.Before(now.Add(-samlLogoutMessageLifetime - samlLogoutClockSkew)):
		return fmt.Errorf("SAML %s IssueInstant %s is more than %s old", kind, rawIssued, samlLogoutMessageLifetime)
	}
	if rawExpiry := strings.TrimSpace(root.SelectAttrValue("NotOnOrAfter", "")); rawExpiry != "" {
		expiry, err := time.Parse(time.RFC3339, rawExpiry)
		if err != nil {
			return fmt.Errorf("SAML %s NotOnOrAfter %q is not a UTC xs:dateTime", kind, rawExpiry)
		}
		if !now.Before(expiry.Add(samlLogoutClockSkew)) {
			return fmt.Errorf("SAML %s expired at %s", kind, rawExpiry)
		}
	}
	return nil
}

// matchSAMLLogoutSessions picks the sessions a LogoutRequest ends: those with
// its NameID and, when it lists SessionIndex values, one of them. A request
// whose SessionIndex names a session with another NameID, whose SessionIndex
// matches none of its NameID's sessions, or whose NameID differs from the
// browser's own SAML session gets an error status instead. A request that
// matches nothing else ends nothing and succeeds, since its sessions may
// already have ended.
func matchSAMLLogoutSessions(sessions []idpSession, request samlLogoutRequest, browserSessionID string) ([]idpSession, samlStatus) {
	nameMatches := func(session idpSession) bool {
		return session.SAMLNameID == request.NameID && (request.NameIDFormat == "" || request.NameIDFormat == session.SAMLNameIDFormat)
	}
	var matched []idpSession
	for _, session := range sessions {
		if len(request.SessionIndexes) > 0 && !slices.Contains(request.SessionIndexes, session.SAMLSessionIndex) {
			continue
		}
		if nameMatches(session) {
			matched = append(matched, session)
			continue
		}
		if len(request.SessionIndexes) > 0 {
			return nil, samlStatus{Code: samlStatusRequester, SubCode: samlStatusUnknownPrincipal, Message: fmt.Sprintf(
				"NameID %s does not match the NameID %s of session %s", describeNameID(request.NameID, request.NameIDFormat), describeNameID(session.SAMLNameID, session.SAMLNameIDFormat), session.SAMLSessionIndex)}
		}
	}
	switch {
	case len(matched) > 0:
		return matched, samlStatus{Code: samlStatusSuccess}
	case slices.ContainsFunc(sessions, nameMatches):
		return nil, samlStatus{Code: samlStatusRequester, Message: fmt.Sprintf(
			"SessionIndex %s matches no live session for NameID %q", strings.Join(request.SessionIndexes, ", "), request.NameID)}
	}
	for _, session := range sessions {
		if session.ID == browserSessionID {
			return nil, samlStatus{Code: samlStatusRequester, SubCode: samlStatusUnknownPrincipal, Message: fmt.Sprintf(
				"NameID %s does not match this browser's session, which has %s", describeNameID(request.NameID, request.NameIDFormat), describeNameID(session.SAMLNameID, session.SAMLNameIDFormat))}
		}
	}
	return nil, samlStatus{Code: samlStatusSuccess}
}

func describeNameID(value, format string) string {
	if format == "" {
		return fmt.Sprintf("%q", value)
	}
	return fmt.Sprintf("%q (%s)", value, format)
}

// liveSAMLSessions returns slug's live sessions that include a SAML sign-in.
func (a *webApp) liveSAMLSessions(slug string) []idpSession {
	a.expireIdPSessions(time.Now())
	a.sessionMu.Lock()
	var sessions []idpSession
	for _, session := range a.idpSessions {
		if session.AppSlug == slug && session.SAMLSessionIndex != "" {
			sessions = append(sessions, session)
		}
	}
	a.sessionMu.Unlock()
	slices.SortFunc(sessions, func(x, y idpSession) int { return x.Started.Compare(y.Started) })
	return sessions
}

// browserSessionID returns the session ID that the browser's cookie names
// for slug, live or not.
func browserSessionID(r *http.Request, slug string) string {
	cookie, err := r.Cookie(signInCookieName(slug))
	if err != nil {
		return ""
	}
	return cookie.Value
}

// serveSAMLLogoutResponse handles the SP's answer to a LogoutRequest that
// scimtest sent, and shows the tester the result.
func (a *webApp) serveSAMLLogoutResponse(w http.ResponseWriter, r *http.Request, app app, baseURL string, message samlLogoutMessage) {
	root := message.Root
	if elementLocalName(root) != "LogoutResponse" || root.NamespaceURI() != samlProtocolXMLNS {
		a.failFlow(w, app, "saml", "logout", http.StatusBadRequest, "SAMLResponse must contain a LogoutResponse")
		return
	}
	requestID := strings.TrimSpace(root.SelectAttrValue("InResponseTo", ""))
	binding := samlBindingName(message.Binding)
	status, err := checkSAMLLogoutResponse(r, app, baseURL, message, time.Now())
	if err != nil {
		problem := "SAML LogoutResponse rejected: " + err.Error()
		a.recordSAMLLogoutTraffic("Rejected with HTTP 400: "+problem, samlLogoutTraffic{"LogoutResponse from SP (" + binding + ")", message.XML})
		a.failFlow(w, app, "saml", "logout", http.StatusBadRequest, problem)
		return
	}
	outcome, statusCode, detail := "failed", "", ""
	switch {
	case status.success():
		outcome, statusCode, detail = "ok", status.Code, "the SP answered "+status.String()
	default:
		statusCode, detail = status.Code, "the SP answered "+status.String()
	}
	logout, pending := a.settleSAMLLogout(app.Slug, requestID, outcome, statusCode, detail)
	if !pending {
		problem := fmt.Sprintf("LogoutResponse InResponseTo %q does not match a pending LogoutRequest from scimtest", requestID)
		a.recordSAMLLogoutTraffic("Rejected with HTTP 400: "+problem, samlLogoutTraffic{"LogoutResponse from SP (" + binding + ")", message.XML})
		a.failFlow(w, app, "saml", "logout", http.StatusBadRequest, problem)
		return
	}
	summary := fmt.Sprintf("LogoutResponse to %s via %s: %s", requestID, binding, detail)
	a.recordSAMLLogoutTraffic(summary, samlLogoutTraffic{"LogoutResponse from SP (" + binding + ")", message.XML})
	a.recordFlowEvent(app.Slug, "saml", "logout", outcome, logout.User, summary)
	renderLogoutPage(w, logoutPage{AppName: app.Name, User: logout.User, Detail: "The service provider answered " + status.String() + "."})
}

// checkSAMLLogoutResponse verifies the SP's LogoutResponse and returns its
// status.
func checkSAMLLogoutResponse(r *http.Request, app app, baseURL string, message samlLogoutMessage, now time.Time) (samlStatus, error) {
	signed, err := verifySAMLLogoutSender(r, app, message, "LogoutResponse")
	if err != nil {
		return samlStatus{}, err
	}
	if err := checkSAMLLogoutMessage(message.Root, "LogoutResponse", samlSLOEndpoint(baseURL, app.Slug), signed, now); err != nil {
		return samlStatus{}, err
	}
	statusElement := childElementByLocalName(message.Root, "Status")
	code := childElementByLocalName(statusElement, "StatusCode")
	if code == nil || strings.TrimSpace(code.SelectAttrValue("Value", "")) == "" {
		return samlStatus{}, errors.New("SAML LogoutResponse has no StatusCode")
	}
	status := samlStatus{
		Code:    strings.TrimSpace(code.SelectAttrValue("Value", "")),
		Message: childElementTextByLocalName(statusElement, "StatusMessage"),
	}
	if sub := childElementByLocalName(code, "StatusCode"); sub != nil {
		status.SubCode = strings.TrimSpace(sub.SelectAttrValue("Value", ""))
	}
	return status, nil
}

// handleSAMLSessionLogout ends a session from the SAML inspector and sends
// its SP a LogoutRequest through the tester's browser.
func (a *webApp) handleSAMLSessionLogout(w http.ResponseWriter, r *http.Request) {
	state, foundApp, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	message, err := a.logOutSAMLSession(foundApp, a.effectiveIDPBaseURL(r, state), r.FormValue("session_id"), r.FormValue("binding"))
	if err != nil {
		a.recordFlowEvent(foundApp.Slug, "saml", "logout", "failed", "", err.Error())
		http.Redirect(w, r, inspectorReturnPath(r, foundApp), http.StatusSeeOther)
		return
	}
	message.deliver(w, r)
}

// logOutSAMLSession ends slug's live session sessionID, then starts
// IdP-initiated Single Logout for it.
func (a *webApp) logOutSAMLSession(app app, baseURL, sessionID, rawBinding string) (samlOutboundMessage, error) {
	binding, err := parseSAMLBinding(rawBinding)
	if err != nil {
		return samlOutboundMessage{}, err
	}
	session, live := a.liveIdPSession(app.Slug, sessionID)
	switch {
	case !live:
		return samlOutboundMessage{}, fmt.Errorf("session %q is not live", sessionID)
	case session.SAMLSessionIndex == "":
		return samlOutboundMessage{}, fmt.Errorf("session %q has no SAML sign-in", sessionID)
	case strings.TrimSpace(app.SAMLSLOURL) == "":
		return samlOutboundMessage{}, errors.New("set the SP's Single Logout URL on the environment before sending a LogoutRequest")
	}
	a.endAppIdPSessions(app.Slug, session.ID, "IdP-initiated SAML logout")
	return a.startSAMLLogout(app, baseURL, session, binding)
}

// startSAMLLogout builds a signed LogoutRequest for session, which may
// already have ended, and records it as pending until the SP answers. The
// caller delivers the message through a browser, and samlLogoutResult reports
// the SP's answer. Ending a session does not call this by itself, since the
// HTTP-Redirect and HTTP-POST bindings need a browser to carry the message.
func (a *webApp) startSAMLLogout(app app, baseURL string, session idpSession, binding string) (samlOutboundMessage, error) {
	switch {
	case strings.TrimSpace(app.SAMLSLOURL) == "":
		return samlOutboundMessage{}, errors.New("set the SP's Single Logout URL on the environment before sending a LogoutRequest")
	case session.SAMLSessionIndex == "":
		return samlOutboundMessage{}, fmt.Errorf("session %q has no SAML sign-in", session.ID)
	}
	now := time.Now()
	requestID, requestXML, err := buildSAMLLogoutRequest(samlIDPEntityID(baseURL, app.Slug), app.SAMLSLOURL, session, now)
	if err != nil {
		return samlOutboundMessage{}, err
	}
	message, err := a.encodeSAMLLogoutMessage(app, binding, "SAMLRequest", app.SAMLSLOURL, requestXML, "")
	if err != nil {
		return samlOutboundMessage{}, err
	}
	message.ID = requestID
	a.rememberSAMLLogout(app.Slug, samlLogout{
		RequestID:   requestID,
		SessionID:   session.ID,
		User:        session.User,
		Binding:     samlBindingName(binding),
		Destination: app.SAMLSLOURL,
		SentAt:      now.UTC().Format(time.RFC3339),
		Outcome:     samlLogoutPending,
	})
	detail := fmt.Sprintf("LogoutRequest %s for session %s sent to %s through the browser (%s)", requestID, session.SAMLSessionIndex, app.SAMLSLOURL, samlBindingName(binding))
	a.recordFlowEvent(app.Slug, "saml", "logout", "ok", session.User, detail)
	a.recordSAMLLogoutTraffic(detail, samlLogoutTraffic{"LogoutRequest to " + app.SAMLSLOURL + " (" + samlBindingName(binding) + ")", message.XML})
	return message, nil
}

// buildSAMLLogoutRequest builds an unsigned IdP-initiated LogoutRequest for
// session and returns its ID.
func buildSAMLLogoutRequest(issuer, destination string, session idpSession, now time.Time) (string, string, error) {
	id, err := newID("saml-logout-request")
	if err != nil {
		return "", "", fmt.Errorf("generate SAML LogoutRequest ID: %w", err)
	}
	format := ""
	if session.SAMLNameIDFormat != "" {
		format = ` Format="` + xmlEscape(session.SAMLNameIDFormat) + `"`
	}
	requestXML := fmt.Sprintf(`<samlp:LogoutRequest xmlns:samlp="%s" xmlns:saml="%s" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" NotOnOrAfter="%s" Reason="%s"><saml:Issuer>%s</saml:Issuer><saml:NameID%s>%s</saml:NameID><samlp:SessionIndex>%s</samlp:SessionIndex></samlp:LogoutRequest>`,
		samlProtocolXMLNS, samlAssertionNS, xmlEscape(id), now.UTC().Format(time.RFC3339), xmlEscape(destination),
		now.UTC().Add(samlLogoutMessageLifetime).Format(time.RFC3339), samlLogoutReasonAdmin, xmlEscape(issuer),
		format, xmlEscape(session.SAMLNameID), xmlEscape(session.SAMLSessionIndex))
	return id, requestXML, nil
}

// buildSAMLLogoutResponse builds an unsigned LogoutResponse to the
// LogoutRequest inResponseTo.
func buildSAMLLogoutResponse(issuer, destination, inResponseTo string, status samlStatus, now time.Time) (string, error) {
	id, err := newID("saml-logout-response")
	if err != nil {
		return "", fmt.Errorf("generate SAML LogoutResponse ID: %w", err)
	}
	return fmt.Sprintf(`<samlp:LogoutResponse xmlns:samlp="%s" xmlns:saml="%s" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s"><saml:Issuer>%s</saml:Issuer>%s</samlp:LogoutResponse>`,
		samlProtocolXMLNS, samlAssertionNS, xmlEscape(id), now.UTC().Format(time.RFC3339), xmlEscape(destination),
		xmlEscape(inResponseTo), xmlEscape(issuer), status.xml()), nil
}

// encodeSAMLLogoutMessage signs messageXML for binding and encodes it as
// param. HTTP-POST carries an enveloped XML signature. HTTP-Redirect deflates
// the message and signs the query string instead.
func (a *webApp) encodeSAMLLogoutMessage(app app, binding, param, destination, messageXML, relayState string) (samlOutboundMessage, error) {
	state, err := loadStateForApp(app.ID)
	if err != nil {
		return samlOutboundMessage{}, err
	}
	key, err := a.activeSigningKey(state)
	if err != nil {
		return samlOutboundMessage{}, err
	}
	message := samlOutboundMessage{Binding: binding, Param: param, Destination: destination, XML: messageXML, RelayState: relayState}
	if binding == samlHTTPPostBinding {
		signed, err := signSAMLLogoutXML(key, messageXML)
		if err != nil {
			return samlOutboundMessage{}, err
		}
		message.XML = signed
		message.Encoded = base64.StdEncoding.EncodeToString([]byte(signed))
		return message, nil
	}
	var compressed bytes.Buffer
	writer, err := flate.NewWriter(&compressed, flate.BestCompression)
	if err != nil {
		return samlOutboundMessage{}, fmt.Errorf("deflate SAML %s: %w", param, err)
	}
	if _, err := writer.Write([]byte(messageXML)); err != nil {
		return samlOutboundMessage{}, fmt.Errorf("deflate SAML %s: %w", param, err)
	}
	if err := writer.Close(); err != nil {
		return samlOutboundMessage{}, fmt.Errorf("deflate SAML %s: %w", param, err)
	}
	query := param + "=" + url.QueryEscape(base64.StdEncoding.EncodeToString(compressed.Bytes()))
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	query += "&SigAlg=" + url.QueryEscape(rsaSHA256SignatureMethod)
	signature, err := signSAMLRedirectQuery(key, query)
	if err != nil {
		return samlOutboundMessage{}, err
	}
	query += "&Signature=" + url.QueryEscape(signature)
	target, err := url.Parse(destination)
	if err != nil {
		return samlOutboundMessage{}, fmt.Errorf("SAML Single Logout URL: %w", err)
	}
	if target.RawQuery != "" {
		query = target.RawQuery + "&" + query
	}
	target.RawQuery = query
	message.URL = target.String()
	return message, nil
}

// signSAMLLogoutXML adds an enveloped signature after the message's Issuer,
// as the HTTP-POST binding carries it.
func signSAMLLogoutXML(key signingKey, messageXML string) (string, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(messageXML); err != nil {
		return "", fmt.Errorf("parse SAML logout message for signing: %w", err)
	}
	ctx, err := dsig.NewSigningContext(key.PrivateKey, [][]byte{key.CertDER})
	if err != nil {
		return "", fmt.Errorf("create SAML signing context: %w", err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if _, err := signSAMLElement(ctx, doc.Root()); err != nil {
		return "", fmt.Errorf("sign SAML logout message: %w", err)
	}
	return doc.WriteToString()
}

// signSAMLRedirectQuery signs an HTTP-Redirect binding query that ends with
// SigAlg, and returns the base64 Signature value.
func signSAMLRedirectQuery(key signingKey, query string) (string, error) {
	digest := sha256.Sum256([]byte(query))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key.PrivateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign SAML Redirect query: %w", err)
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

// parseSAMLBinding accepts redirect or post, with or without the HTTP-
// prefix. Empty means redirect.
func parseSAMLBinding(value string) (string, error) {
	switch strings.TrimPrefix(strings.ToLower(strings.TrimSpace(value)), "http-") {
	case "", "redirect":
		return samlHTTPRedirectBinding, nil
	case "post":
		return samlHTTPPostBinding, nil
	}
	return "", fmt.Errorf("binding must be redirect or post, not %q", value)
}

func samlBindingName(binding string) string {
	if binding == samlHTTPPostBinding {
		return "HTTP-POST"
	}
	return "HTTP-Redirect"
}

func samlIDPEntityID(baseURL, slug string) string { return baseURL + "/saml/" + slug + "/metadata" }

func samlSLOEndpoint(baseURL, slug string) string { return baseURL + "/saml/" + slug + "/slo" }

// samlNameIDFormatForApp returns the NameID format the environment's
// assertions carry.
func samlNameIDFormatForApp(app app) string {
	if app.SAMLNameIDFormat != "" {
		return app.SAMLNameIDFormat
	}
	return samlNameIDFormatForField(app.SAMLNameIDField)
}

// rememberSAMLLogout records an IdP-initiated LogoutRequest, newest first.
func (a *webApp) rememberSAMLLogout(slug string, logout samlLogout) {
	a.samlLogoutMu.Lock()
	defer a.samlLogoutMu.Unlock()
	if a.samlLogoutLog == nil {
		a.samlLogoutLog = make(map[string][]samlLogout)
	}
	entries := append([]samlLogout{logout}, a.samlLogoutLog[slug]...)
	if len(entries) > maxInspections {
		entries = entries[:maxInspections]
	}
	a.samlLogoutLog[slug] = entries
}

// settleSAMLLogout records the SP's answer to the pending LogoutRequest
// requestID. It reports false when no such request is pending.
func (a *webApp) settleSAMLLogout(slug, requestID, outcome, status, detail string) (samlLogout, bool) {
	a.samlLogoutMu.Lock()
	defer a.samlLogoutMu.Unlock()
	for i, logout := range a.samlLogoutLog[slug] {
		if logout.RequestID != requestID || logout.Outcome != samlLogoutPending {
			continue
		}
		logout.Outcome, logout.Status, logout.Detail = outcome, status, detail
		logout.AnsweredAt = time.Now().UTC().Format(time.RFC3339)
		a.samlLogoutLog[slug][i] = logout
		return logout, true
	}
	return samlLogout{}, false
}

// samlLogoutResult returns the IdP-initiated LogoutRequest requestID and the
// SP's answer so far.
func (a *webApp) samlLogoutResult(slug, requestID string) (samlLogout, bool) {
	a.samlLogoutMu.Lock()
	defer a.samlLogoutMu.Unlock()
	for _, logout := range a.samlLogoutLog[slug] {
		if logout.RequestID == requestID {
			return logout, true
		}
	}
	return samlLogout{}, false
}

// recentSAMLLogouts lists slug's IdP-initiated LogoutRequests, newest first.
func (a *webApp) recentSAMLLogouts(slug string) []samlLogout {
	a.samlLogoutMu.Lock()
	defer a.samlLogoutMu.Unlock()
	return append([]samlLogout{}, a.samlLogoutLog[slug]...)
}

// recordSAMLLogoutTraffic renders a Single Logout exchange, with each message
// decoded, for --debug and the Traffic view. Logout messages carry no
// credentials, so their XML is shown even when secrets are hidden.
func (a *webApp) recordSAMLLogoutTraffic(outcome string, messages ...samlLogoutTraffic) {
	stdout := a.debugRPEnabled()
	record := a.trafficRecordEnabled()
	if !stdout && !record {
		return
	}
	var transcript bytes.Buffer
	writeDebugf(&transcript, "===== SAML Single Logout %s =====\n", time.Now().Format(time.RFC3339))
	for _, message := range messages {
		writeDebugf(&transcript, "----- %s -----\n", message.Heading)
		writeDebugln(&transcript, message.XML)
	}
	writeDebugln(&transcript, "----- outcome -----")
	writeDebugln(&transcript, outcome)
	writeDebugln(&transcript, "===== end SAML Single Logout =====")

	rpDebugLogMu.Lock()
	defer rpDebugLogMu.Unlock()
	if stdout {
		writeDebugln(os.Stdout)
		writeDebugln(os.Stdout, transcript.String())
	}
	if record {
		a.traffic.add(transcript.String())
	}
}
