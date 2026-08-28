package web

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// samlPostedResponse is what successful SSO posts, plus the plaintext signed
// Assertion when encryption ran. Status-only builders do not use this type.
type samlPostedResponse struct {
	XML             string
	SignedAssertion string
}

const (
	samlHTTPPostBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
	samlProtocolXMLNS   = "urn:oasis:names:tc:SAML:2.0:protocol"
	maxSAMLRequestBytes = 1 << 20
)

var errSAMLRequestTooLarge = fmt.Errorf("inflated SAMLRequest exceeds %d bytes", maxSAMLRequestBytes)

type samlAuthnRequest struct {
	ID              string
	Issuer          string
	Destination     string
	ACSURL          string
	ProtocolBinding string
}

type samlResponseContext struct {
	ACSURL       string
	InResponseTo string
}

func (a *webApp) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	state, app, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}
	baseURL := a.effectiveIDPBaseURL(r, state)
	entityID := baseURL + "/saml/" + app.Slug + "/metadata"
	nameIDFormat := app.SAMLNameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = samlNameIDFormatForField(app.SAMLNameIDField)
	}
	cert := base64.StdEncoding.EncodeToString(a.certDER)
	metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <NameIDFormat>%s</NameIDFormat>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="%s/saml/%s/sso"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s/saml/%s/sso"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, xmlEscape(entityID), cert, xmlEscape(nameIDFormat), xmlEscape(baseURL), xmlEscape(app.Slug), xmlEscape(baseURL), xmlEscape(app.Slug))
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="scimtest-`+app.Slug+`-idp-metadata.xml"`)
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml; charset=utf-8")
	if _, err := w.Write([]byte(metadata)); err != nil {
		log.Printf("write SAML metadata response: %v", err)
	}
}

func (a *webApp) handleSAMLSSO(w http.ResponseWriter, r *http.Request) {
	a.serveSAMLSSO(w, r, false)
}

func (a *webApp) handleSAMLSSOPost(w http.ResponseWriter, r *http.Request) {
	a.serveSAMLSSO(w, r, true)
}

// serveSAMLSSO handles both SSO bindings. The GET without a selection always
// offers the chooser, so a user_id URL can iterate hands-free. The POST only
// offers it for SP-initiated posts (SAMLRequest, login_hint, or RelayState
// present): the chooser's own submission must never bounce back to it.
func (a *webApp) serveSAMLSSO(w http.ResponseWriter, r *http.Request, post bool) {
	if !a.allowTunneledChooser(w, r) {
		return
	}
	state, app, ok := appForProtocol(w, r, supportsSAML)
	if !ok {
		return
	}
	values := r.URL.Query()
	if post {
		if err := r.ParseForm(); err != nil {
			a.failFlow(w, app, "saml", "sso", http.StatusBadRequest, err.Error())
			return
		}
		values = cloneURLValues(r.Form)
		// A chooser POST retains the original Redirect-binding query. Do not
		// allow hidden or attacker-supplied body fields to replace signed input.
		query := r.URL.Query()
		if query.Get("SAMLRequest") != "" {
			values.Set("SAMLRequest", query.Get("SAMLRequest"))
			values.Del("RelayState")
			if query.Has("RelayState") {
				values.Set("RelayState", query.Get("RelayState"))
			}
		}
	}
	baseURL := a.effectiveIDPBaseURL(r, state)
	responseContext, err := resolveSAMLResponseContext(r, values, app, baseURL)
	if err != nil {
		a.failFlow(w, app, "saml", "sso", http.StatusBadRequest, err.Error())
		return
	}
	if isTruthy(values.Get("deny")) {
		a.denySAML(w, r, app, baseURL, responseContext, values)
		return
	}
	needsChooser := !chooserSelectionProvided(app, values) &&
		(!post || values.Get("SAMLRequest") != "" || values.Get("login_hint") != "" || values.Get("RelayState") != "")
	if needsChooser {
		data := newChooserData("SAML sign-in", app, publicRequestURI(r), state.Users, loginHintFromValues(values), hiddenValues(values), "Create an active user before starting a SAML flow.")
		a.applyRememberedChooserUser(&data, r, state, app)
		renderChooser(w, data)
		return
	}
	a.completeSAMLSSO(w, r, state, app, baseURL, responseContext, values)
}

// completeSAMLSSO signs and posts back a SAML response for the selected user.
// It is shared by the chooser POST and the user_id GET shortcut.
func (a *webApp) completeSAMLSSO(w http.ResponseWriter, r *http.Request, state appState, app app, baseURL string, responseContext samlResponseContext, values url.Values) {
	user, ok := chooserUser(state.Users, app, values)
	if !ok || !user.Active || user.Deleted {
		a.failFlow(w, app, "saml", "sso", http.StatusBadRequest, "active user is required")
		return
	}
	dest, err := parseSAMLEncryptionCertificate(app.SAMLEncryptionCertPEM)
	if err != nil {
		a.failFlow(w, app, "saml", "sso", http.StatusBadRequest, err.Error())
		return
	}
	faults := a.flowFaults(app.Slug, values)
	posted, err := a.buildSignedSAMLResponse(state, baseURL, app, user, responseContext, dest, faults)
	if err != nil {
		a.failFlow(w, app, "saml", "sso", http.StatusInternalServerError, err.Error())
		return
	}
	encodedResponse := base64.StdEncoding.EncodeToString([]byte(posted.XML))
	a.rememberSAMLInspection(app, user, responseContext, posted, encodedResponse, faults, time.Now())
	ssoDetail := "Signed response posted to " + responseContext.ACSURL
	if faults.active() {
		ssoDetail = "Response posted to " + responseContext.ACSURL + " (faults injected)"
	}
	a.recordFlowEvent(app.Slug, "saml", "sso", "ok", userLabel(user), ssoDetail)
	rememberChooserUser(w, app.Slug, user.ID)
	renderPostBack(w, responseContext.ACSURL, map[string]string{
		"SAMLResponse": encodedResponse,
		"RelayState":   values.Get("RelayState"),
	})
}

// denySAML posts an AuthnFailed status response so an SP's failure handling can
// be tested from the chooser's Deny button.
func (a *webApp) denySAML(w http.ResponseWriter, r *http.Request, app app, baseURL string, responseContext samlResponseContext, values url.Values) {
	response, err := buildSAMLStatusResponse(baseURL, app, responseContext, faultOptions{SAMLStatus: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"})
	if err != nil {
		a.failFlow(w, app, "saml", "sso", http.StatusInternalServerError, err.Error())
		return
	}
	a.recordFlowEvent(app.Slug, "saml", "sso", "failed", "", "user denied the request (AuthnFailed)")
	renderPostBack(w, responseContext.ACSURL, map[string]string{
		"SAMLResponse": base64.StdEncoding.EncodeToString([]byte(response)),
		"RelayState":   values.Get("RelayState"),
	})
}

func resolveSAMLResponseContext(r *http.Request, values url.Values, app app, baseURL string) (samlResponseContext, error) {
	// Every response ends up posted to the configured ACS URL, so its
	// absence fails here - before the user is shown a chooser - rather
	// than after account selection.
	configuredACS := strings.TrimSpace(app.SAMLACSURL)
	if configuredACS == "" {
		return samlResponseContext{}, fmt.Errorf("SAML ACS URL must be configured on the app")
	}
	requestedACS := strings.TrimSpace(values.Get("acs_url"))
	if requestedACS != "" && requestedACS != configuredACS {
		return samlResponseContext{}, fmt.Errorf("SAML ACS URL does not match the configured app")
	}

	context := samlResponseContext{ACSURL: configuredACS}
	encodedRequest := strings.TrimSpace(values.Get("SAMLRequest"))
	if encodedRequest != "" {
		if app.SAMLVerifyRequests {
			if err := validateSAMLAuthnRequestSignature(r, encodedRequest, app.SAMLRequestCertPEM); err != nil {
				return samlResponseContext{}, err
			}
		}
		request, err := parseSAMLAuthnRequest(encodedRequest)
		if err != nil {
			return samlResponseContext{}, err
		}
		if request.ID == "" {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest ID is required")
		}
		if expectedIssuer := strings.TrimSpace(app.SAMLEntityID); expectedIssuer != "" && request.Issuer != expectedIssuer {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest issuer does not match the configured app")
		}
		expectedDestination := strings.TrimRight(baseURL, "/") + "/saml/" + app.Slug + "/sso"
		if request.Destination != "" && request.Destination != expectedDestination {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest destination does not match this IDP")
		}
		if request.ACSURL != "" && request.ACSURL != configuredACS {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest ACS URL does not match the configured app")
		}
		if request.ProtocolBinding != "" && request.ProtocolBinding != samlHTTPPostBinding {
			return samlResponseContext{}, fmt.Errorf("SAML AuthnRequest must request the HTTP-POST response binding")
		}
		context.InResponseTo = request.ID
	}
	return context, nil
}

func parseSAMLAuthnRequest(encodedRequest string) (samlAuthnRequest, error) {
	doc, err := parseSAMLRequestDocument(encodedRequest)
	if err != nil {
		return samlAuthnRequest{}, err
	}
	root := doc.Root()
	if elementLocalName(root) != "AuthnRequest" || root.NamespaceURI() != samlProtocolXMLNS {
		return samlAuthnRequest{}, fmt.Errorf("SAMLRequest must contain an AuthnRequest")
	}
	return samlAuthnRequest{
		ID:              strings.TrimSpace(root.SelectAttrValue("ID", "")),
		Issuer:          childElementTextByLocalName(root, "Issuer"),
		Destination:     strings.TrimSpace(root.SelectAttrValue("Destination", "")),
		ACSURL:          strings.TrimSpace(root.SelectAttrValue("AssertionConsumerServiceURL", "")),
		ProtocolBinding: strings.TrimSpace(root.SelectAttrValue("ProtocolBinding", "")),
	}, nil
}

func childElementTextByLocalName(parent *etree.Element, localName string) string {
	for _, child := range parent.ChildElements() {
		if elementLocalName(child) == localName {
			return strings.TrimSpace(child.Text())
		}
	}
	return ""
}

func parseSAMLRequestDocument(encodedRequest string) (*etree.Document, error) {
	encodedRequest = strings.TrimSpace(encodedRequest)
	if encodedRequest == "" {
		return nil, fmt.Errorf("SAMLRequest is required")
	}
	decoded, err := base64.StdEncoding.DecodeString(encodedRequest)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(encodedRequest, " ", "+"))
		if err != nil {
			return nil, fmt.Errorf("decode SAMLRequest: %w", err)
		}
	}
	requestXML, inflateErr := inflateRawDeflate(decoded)
	if errors.Is(inflateErr, errSAMLRequestTooLarge) {
		return nil, inflateErr
	}
	if inflateErr != nil || len(requestXML) == 0 {
		requestXML = decoded
	}
	if len(requestXML) > maxSAMLRequestBytes {
		return nil, errSAMLRequestTooLarge
	}

	doc := etree.NewDocument()
	if err := doc.ReadFromString(string(requestXML)); err != nil {
		return nil, fmt.Errorf("parse SAMLRequest XML: %w", err)
	}
	if doc.Root() == nil {
		return nil, fmt.Errorf("parse SAMLRequest XML: root element is required")
	}
	return doc, nil
}

func cloneURLValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

func inflateRawDeflate(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	out, readErr := io.ReadAll(io.LimitReader(reader, maxSAMLRequestBytes+1))
	closeErr := reader.Close()
	if readErr != nil {
		if closeErr != nil {
			return nil, fmt.Errorf("read raw deflate: %w (close: %v)", readErr, closeErr)
		}
		return nil, fmt.Errorf("read raw deflate: %w", readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close raw deflate reader: %w", closeErr)
	}
	if len(out) > maxSAMLRequestBytes {
		return nil, errSAMLRequestTooLarge
	}
	return out, nil
}

func firstElementTextByLocalName(el *etree.Element, localName string) string {
	if el == nil {
		return ""
	}
	if elementLocalName(el) == localName {
		if text := strings.TrimSpace(el.Text()); text != "" {
			return text
		}
	}
	for _, child := range el.ChildElements() {
		if text := firstElementTextByLocalName(child, localName); text != "" {
			return text
		}
	}
	return ""
}

func (a *webApp) buildSignedSAMLResponse(state appState, baseURL string, app app, user user, responseContext samlResponseContext, dest *x509.Certificate, faults faultOptions) (samlPostedResponse, error) {
	if faults.SAMLStatus != "" {
		responseXML, err := buildSAMLStatusResponse(baseURL, app, responseContext, faults)
		return samlPostedResponse{XML: responseXML}, err
	}
	response, err := buildSAMLResponse(state, baseURL, app, user, responseContext, faults)
	if err != nil {
		return samlPostedResponse{}, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromString(response); err != nil {
		return samlPostedResponse{}, fmt.Errorf("parse SAML response for signing: %w", err)
	}
	assertion := findElementByLocalName(doc.Root(), "Assertion")
	if assertion == nil {
		return samlPostedResponse{}, fmt.Errorf("SAML assertion not found")
	}
	ctx, err := dsig.NewSigningContext(a.signingKey, [][]byte{a.certDER})
	if err != nil {
		return samlPostedResponse{}, fmt.Errorf("create SAML signing context: %w", err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signature, err := ctx.ConstructSignature(assertion, true)
	if err != nil {
		return samlPostedResponse{}, fmt.Errorf("sign SAML assertion: %w", err)
	}
	signedAssertion := assertion.Copy()
	if err := placeSAMLAssertionSignature(signedAssertion, signature); err != nil {
		return samlPostedResponse{}, err
	}
	parent := assertion.Parent()
	if parent == nil {
		return samlPostedResponse{}, fmt.Errorf("SAML assertion has no parent")
	}
	parent.RemoveChild(assertion)
	parent.AddChild(signedAssertion)

	if faults.BreakSignature {
		corruptSAMLSignatureValue(signedAssertion)
	}

	var signedXML string
	if dest != nil {
		signedXML, err = serializeElement(signedAssertion)
		if err != nil {
			return samlPostedResponse{}, err
		}
		encrypted, err := encryptSAMLAssertion(signedAssertion, dest)
		if err != nil {
			return samlPostedResponse{}, fmt.Errorf("encrypt SAML assertion: %w", err)
		}
		parent.RemoveChild(signedAssertion)
		parent.AddChild(encrypted)
	}

	responseXML, err := doc.WriteToString()
	if err != nil {
		return samlPostedResponse{}, fmt.Errorf("serialize signed SAML response: %w", err)
	}
	return samlPostedResponse{XML: responseXML, SignedAssertion: signedXML}, nil
}

// buildSAMLStatusResponse produces an unsigned non-success SAML Response so an
// SP's failure handling can be tested.
func buildSAMLStatusResponse(baseURL string, app app, responseContext samlResponseContext, faults faultOptions) (string, error) {
	responseID, err := newID("saml-response")
	if err != nil {
		return "", fmt.Errorf("generate SAML response ID: %w", err)
	}
	now := time.Now().UTC().Add(faults.ClockSkew)
	issuer := baseURL + "/saml/" + app.Slug + "/metadata"
	inResponseTo := ""
	if responseContext.InResponseTo != "" {
		inResponseTo = ` InResponseTo="` + xmlEscape(responseContext.InResponseTo) + `"`
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s"%s>
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusCode Value="%s"/></samlp:StatusCode></samlp:Status>
</samlp:Response>`,
		xmlEscape(responseID), now.Format(time.RFC3339), xmlEscape(responseContext.ACSURL), inResponseTo,
		xmlEscape(issuer), xmlEscape(faults.SAMLStatus)), nil
}

func corruptSAMLSignatureValue(assertion *etree.Element) {
	value := findElementByLocalName(assertion, "SignatureValue")
	if value == nil || value.Text() == "" {
		return
	}
	text := value.Text()
	replacement := "A"
	if text[0] == 'A' {
		replacement = "B"
	}
	value.SetText(replacement + text[1:])
}

func childElementByLocalName(parent *etree.Element, localName string) *etree.Element {
	if parent == nil {
		return nil
	}
	for _, child := range parent.ChildElements() {
		if elementLocalName(child) == localName {
			return child
		}
	}
	return nil
}

func placeSAMLAssertionSignature(assertion *etree.Element, signature *etree.Element) error {
	issuerIndex := -1
	for index, child := range assertion.Child {
		element, ok := child.(*etree.Element)
		if !ok {
			continue
		}
		if elementLocalName(element) == "Issuer" {
			issuerIndex = index
		}
	}
	if issuerIndex < 0 {
		return fmt.Errorf("signed SAML assertion issuer not found")
	}
	assertion.InsertChildAt(issuerIndex+1, signature)
	return nil
}

func findElementByLocalName(el *etree.Element, localName string) *etree.Element {
	if el == nil {
		return nil
	}
	if elementLocalName(el) == localName {
		return el
	}
	for _, child := range el.ChildElements() {
		if found := findElementByLocalName(child, localName); found != nil {
			return found
		}
	}
	return nil
}

func elementLocalName(el *etree.Element) string {
	if el == nil {
		return ""
	}
	if index := strings.LastIndex(el.Tag, ":"); index >= 0 {
		return el.Tag[index+1:]
	}
	return el.Tag
}

func buildSAMLResponse(state appState, baseURL string, app app, user user, responseContext samlResponseContext, faults faultOptions) (string, error) {
	now := time.Now().UTC().Add(faults.ClockSkew)
	responseID, err := newID("saml-response")
	if err != nil {
		return "", fmt.Errorf("generate SAML response ID: %w", err)
	}
	assertionID, err := newID("saml-assertion")
	if err != nil {
		return "", fmt.Errorf("generate SAML assertion ID: %w", err)
	}
	issuer := baseURL + "/saml/" + app.Slug + "/metadata"
	audience := app.SAMLAudience
	if audience == "" {
		audience = app.SAMLEntityID
	}
	if audience == "" {
		audience = responseContext.ACSURL
	}
	attributeStatement := samlAttributeStatement(state, app, user)
	nameIDValue := samlNameIDValue(app, user)
	nameIDFormat := app.SAMLNameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = samlNameIDFormatForField(app.SAMLNameIDField)
	}
	responseInResponseTo := ""
	subjectInResponseTo := ""
	if responseContext.InResponseTo != "" {
		responseInResponseTo = ` InResponseTo="` + xmlEscape(responseContext.InResponseTo) + `"`
		subjectInResponseTo = ` InResponseTo="` + xmlEscape(responseContext.InResponseTo) + `"`
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s"%s>
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="%s">%s</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData%s NotOnOrAfter="%s" Recipient="%s"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s"><saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction></saml:Conditions>
    <saml:AuthnStatement AuthnInstant="%s"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>
    <saml:AttributeStatement>
      %s
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>`,
		xmlEscape(responseID), now.Format(time.RFC3339), xmlEscape(responseContext.ACSURL), responseInResponseTo, xmlEscape(issuer),
		xmlEscape(assertionID), now.Format(time.RFC3339), xmlEscape(issuer),
		xmlEscape(nameIDFormat), xmlEscape(nameIDValue), subjectInResponseTo, now.Add(5*time.Minute).Format(time.RFC3339), xmlEscape(responseContext.ACSURL),
		now.Add(-time.Minute).Format(time.RFC3339), now.Add(5*time.Minute).Format(time.RFC3339), xmlEscape(audience),
		now.Format(time.RFC3339), attributeStatement), nil
}

func samlAttributeStatement(state appState, app app, user user) string {
	mappings := samlAttributeMappingsForApp(app)
	var attributes strings.Builder
	writeSAMLAttribute(&attributes, mappings.Email, []string{user.Email})
	writeSAMLAttribute(&attributes, mappings.Username, []string{user.Username})
	writeSAMLAttribute(&attributes, mappings.GivenName, []string{user.GivenName})
	writeSAMLAttribute(&attributes, mappings.FamilyName, []string{user.FamilyName})
	if app.IncludeGroupsClaim {
		writeSAMLAttribute(&attributes, mappings.Groups, userGroups(state, user.ID))
	}
	return attributes.String()
}

func writeSAMLAttribute(attributes *strings.Builder, name string, values []string) {
	attributes.WriteString(`<saml:Attribute Name="`)
	attributes.WriteString(xmlEscape(name))
	attributes.WriteString(`">`)
	for _, value := range values {
		attributes.WriteString("<saml:AttributeValue>")
		attributes.WriteString(xmlEscape(value))
		attributes.WriteString("</saml:AttributeValue>")
	}
	attributes.WriteString("</saml:Attribute>")
}

func renderPostBack(w http.ResponseWriter, target string, values map[string]string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := postBackTemplate.Execute(w, struct {
		Target string
		Values map[string]string
	}{Target: target, Values: values}); err != nil {
		log.Printf("render SAML postback: %v", err)
	}
}

var postBackTemplate = template.Must(template.New("postback").Parse(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Continue</title></head>
<body>
  <form method="post" action="{{.Target}}">
    {{range $key, $value := .Values}}{{if $value}}<input type="hidden" name="{{$key}}" value="{{$value}}">{{end}}{{end}}
    <noscript><button type="submit">Continue</button></noscript>
  </form>
  <script>document.forms[0].submit()</script>
</body>
</html>`))

func xmlEscape(value string) string {
	var b strings.Builder
	if err := xml.EscapeText(&b, []byte(value)); err != nil {
		log.Printf("escape XML text: %v", err)
		return ""
	}
	return b.String()
}
