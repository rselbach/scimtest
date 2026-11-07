package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAPIAcceptanceUserAttributes(t *testing.T) {
	_, handler := newAcceptanceAPI(t)
	environment := acceptanceEnvironment(t, handler, `{"name":"Greendale Portal","slug":"greendale","oidc_enabled":true,"oidc_client_id":"greendale-client","oidc_client_secret":"study-group-secret","oidc_redirect_uris":["http://greendale.test/callback"],"saml_enabled":true,"saml_entity_id":"greendale-sp","saml_acs_url":"http://greendale.test/saml"}`)
	base := "/api/v1/environments/" + environment.ID
	rec := acceptanceRequest(t, handler, http.MethodPost, base+"/users", `{"given_name":"Craig","family_name":"Pelton","email":"dean@greendale.edu","department":"Office of the Dean"}`, http.StatusCreated)
	var dean user
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &dean))
	rec = acceptanceRequest(t, handler, http.MethodPost, base+"/users", fmt.Sprintf(`{
		"given_name":"Troy","family_name":"Barnes","email":"troy@greendale.edu",
		"employee_number":" GC-1001 ","cost_center":"3100","organization":"Greendale Community College",
		"division":"Facilities","department":"Air Conditioning Repair","manager_id":%q,
		"attributes":{"role":" student ","https://greendale.edu/claims/annex":"true"}
	}`, dean.ID), http.StatusCreated)
	var troy user
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &troy))
	userPath := base + "/users/" + troy.ID

	rec = acceptanceRequest(t, handler, http.MethodGet, userPath, "", http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &troy))
	require.Equal(t, "GC-1001", troy.EmployeeNumber)
	require.Equal(t, "3100", troy.CostCenter)
	require.Equal(t, "Greendale Community College", troy.Organization)
	require.Equal(t, "Facilities", troy.Division)
	require.Equal(t, "Air Conditioning Repair", troy.Department)
	require.Equal(t, dean.ID, troy.ManagerID)
	require.Equal(t, map[string]string{"role": "student", "https://greendale.edu/claims/annex": "true"}, troy.Attributes)
	require.Contains(t, rec.Body.String(), `"employee_number":"GC-1001"`)

	for name, body := range map[string]string{
		"self manager":       fmt.Sprintf(`{"manager_id":%q}`, troy.ID),
		"unknown manager":    `{"manager_id":"duncan"}`,
		"reserved attribute": `{"attributes":{"sub":"abed"}}`,
		"invalid name":       `{"attributes":{"study group":"yes"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			acceptanceRequest(t, handler, http.MethodPatch, userPath, body, http.StatusBadRequest)
		})
	}

	claims := acceptanceIDTokenClaims(t, handler, base, troy.ID)
	require.Equal(t, "GC-1001", claims["employeeNumber"])
	require.Equal(t, "Air Conditioning Repair", claims["department"])
	require.Equal(t, "Greendale Community College", claims["organization"])
	require.Equal(t, dean.ID, claims["manager"])
	require.Equal(t, "student", claims["role"])
	require.Equal(t, "true", claims["https://greendale.edu/claims/annex"])

	saml := acceptanceRequest(t, handler, http.MethodPost, base+"/saml/sign-in", fmt.Sprintf(`{"user_id":%q}`, troy.ID), http.StatusOK)
	var samlResponse struct {
		SAMLResponse string `json:"saml_response"`
	}
	require.NoError(t, json.Unmarshal(saml.Body.Bytes(), &samlResponse))
	assertion, err := base64.StdEncoding.DecodeString(samlResponse.SAMLResponse)
	require.NoError(t, err)
	for _, want := range []string{
		`<saml:Attribute Name="employeeNumber"><saml:AttributeValue>GC-1001</saml:AttributeValue></saml:Attribute>`,
		`<saml:Attribute Name="department"><saml:AttributeValue>Air Conditioning Repair</saml:AttributeValue></saml:Attribute>`,
		`<saml:Attribute Name="manager"><saml:AttributeValue>dean@greendale.edu</saml:AttributeValue></saml:Attribute>`,
		`<saml:Attribute Name="role"><saml:AttributeValue>student</saml:AttributeValue></saml:Attribute>`,
	} {
		require.Contains(t, string(assertion), want)
	}

	backup := acceptanceRequest(t, handler, http.MethodGet, base+"/backup", "", http.StatusOK).Body.String()
	rec = acceptanceRequest(t, handler, http.MethodPatch, userPath, `{"department":"Study Room F","manager_id":"","attributes":{}}`, http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &troy))
	require.Equal(t, "Study Room F", troy.Department)
	require.Empty(t, troy.ManagerID)
	require.Nil(t, troy.Attributes)
	acceptanceRequest(t, handler, http.MethodPost, base+"/restore", backup, http.StatusOK)
	rec = acceptanceRequest(t, handler, http.MethodGet, userPath, "", http.StatusOK)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &troy))
	require.Equal(t, "Air Conditioning Repair", troy.Department)
	require.Equal(t, dean.ID, troy.ManagerID)
	require.Equal(t, "student", troy.Attributes["role"])

	// Removing the manager leaves the reference behind, but it no longer
	// resolves and does not block unrelated edits.
	acceptanceRequest(t, handler, http.MethodDelete, base+"/users/"+dean.ID, "", http.StatusOK)
	acceptanceRequest(t, handler, http.MethodPatch, userPath, `{"given_name":"Troy Barnes"}`, http.StatusOK)
	claims = acceptanceIDTokenClaims(t, handler, base, troy.ID)
	require.NotContains(t, claims, "manager")
}

func acceptanceIDTokenClaims(t *testing.T, handler http.Handler, base string, userID string) map[string]any {
	t.Helper()
	authorize := acceptanceRequest(t, handler, http.MethodPost, base+"/oidc/authorize", fmt.Sprintf(`{"user_id":%q,"response_type":"code","client_id":"greendale-client","redirect_uri":"http://greendale.test/callback","scope":"openid profile email"}`, userID), http.StatusOK)
	var authorization struct {
		Code string `json:"code"`
	}
	require.NoError(t, json.Unmarshal(authorize.Body.Bytes(), &authorization))
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {authorization.Code},
		"client_id":     {"greendale-client"},
		"client_secret": {"study-group-secret"},
		"redirect_uri":  {"http://greendale.test/callback"},
	}
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/oidc/greendale/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokens := httptest.NewRecorder()
	handler.ServeHTTP(tokens, req)
	require.Equal(t, http.StatusOK, tokens.Code, tokens.Body.String())
	var tokenResponse struct {
		IDToken string `json:"id_token"`
	}
	require.NoError(t, json.Unmarshal(tokens.Body.Bytes(), &tokenResponse))
	parts := strings.Split(tokenResponse.IDToken, ".")
	require.Len(t, parts, 3)
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(claimsJSON, &claims))
	return claims
}

func TestUserClaimsIncludeUserAttributes(t *testing.T) {
	dean := user{ID: "dean", GivenName: "Craig", Email: "dean@greendale.edu", Username: "dean"}
	troy := user{
		ID: "troy", GivenName: "Troy", FamilyName: "Barnes", Email: "troy@greendale.edu", Username: "troy",
		EmployeeNumber: "GC-1001", Department: "Air Conditioning Repair", ManagerID: "dean",
		// "email" and "iss" can only arrive from an unvalidated backup.
		Attributes: map[string]string{"role": "student", "email": "abed@greendale.edu", "iss": "https://city-college.test"},
	}
	tests := map[string]struct {
		users   []user
		scope   string
		want    map[string]any
		wantNot []string
	}{
		"profile scope": {
			users: []user{troy, dean},
			scope: "openid profile email",
			want: map[string]any{
				"employeeNumber": "GC-1001", "department": "Air Conditioning Repair", "manager": "dean",
				"role": "student", "email": "troy@greendale.edu",
			},
			wantNot: []string{"costCenter", "organization", "division", "iss"},
		},
		"without profile scope": {
			users:   []user{troy, dean},
			scope:   "openid email",
			want:    map[string]any{"email": "troy@greendale.edu"},
			wantNot: []string{"employeeNumber", "department", "manager", "role"},
		},
		"deleted manager": {
			users:   []user{troy, {ID: "dean", Deleted: true}},
			scope:   "openid profile",
			want:    map[string]any{"department": "Air Conditioning Repair"},
			wantNot: []string{"manager"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			claims := userClaims(appState{Users: tc.users}, app{}, troy, tc.scope, "")
			for claim, want := range tc.want {
				r.Equal(want, claims[claim], claim)
			}
			for _, claim := range tc.wantNot {
				r.NotContains(claims, claim)
			}
		})
	}
	require.Contains(t, oidcClaimsSupported(app{}), "department")
}

func TestSAMLAttributeStatementIncludesUserAttributes(t *testing.T) {
	r := require.New(t)
	dean := user{ID: "dean", GivenName: "Craig", Email: "dean@greendale.edu", Username: "dpelton"}
	troy := user{
		ID: "troy", GivenName: "Troy", Email: "troy@greendale.edu", Username: "troy",
		Division: "Facilities", ManagerID: "dean",
		Attributes: map[string]string{"role": "student", "username": "abed"},
	}

	statement := samlAttributeStatement(appState{Users: []user{troy, dean}}, app{SAMLNameIDField: "username"}, troy)

	r.Contains(statement, `<saml:Attribute Name="division"><saml:AttributeValue>Facilities</saml:AttributeValue></saml:Attribute>`)
	r.Contains(statement, `<saml:Attribute Name="manager"><saml:AttributeValue>dpelton</saml:AttributeValue></saml:Attribute>`)
	r.Contains(statement, `<saml:Attribute Name="role"><saml:AttributeValue>student</saml:AttributeValue></saml:Attribute>`)
	r.Equal(1, strings.Count(statement, `Name="username"`), "custom attributes never repeat a mapped attribute")
	r.Contains(statement, `<saml:Attribute Name="username"><saml:AttributeValue>troy</saml:AttributeValue></saml:Attribute>`)
	r.NotContains(statement, "department")
}

func TestUserFormSavesUserAttributes(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Users: []user{{ID: "dean", GivenName: "Craig", FamilyName: "Pelton", Email: "dean@greendale.edu", Username: "dean", Active: true}}}))
	app := &webApp{}
	form := url.Values{
		"tab":             {"users"},
		"given_name":      {"Troy"},
		"email":           {"troy@greendale.edu"},
		"employee_number": {"GC-1001"},
		"cost_center":     {"3100"},
		"organization":    {"Greendale Community College"},
		"division":        {"Facilities"},
		"department":      {"Air Conditioning Repair"},
		"manager_id":      {"dean"},
		"attributes":      {"role=student\r\nannex = true\r\n"},
	}
	rec := postUserForm(app, form)
	r.Equal(http.StatusSeeOther, rec.Code)

	state, err := loadState()
	r.NoError(err)
	r.Len(state.Users, 2)
	troy := state.Users[1]
	r.Equal("GC-1001", troy.EmployeeNumber)
	r.Equal("3100", troy.CostCenter)
	r.Equal("Greendale Community College", troy.Organization)
	r.Equal("Facilities", troy.Division)
	r.Equal("Air Conditioning Repair", troy.Department)
	r.Equal("dean", troy.ManagerID)
	r.Equal(map[string]string{"role": "student", "annex": "true"}, troy.Attributes)

	get := httptest.NewRecorder()
	app.routes().ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/?tab=users&modal=user&id="+troy.ID, nil))
	r.Equal(http.StatusOK, get.Code)
	body := get.Body.String()
	r.Contains(body, `value="Air Conditioning Repair"`)
	r.Contains(body, `<option value="dean" selected>Craig Pelton (dean@greendale.edu)</option>`)
	r.NotContains(body, `<option value="`+troy.ID+`"`, "a user cannot manage themselves")
	r.Contains(body, ">annex=true\nrole=student</textarea>")

	form.Set("id", troy.ID)
	form.Set("department", "Law")
	form.Set("attributes", "")
	r.Equal(http.StatusSeeOther, postUserForm(app, form).Code)
	state, err = loadState()
	r.NoError(err)
	r.Equal("Law", state.Users[1].Department)
	r.Nil(state.Users[1].Attributes)
	r.Equal("Updated enterprise attributes", state.UserOperations[troy.ID][0].Summary)
}

func TestInvalidUserAttributesPreserveSubmittedValues(t *testing.T) {
	r := require.New(t)
	setTestStateFile(t)
	r.NoError(saveState(appState{Users: []user{{ID: "dean", GivenName: "Craig", Email: "dean@greendale.edu", Username: "dean", Active: true}}}))
	app := &webApp{}
	form := url.Values{
		"tab":        {"users"},
		"given_name": {"Troy"},
		"email":      {"troy@greendale.edu"},
		"department": {"Air Conditioning Repair"},
		"manager_id": {"dean"},
		"attributes": {"role=student\nannex"},
	}
	post := postUserForm(app, form)
	r.Equal(http.StatusSeeOther, post.Code)

	get := httptest.NewRequest(http.MethodGet, post.Header().Get("Location"), nil)
	for _, cookie := range post.Result().Cookies() {
		get.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, get)

	r.Equal(http.StatusOK, rec.Code)
	body := rec.Body.String()
	r.Contains(body, "custom attribute on line 2 must look like name=value")
	r.Contains(body, `value="Air Conditioning Repair"`)
	r.Contains(body, `<option value="dean" selected>`)
	r.Contains(body, ">role=student\nannex</textarea>")
	state, err := loadState()
	r.NoError(err)
	r.Len(state.Users, 1)
}

func postUserForm(app *webApp, form url.Values) *httptest.ResponseRecorder {
	post := httptest.NewRequest(http.MethodPost, "/users/save", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	app.routes().ServeHTTP(rec, post)
	return rec
}
