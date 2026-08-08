package web

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

type chooserData struct {
	Title           string
	AppName         string
	Action          string
	Users           []user
	SelectedUserID  string
	Hidden          map[string][]string
	NoUsersHint     string
	IdentifierOnly  bool
	LoginIdentifier string
}

func newChooserData(title string, app app, action string, users []user, loginHint string, hidden map[string][]string, noUsersHint string) chooserData {
	data := chooserData{
		Title: title, AppName: app.Name, Action: action, Hidden: hidden,
		NoUsersHint: noUsersHint,
	}
	if normalizeChooserMode(app.ChooserMode) == chooserModeIdentifier {
		data.IdentifierOnly = true
		data.LoginIdentifier = loginHint
		return data
	}
	data.Users = activeUsersWithLoginHint(users, loginHint)
	data.SelectedUserID = selectedLoginHintUserID(users, loginHint)
	return data
}

func chooserCookieName(slug string) string { return "scimtest_chooser_" + slug }

// rememberChooserUser records the last user signed in for an environment so the
// chooser can pre-select them on the next flow.
func rememberChooserUser(w http.ResponseWriter, slug, userID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     chooserCookieName(slug),
		Value:    userID,
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// applyRememberedChooserUser pre-selects the last-used user when nothing else
// already selected one.
func (a *webApp) applyRememberedChooserUser(data *chooserData, r *http.Request, state appState, app app) {
	if data.SelectedUserID != "" || data.IdentifierOnly {
		return
	}
	cookie, err := r.Cookie(chooserCookieName(app.Slug))
	if err != nil {
		return
	}
	if user, ok := userByID(state.Users, cookie.Value); ok && user.Active && !user.Deleted {
		data.SelectedUserID = user.ID
	}
}

func chooserSelectionProvided(app app, values url.Values) bool {
	if normalizeChooserMode(app.ChooserMode) == chooserModeIdentifier {
		return strings.TrimSpace(values.Get("login_identifier")) != ""
	}
	return strings.TrimSpace(values.Get("user_id")) != ""
}

func chooserUser(users []user, app app, values url.Values) (user, bool) {
	userID := values.Get("user_id")
	if normalizeChooserMode(app.ChooserMode) == chooserModeIdentifier {
		userID = selectedLoginHintUserID(users, values.Get("login_identifier"))
	}
	return userByID(users, userID)
}

func activeUsers(users []user) []user {
	var active []user
	for _, user := range users {
		if user.Active && !user.Deleted {
			active = append(active, user)
		}
	}
	sort.Slice(active, func(i, j int) bool {
		return userLabel(active[i]) < userLabel(active[j])
	})
	return active
}

func activeUsersWithLoginHint(users []user, loginHint string) []user {
	active := activeUsers(users)
	selectedID := selectedLoginHintUserID(active, loginHint)
	if selectedID == "" {
		return active
	}
	for i, user := range active {
		if user.ID != selectedID {
			continue
		}
		selected := active[i]
		copy(active[1:i+1], active[0:i])
		active[0] = selected
		return active
	}
	return active
}

func selectedLoginHintUserID(users []user, loginHint string) string {
	loginHint = strings.TrimSpace(loginHint)
	if loginHint == "" {
		return ""
	}

	selectedID := ""
	for _, user := range users {
		if !user.Active || user.Deleted {
			continue
		}
		if !loginHintMatchesUser(loginHint, user) {
			continue
		}
		if selectedID != "" && selectedID != user.ID {
			return ""
		}
		selectedID = user.ID
	}
	return selectedID
}

func loginHintMatchesUser(loginHint string, user user) bool {
	username := strings.TrimSpace(user.Username)
	email := strings.TrimSpace(user.Email)
	return (username != "" && strings.EqualFold(loginHint, username)) ||
		(email != "" && strings.EqualFold(loginHint, email))
}

func loginHintFromValues(values url.Values) string {
	if loginHint, _ := firstQueryValue(values, "login_hint", "LoginHint", "loginHint"); loginHint != "" {
		return loginHint
	}
	if loginHint := loginHintFromSAMLRequest(values.Get("SAMLRequest")); loginHint != "" {
		return loginHint
	}
	if loginHint := loginHintFromRelayState(values.Get("RelayState")); loginHint != "" {
		return loginHint
	}
	return ""
}

func firstQueryValue(values url.Values, keys ...string) (string, string) {
	for _, key := range keys {
		if value := strings.TrimSpace(values.Get(key)); value != "" {
			return value, key
		}
	}
	return "", ""
}

func loginHintFromSAMLRequest(encodedRequest string) string {
	doc, err := parseSAMLRequestDocument(encodedRequest)
	if err != nil {
		return ""
	}
	for _, localName := range []string{"NameID", "LoginHint", "login_hint"} {
		if text := firstElementTextByLocalName(doc.Root(), localName); text != "" {
			return text
		}
	}
	return ""
}

func loginHintFromRelayState(relayState string) string {
	relayState = strings.TrimSpace(relayState)
	if relayState == "" {
		return ""
	}
	candidates := []string{relayState}
	if decoded, err := url.QueryUnescape(relayState); err == nil && decoded != relayState {
		candidates = append(candidates, decoded)
	}
	for _, candidate := range candidates {
		if loginHint := loginHintFromURLOrQuery(candidate); loginHint != "" {
			return loginHint
		}
	}
	return ""
}

func loginHintFromURLOrQuery(value string) string {
	if parsed, err := url.Parse(value); err == nil && parsed.RawQuery != "" {
		if loginHint, _ := firstQueryValue(parsed.Query(), "login_hint", "LoginHint", "loginHint"); loginHint != "" {
			return loginHint
		}
	}
	if parsedValues, err := url.ParseQuery(value); err == nil {
		loginHint, _ := firstQueryValue(parsedValues, "login_hint", "LoginHint", "loginHint")
		return loginHint
	}
	return ""
}

func hiddenValues(values url.Values) map[string][]string {
	out := make(map[string][]string)
	for key, value := range values {
		if key == "user_id" || key == "login_identifier" {
			continue
		}
		out[key] = value
	}
	return out
}

func renderChooser(w http.ResponseWriter, data chooserData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := chooserTemplate.Execute(w, data); err != nil {
		log.Printf("render login chooser: %v", err)
	}
}

var chooserTemplate = template.Must(template.New("chooser").Funcs(template.FuncMap{
	"userDisplayName": userLabel,
}).Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{.Title}} · {{.AppName}}</title>
  <style>
    :root { --bg:#f4f5f7; --card:#fff; --line:#d1d5db; --text:#1f2328; --muted:#6b7280; --accent:#1563ff; --accent-strong:#1051d8; --radius:8px; }
    * { box-sizing: border-box; }
    body { margin:0; min-height:100vh; min-height:100dvh; display:grid; place-items:center; padding:16px; background:var(--bg); color:var(--text); font:13.5px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif; }
    main { width:min(460px, 100%); max-height:calc(100vh - 32px); max-height:calc(100dvh - 32px); display:grid; grid-template-rows:auto minmax(0, 1fr); background:var(--card); border:1px solid var(--line); border-radius:var(--radius); box-shadow:0 20px 50px rgba(15,23,42,.16); overflow:hidden; }
    header { padding:18px 20px; border-bottom:1px solid #e5e7eb; }
    h1 { margin:0; font-size:18px; line-height:1.2; }
    p { margin:4px 0 0; color:var(--muted); }
    form { min-height:0; padding:18px 20px 20px; display:grid; grid-template-rows:auto minmax(0, 1fr) auto; gap:12px; overflow:hidden; }
    .search-row { display:grid; grid-template-columns:minmax(0, 1fr) auto; align-items:center; gap:10px; }
    .search-row input { width:100%; height:36px; padding:0 11px; border:1px solid var(--line); border-radius:6px; color:var(--text); font:inherit; }
    .search-row input:focus { outline:none; border-color:var(--accent); box-shadow:0 0 0 3px rgba(21,99,255,.15); }
    .match-count { color:var(--muted); font-size:12px; white-space:nowrap; }
    .user-list { min-height:0; max-height:520px; overflow-y:auto; display:grid; align-content:start; gap:8px; padding-right:4px; scrollbar-gutter:stable; }
    .user-option { display:flex; align-items:center; gap:10px; padding:10px 12px; border:1px solid #e5e7eb; border-radius:6px; cursor:pointer; }
    .user-option:hover { border-color:var(--line); background:#f9fafb; }
    .user-option:has(input:checked) { border-color:var(--accent); background:#f5f8ff; }
    strong { display:block; font-weight:600; }
    .user-meta { color:var(--muted); font-size:12.5px; }
    .no-matches { padding:24px 12px; text-align:center; color:var(--muted); }
    [hidden] { display:none !important; }
    button { height:34px; border:1px solid var(--accent); background:var(--accent); color:#fff; border-radius:6px; font-weight:600; cursor:pointer; }
    button:hover { background:var(--accent-strong); border-color:var(--accent-strong); }
    button:disabled { opacity:.5; cursor:not-allowed; }
    .chooser-actions { display:grid; grid-template-columns:auto 1fr; gap:10px; }
    button.secondary { background:#fff; color:var(--muted); border-color:var(--line); }
    button.secondary:hover { background:#f9fafb; border-color:var(--muted); color:var(--text); }
    .empty { color:var(--muted); padding:18px 20px 20px; }
	.identifier-form { grid-template-rows:auto auto; }
	.identifier-field { display:grid; gap:6px; color:var(--muted); }
	.identifier-field input { width:100%; height:38px; padding:0 11px; border:1px solid var(--line); border-radius:6px; color:var(--text); font:inherit; }
  </style>
</head>
<body>
  <main>
    <header>
      <h1>{{.Title}}</h1>
      <p>{{.AppName}}</p>
    </header>
    {{if .IdentifierOnly}}
	<form class="identifier-form" method="post" action="{{.Action}}">
	  {{range $key, $values := .Hidden}}{{range $values}}<input type="hidden" name="{{$key}}" value="{{.}}">{{end}}{{end}}
	  <label class="identifier-field">Username or email
		<input name="login_identifier" value="{{.LoginIdentifier}}" autocomplete="username" required autofocus>
	  </label>
	  <div class="chooser-actions">
	    <button type="submit" formnovalidate name="deny" value="1" class="secondary">Deny</button>
	    <button type="submit">Continue</button>
	  </div>
	</form>
	{{else if .Users}}
    <form method="post" action="{{.Action}}">
      {{range $key, $values := .Hidden}}{{range $values}}<input type="hidden" name="{{$key}}" value="{{.}}">{{end}}{{end}}
      <div class="search-row">
        <input type="search" placeholder="Search name, username, or email" aria-label="Search users" aria-controls="user-list" autocomplete="off" autofocus data-user-search>
        <span class="match-count" aria-live="polite" data-match-count></span>
      </div>
      <div class="user-list" id="user-list" role="radiogroup" aria-label="Users" data-user-list>
        {{range .Users}}
        <label class="user-option" data-user-option data-search="{{userDisplayName .}} {{.Username}} {{.Email}}">
          <input type="radio" name="user_id" value="{{.ID}}" required {{if eq .ID $.SelectedUserID}}checked{{end}}>
          <div><strong>{{userDisplayName .}}</strong><span class="user-meta">{{.Email}}</span></div>
        </label>
        {{end}}
        <div class="no-matches" hidden data-no-matches>No users match your search.</div>
      </div>
      <div class="chooser-actions">
        <button type="submit" formnovalidate name="deny" value="1" class="secondary" data-deny>Deny</button>
        <button type="submit" data-continue>Continue</button>
      </div>
    </form>
    {{else}}
    <div class="empty">{{.NoUsersHint}}</div>
    {{end}}
  </main>
  {{if .Users}}
  <script>
    const search = document.querySelector('[data-user-search]');
    const options = Array.from(document.querySelectorAll('[data-user-option]'));
    const matchCount = document.querySelector('[data-match-count]');
    const noMatches = document.querySelector('[data-no-matches]');
    const continueButton = document.querySelector('[data-continue]');
    function filterUsers() {
      const terms = search.value.toLocaleLowerCase().trim().split(/\s+/).filter(Boolean);
      let visible = 0;
      for (const option of options) {
        const value = option.dataset.search.toLocaleLowerCase();
        const matches = terms.every(function (term) { return value.includes(term); });
        option.hidden = !matches;
        const radio = option.querySelector('input[type="radio"]');
        if (radio) radio.disabled = !matches;
        if (matches) {
          visible++;
        } else {
          if (radio) radio.checked = false;
        }
      }
      matchCount.textContent = String(visible) + (visible === 1 ? ' user' : ' users');
      noMatches.hidden = visible !== 0;
      continueButton.disabled = visible === 0;
    }
    search.addEventListener('input', filterUsers);
    filterUsers();
  </script>
  {{end}}
</body>
</html>`))
