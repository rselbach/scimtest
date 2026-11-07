package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUpdateControlRendersStates(t *testing.T) {
	tests := map[string]struct {
		view     updateView
		want     []string
		wantNone []string
	}{
		"hidden": {
			view:     updateView{},
			wantNone: []string{"update-pill"},
		},
		"ready": {
			view:     updateView{Show: true, State: "ready", Version: "2.6.0", CurrentVersion: "2.5.1", Highlights: []string{"Validity presets"}, HasNotes: true, Callout: "Restarting closes the tunnel.", InstallsOnQuit: true},
			want:     []string{"Update ready", "scimtest 2.6.0 is ready", "You have 2.5.1", "<li>Validity presets</li>", "Full release notes", `action="/desktop/update/restart"`, "It installs the next time you quit."},
			wantNone: []string{" disabled", "is-warning"},
		},
		"ready while syncing": {
			view: updateView{Show: true, State: "ready", Version: "2.6.0", Callout: "A sync is running.", Warning: true, SyncRunning: true},
			want: []string{`type="submit" disabled>Restart to Update`, "update-popover-callout is-warning"},
		},
		"failed": {
			view:     updateView{Show: true, State: "failed", Version: "2.6.0", Callout: "The download didn't match.", Warning: true, DownloadLabel: "Download from GitHub"},
			want:     []string{"Update failed", "scimtest 2.6.0 couldn't be installed", "Download from GitHub", "Try Again", `action="/desktop/update/check"`},
			wantNone: []string{"/desktop/update/restart"},
		},
		"Linux package": {
			view:     updateView{Show: true, State: "available", Version: "2.6.0", DownloadLabel: "Download .deb"},
			want:     []string{"Update available", "scimtest 2.6.0 is available", `value="download"`, "Download .deb"},
			wantNone: []string{"/desktop/update/restart", "Try Again"},
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			var out strings.Builder
			r.NoError(pageTemplate.ExecuteTemplate(&out, "update-control", tc.view))
			for _, want := range tc.want {
				r.Contains(out.String(), want)
			}
			for _, unwanted := range tc.wantNone {
				r.NotContains(out.String(), unwanted)
			}
		})
	}
}

func TestUpdateRoutesNeedAnUpdater(t *testing.T) {
	tests := map[string]http.HandlerFunc{
		"restart": (&webApp{}).handleUpdateRestart,
		"check":   (&webApp{}).handleUpdateCheck,
		"open":    (&webApp{}).handleUpdateOpen,
	}
	for name, handler := range tests {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler(rec, httptest.NewRequest(http.MethodPost, "/desktop/update/"+name, nil))
			require.New(t).Equal(http.StatusNotFound, rec.Code)
		})
	}
}

func TestReturnPath(t *testing.T) {
	tests := map[string]struct {
		referer string
		want    string
	}{
		"same host":         {referer: "http://example.com/traffic?view=all", want: "/traffic?view=all"},
		"other host":        {referer: "https://greendale.example/users", want: "/"},
		"no referer":        {want: "/"},
		"protocol-relative": {referer: "http://example.com//greendale.example/", want: "/"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/desktop/update/check", nil)
			if tc.referer != "" {
				request.Header.Set("Referer", tc.referer)
			}
			require.New(t).Equal(tc.want, returnPath(request))
		})
	}
}

func TestDownloadLabel(t *testing.T) {
	tests := map[string]struct {
		url  string
		want string
	}{
		"none": {},
		"deb":  {url: "https://github.com/a.deb", want: "Download .deb"},
		"rpm":  {url: "https://github.com/a.rpm", want: "Download .rpm"},
		"arch": {url: "https://github.com/a.pkg.tar.zst", want: "Download package"},
		"dmg":  {url: "https://github.com/a.dmg", want: "Download from GitHub"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			require.New(t).Equal(tc.want, downloadLabel(tc.url))
		})
	}
}
