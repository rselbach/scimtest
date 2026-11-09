package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/rselbach/scimtest/internal/update"
)

// updateCheckTimeout bounds a check the user starts, which includes
// downloading the update.
const updateCheckTimeout = 5 * time.Minute

var errSyncRunning = errors.New("a sync is running; restart when it finishes")

// updateView is the toolbar update control.
type updateView struct {
	Show           bool
	State          string
	Version        string
	CurrentVersion string
	Highlights     []string
	HasNotes       bool
	Callout        string
	Warning        bool
	DownloadLabel  string
	SyncRunning    bool
	InstallsOnQuit bool
}

func (a *webApp) updateView() updateView {
	if a.updater == nil {
		return updateView{}
	}
	snapshot := a.updater.Snapshot()
	view := updateView{
		Version:        snapshot.Version,
		CurrentVersion: snapshot.CurrentVersion,
		Highlights:     snapshot.Highlights,
		HasNotes:       snapshot.NotesURL != "",
		DownloadLabel:  downloadLabel(snapshot.DownloadURL),
	}
	switch snapshot.Status {
	case update.StatusReady:
		view.State = "ready"
		view.InstallsOnQuit = true
		view.SyncRunning = a.anySyncRunning()
		view.Callout = "Restarting closes the tunnel and any sign-in in progress for a few seconds. scimtest reopens when it's done."
		if view.SyncRunning {
			view.Warning = true
			view.Callout = "A sync is running. You can restart when it finishes."
		}
	case update.StatusAvailable:
		view.State = "available"
		view.Callout = "This copy of scimtest can't replace itself. Download the new version and replace the app in Applications."
		if runtime.GOOS == "linux" {
			view.Callout = "Install it with your package manager. Your environments and users are kept."
		}
	case update.StatusFailed:
		view.State = "failed"
		view.Warning = true
		view.Callout = snapshot.Failure
		view.Highlights = nil
	default:
		return updateView{}
	}
	view.Show = true
	return view
}

func downloadLabel(downloadURL string) string {
	switch {
	case downloadURL == "":
		return ""
	case strings.HasSuffix(downloadURL, ".deb"):
		return "Download .deb"
	case strings.HasSuffix(downloadURL, ".rpm"):
		return "Download .rpm"
	case strings.HasSuffix(downloadURL, ".pkg.tar.zst"):
		return "Download package"
	default:
		return "Download from GitHub"
	}
}

// restartGuard refuses a restart while a sync runs.
func (a *webApp) restartGuard() error {
	if a.anySyncRunning() {
		return errSyncRunning
	}
	return nil
}

func (a *webApp) handleUpdateRestart(w http.ResponseWriter, r *http.Request) {
	if a.updater == nil {
		http.NotFound(w, r)
		return
	}
	if err := a.updater.Restart(); err != nil {
		redirectWithFlash(w, r, returnPath(r), flashMessage{Kind: "error", Message: fmt.Sprintf("restart to update: %v", err)})
		return
	}
	http.Redirect(w, r, returnPath(r), http.StatusSeeOther)
}

func (a *webApp) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if a.updater == nil {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), updateCheckTimeout)
	defer cancel()
	if err := a.updater.CheckNow(ctx); err != nil {
		redirectWithFlash(w, r, returnPath(r), flashMessage{Kind: "error", Message: fmt.Sprintf("check for updates: %v", err)})
		return
	}
	http.Redirect(w, r, returnPath(r), http.StatusSeeOther)
}

// handleUpdateOpen opens the offered release's notes or download in the
// default browser. The URL comes from the verified feed, never the request.
func (a *webApp) handleUpdateOpen(w http.ResponseWriter, r *http.Request) {
	if a.updater == nil {
		http.NotFound(w, r)
		return
	}
	snapshot := a.updater.Snapshot()
	var target string
	switch r.FormValue("target") {
	case "notes":
		target = snapshot.NotesURL
	case "download":
		target = snapshot.DownloadURL
	}
	if target == "" {
		http.Error(w, "nothing to open", http.StatusNotFound)
		return
	}
	opener := a.browserOpen
	if opener == nil {
		opener = OpenBrowser
	}
	if err := opener(target); err != nil {
		redirectWithFlash(w, r, returnPath(r), flashMessage{Kind: "error", Message: fmt.Sprintf("open %s: %v", target, err)})
		return
	}
	http.Redirect(w, r, returnPath(r), http.StatusSeeOther)
}

// returnPath is the same-host page that submitted r, or the dashboard.
func returnPath(r *http.Request) string {
	referer, err := url.Parse(r.Referer())
	if err != nil || referer.Host != r.Host || !strings.HasPrefix(referer.Path, "/") || strings.HasPrefix(referer.Path, "//") {
		return "/"
	}
	return (&url.URL{Path: referer.Path, RawQuery: referer.RawQuery}).String()
}

// updatedFlash announces the first dashboard view after an update.
func (a *webApp) updatedFlash() flashMessage {
	if a.updater == nil {
		return flashMessage{}
	}
	version := a.updater.TakeUpdatedTo()
	if version == "" {
		return flashMessage{}
	}
	return flashMessage{Kind: "success", Message: fmt.Sprintf("Updated to scimtest %s.", version)}
}
