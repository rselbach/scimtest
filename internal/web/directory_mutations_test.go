package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDirectoryDeletionTransports(t *testing.T) {
	for mode, tracked := range map[string]bool{"local": false, "enabled": true, "paused": true} {
		for resource, id := range map[string]string{"users": "troy", "groups": "study"} {
			for operation, ids := range map[string][]string{
				"delete": nil, "restore": nil, "bulk": {id, id},
				"invalid bulk": {id, "missing"}, "whitespace bulk": {" " + id + " "},
			} {
				t.Run(mode+"/"+resource+"/"+operation, func(t *testing.T) {
					r := require.New(t)
					var results []appState
					for _, transport := range []string{"html", "api"} {
						svc, handler := newAcceptanceAPI(t)
						state := appState{
							Config: config{SCIMDisabled: mode != "enabled"},
							Apps:   []app{{ID: "greendale", Name: "Greendale", Slug: "greendale", SCIMEnabled: mode == "enabled", SCIMBaseURL: "https://greendale.test/scim", SCIMBearerToken: "token"}},
							Users:  []user{{ID: "troy", GivenName: "Troy", Username: "troy", Email: "troy@greendale.edu", Active: true, LastError: "old failure"}, {ID: "abed", GivenName: "Abed", Username: "abed", Email: "abed@greendale.edu", Active: true, ManagerID: "troy"}},
							Groups: []group{{ID: "study", DisplayName: "Study Group", MemberIDs: []string{"troy", "abed"}, LastError: "old failure"}},
						}
						if mode != "enabled" {
							state.Apps[0].SCIMBaseURL = ""
							state.Apps[0].SCIMBearerToken = ""
						}
						if tracked {
							state.UserSync = map[string]map[string]resourceSyncState{"greendale": {"troy": {RemoteID: "remote-troy", LastError: "old failure"}, "abed": {RemoteID: "remote-abed"}}}
							state.GroupSync = map[string]map[string]resourceSyncState{"greendale": {"study": {RemoteID: "remote-study", LastError: "old failure"}}}
						}

						if operation == "restore" {
							if resource == "users" {
								state.Users[0].Deleted = true
							} else {
								state.Groups[0].Deleted = true
							}
							if tracked {
								if resource == "users" {
									row := state.UserSync["greendale"][id]
									row.Deleted = true
									state.UserSync["greendale"][id] = row
								} else {
									row := state.GroupSync["greendale"][id]
									row.Deleted = true
									state.GroupSync["greendale"][id] = row
								}
							}
						}
						r.NoError(saveState(state))
						before, err := loadStateForApp("greendale")
						r.NoError(err)
						if transport == "api" {
							path := "/api/v1/environments/greendale/" + resource + "/" + id
							method, body, want := http.MethodDelete, "", http.StatusOK
							switch operation {
							case "restore":
								method, path = http.MethodPost, path+"/restore"
								if !tracked {
									want = http.StatusConflict
								}
							case "bulk", "invalid bulk", "whitespace bulk":
								method, path = http.MethodPost, "/api/v1/environments/greendale/"+resource+"/bulk-delete"
								payload, err := json.Marshal(apiIDsRequest{IDs: ids})
								r.NoError(err)
								body = string(payload)
								if operation != "bulk" {
									want = http.StatusBadRequest
								}
							}
							rec := acceptanceRequest(t, handler, method, path, body, want)
							if operation == "bulk" {
								r.JSONEq(`{"deleted":1}`, rec.Body.String())
							}
						} else {
							path := "/" + resource + "/" + id + "/" + operation
							form := url.Values{"environment_id": {"greendale"}, "tab": {resource}}
							if ids != nil {
								path = "/" + resource + "/delete"
								key := "user_ids"
								if resource == "groups" {
									key = "group_ids"
								}
								form[key] = ids
							}
							req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080"+path, strings.NewReader(form.Encode()))
							req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
							rec := httptest.NewRecorder()
							svc.routes().ServeHTTP(rec, req)
							r.Equal(http.StatusSeeOther, rec.Code)
						}
						after, err := loadStateForApp("greendale")
						r.NoError(err)
						if operation == "invalid bulk" || (operation == "restore" && !tracked) || (operation == "whitespace bulk" && transport == "api") {
							r.Equal(before, after)
						} else if resource == "users" {
							if tracked {
								r.Equal(operation != "restore", after.Users[0].Deleted)
								r.True(after.UserSync["greendale"][id].Dirty)
								r.True(after.UserSync["greendale"]["abed"].Dirty)
								r.Empty(after.Users[0].LastError)
								r.Equal([]string{"troy", "abed"}, after.Groups[0].MemberIDs)
							} else {
								r.Len(after.Users, 1)
								r.Equal([]string{"abed"}, after.Groups[0].MemberIDs)
							}
						} else if tracked {
							r.Equal(operation != "restore", after.Groups[0].Deleted)
							r.True(after.GroupSync["greendale"][id].Dirty)
							r.Empty(after.Groups[0].LastError)
						} else {
							r.Empty(after.Groups)
						}

						logs := after.UserOperations[id]
						if resource == "groups" {
							logs = after.GroupOperations[id]
						}
						wantSummary := ""
						if tracked && operation != "invalid bulk" && (operation != "whitespace bulk" || transport != "api") {
							switch operation {
							case "restore":
								wantSummary = "Restored"
							case "delete":
								wantSummary = "Marked for deletion"
							default:
								wantSummary = "Marked for deletion in bulk"
							}
						}
						if wantSummary == "" {
							r.Empty(logs)
						} else {
							r.Len(logs, 1)
							r.Equal(wantSummary, logs[0].Summary)
						}
						for key, logs := range after.UserOperations {
							for i := range logs {
								logs[i].CreatedAt = ""
							}
							after.UserOperations[key] = logs
						}
						for key, logs := range after.GroupOperations {
							for i := range logs {
								logs[i].CreatedAt = ""
							}
							after.GroupOperations[key] = logs
						}
						results = append(results, after)
					}
					if operation != "whitespace bulk" {
						r.Equal(results[0], results[1], fmt.Sprintf("%s %s %s", mode, resource, operation))
					}
				})
			}
		}
	}
}
