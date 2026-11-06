package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type rustPolicyCase struct {
	Kind   string `json:"kind"`
	Routes string `json:"routes"`
	Root   string `json:"root"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Key    string `json:"key"`
	Value  string `json:"value"`
	Host   string `json:"host"`
	Origin string `json:"origin"`
	Site   string `json:"site"`
}

type rustStoreAction struct {
	Kind       string                   `json:"kind"`
	InstanceID string                   `json:"instance_id"`
	PublicKey  string                   `json:"public_key"`
	UserID     int64                    `json:"user_id"`
	Login      string                   `json:"login"`
	TunnelID   string                   `json:"tunnel_id"`
	Revoked    bool                     `json:"revoked"`
	Existing   bool                     `json:"existing"`
	Cutoff     time.Time                `json:"cutoff"`
	Retained   map[string]bool          `json:"retained"`
	Settings   StoredApplicationProfile `json:"settings"`
}

// TestRustHostedContractFixture exposes the Go contract to Rust integration tests.
// All reads and writes are confined to the caller's disposable fixture paths.
func TestRustHostedContractFixture(t *testing.T) {
	r := require.New(t)
	inputPath := os.Getenv("SCIMTEST_RUST_HOSTED_CONTRACT")
	if inputPath == "" {
		t.Skip("invoked by the Rust hosted-service contract tests")
	}
	var input struct {
		Kind      string                   `json:"kind"`
		Policies  []rustPolicyCase         `json:"policies"`
		Path      string                   `json:"path"`
		ProfileID string                   `json:"profile_id"`
		SessionID string                   `json:"session_id"`
		Settings  StoredApplicationProfile `json:"settings"`
		Actions   []rustStoreAction        `json:"actions"`
		Client    rustRelayClient          `json:"client"`
		Service   rustHostedService        `json:"service"`
	}
	data, err := os.ReadFile(inputPath)
	r.NoError(err)
	r.NoError(json.Unmarshal(data, &input))
	var output any
	switch input.Kind {
	case "service":
		output = runRustHostedService(t, input.Service)
	case "client":
		output = runRustRelayClient(t, input.Client)
	case "policy":
		results := make([]any, 0, len(input.Policies))
		for _, tc := range input.Policies {
			results = append(results, rustPolicyResult(t, tc))
		}
		output = results
	case "seed":
		store, err := OpenStore(input.Path)
		r.NoError(err)
		settings := input.Settings
		profile, err := store.CreateApplicationProfile(settings.Name, settings.PublicKey,
			settings.Routes, settings.RequestsPerMinute, settings.RequestBurst,
			settings.ConcurrentRequests)
		r.NoError(err)
		session, err := store.CreateSession(" RSELBACH ", true)
		r.NoError(err)
		output = map[string]any{"profile": profile, "session": session}
	case "store":
		store, err := OpenStore(input.Path)
		r.NoError(err)
		results := make([]any, 0, len(input.Actions))
		for _, action := range input.Actions {
			results = append(results, rustStoreResult(t, store, input.ProfileID, action))
		}
		profile, found := store.ApplicationProfile(input.ProfileID)
		session, sessionFound, err := store.Session(input.SessionID)
		r.NoError(err)
		output = map[string]any{
			"results": results, "profile": profile, "found": found,
			"session": session, "session_found": sessionFound,
			"profiles": store.ListApplicationProfiles(),
		}
	default:
		t.Fatalf("unknown Rust fixture kind %q", input.Kind)
	}
	encoded, err := json.Marshal(output)
	r.NoError(err)
	r.NoError(os.WriteFile(os.Getenv("SCIMTEST_RUST_HOSTED_RESULT"), encoded, 0o600))
}

func rustPolicyResult(t *testing.T, tc rustPolicyCase) any {
	t.Helper()
	r := require.New(t)
	switch tc.Kind {
	case "dashboard_mutation":
		s := &Server{cfg: Config{
			Domain: "public.greendale.test", DashboardDomain: "admin.greendale.test",
			PublicScheme: tc.Value,
		}}
		request := httptest.NewRequest(http.MethodPost, "/enroll", nil)
		request.Host = tc.Host
		request.Header.Set("Origin", tc.Origin)
		request.Header.Set("Sec-Fetch-Site", tc.Site)
		return s.allowedDashboardMutation(request)
	case "enrollment_ip":
		return enrollmentIPKey(tc.Value)
	case "enrollment_status":
		s := &Server{}
		request := httptest.NewRequest(tc.Method, "/api/enroll/status", nil)
		request.Header.Set("Authorization", tc.Value)
		response := httptest.NewRecorder()
		s.requirePost(s.handleEnrollmentStatus)(response, request)
		return map[string]any{
			"status": response.Code, "body": response.Body.String(),
			"content_type": response.Header().Get("Content-Type"),
			"cache":        response.Header().Get("Cache-Control"),
			"allow":        response.Header().Get("Allow"),
			"authenticate": response.Header().Get("WWW-Authenticate"),
		}
	case "routes":
		routes, err := parseApplicationRoutes(tc.Routes)
		return map[string]any{"routes": routes, "error": rustFixtureError(err)}
	case "request":
		routes, err := parseApplicationRoutes(tc.Routes)
		r.NoError(err)
		request, err := http.NewRequest(tc.Method, tc.Path, nil)
		r.NoError(err)
		return applicationRequestAllowed(routes, tc.Root, request)
	case "public_key":
		canonical, key, fingerprint, err := parseEd25519PublicKey(tc.Key)
		return map[string]any{"canonical": canonical, "bytes": key,
			"fingerprint": fingerprint, "error": rustFixtureError(err)}
	case "instance_key":
		key, id, err := parseInstancePublicKey(tc.Key)
		return map[string]any{"bytes": key, "id": id, "error": rustFixtureError(err)}
	case "ids":
		return map[string]bool{"application": applicationIDRE.MatchString(tc.Value),
			"instance": instanceIDRE.MatchString(tc.Value)}
	default:
		t.Fatalf("unknown Rust policy kind %q", tc.Kind)
		return nil
	}
}

func rustStoreResult(t *testing.T, store *Store, profileID string, action rustStoreAction) any {
	t.Helper()
	var err error
	var value any
	switch action.Kind {
	case "enroll":
		err = store.EnrollApplicationInstance(profileID, action.InstanceID,
			action.PublicKey, enrollmentActor{GitHubUserID: action.UserID,
				GitHubLogin: action.Login})
	case "remember":
		if action.Existing {
			err = store.RememberAuthenticatedApplicationTunnel(profileID,
				action.InstanceID, action.TunnelID)
			break
		}
		err = store.RememberApplicationTunnel(profileID, action.InstanceID, action.TunnelID)
	case "unreserve":
		value, err = store.UnreserveApplicationTunnel(profileID, action.InstanceID)
	case "revoke_user":
		value, err = store.RevokeApplicationInstanceForGitHubUser(profileID,
			action.InstanceID, action.UserID)
	case "set_revoked":
		value, err = store.SetApplicationInstanceRevoked(profileID, action.InstanceID, action.Revoked)
	case "prune":
		value, err = store.PruneIdleApplicationInstances(profileID, action.Cutoff, action.Retained)
	case "update":
		settings := action.Settings
		value, err = store.UpdateApplicationProfile(profileID, settings.Name,
			settings.PublicKey, settings.Routes, settings.RequestsPerMinute,
			settings.RequestBurst, settings.ConcurrentRequests)
	case "delete_profile":
		err = store.DeleteApplicationProfile(profileID)
	case "count":
		value = store.CountApplicationInstancesByGitHubUserID(profileID, action.UserID)
	case "reserved":
		value = store.TunnelIDReserved(action.TunnelID)
	case "tunnel":
		value = store.ApplicationTunnelID(profileID, action.InstanceID)
	default:
		t.Fatalf("unknown Rust store action %q", action.Kind)
	}
	return map[string]any{"value": value, "error": rustFixtureError(err)}
}

func rustFixtureError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
