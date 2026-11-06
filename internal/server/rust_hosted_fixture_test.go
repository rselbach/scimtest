package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type rustHostedService struct {
	Addr                    string `json:"addr"`
	Domain                  string `json:"domain"`
	DashboardDomain         string `json:"dashboard_domain"`
	Scheme                  string `json:"scheme"`
	DataPath                string `json:"data_path"`
	GitHubTokenURL          string `json:"github_token_url"`
	GitHubUserURL           string `json:"github_user_url"`
	GitHubAuthorizeURL      string `json:"github_authorize_url"`
	MaxInstallationsPerUser int    `json:"max_installations_per_user"`
}

func runRustHostedService(t *testing.T, input rustHostedService) any {
	t.Helper()
	r := require.New(t)
	s, err := New(Config{
		Addr: input.Addr, Domain: input.Domain,
		DashboardDomain: input.DashboardDomain, PublicScheme: input.Scheme,
		DataPath: input.DataPath, GitHubClientID: "greendale-client",
		GitHubClientSecret: "greendale-secret", ShutdownTimeout: 3 * time.Second,
		MaxInstallationsPerUser: input.MaxInstallationsPerUser,
	})
	r.NoError(err)
	s.github.TokenURL = input.GitHubTokenURL
	s.github.UserURL = input.GitHubUserURL
	s.github.AuthorizeBaseURL = input.GitHubAuthorizeURL
	r.NoError(s.Run())
	return map[string]bool{"stopped": true}
}
