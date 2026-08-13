package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseArgs(t *testing.T) {
	tests := map[string]struct {
		args    []string
		want    cliOptions
		wantErr string
	}{
		"no args":            {args: nil, want: cliOptions{}},
		"web command":        {args: []string{"web"}, want: cliOptions{command: "web"}},
		"debug":              {args: []string{"--debug"}, want: cliOptions{debug: true}},
		"debug secrets":      {args: []string{"--debug-secrets"}, want: cliOptions{debug: true, debugSecrets: true}},
		"no open":            {args: []string{"--no-open"}, want: cliOptions{noOpen: true}},
		"help":               {args: []string{"--debug", "--help"}, want: cliOptions{help: true}},
		"help subcommand":    {args: []string{"help"}, want: cliOptions{help: true}},
		"version flag":       {args: []string{"--version"}, want: cliOptions{version: true}},
		"version subcommand": {args: []string{"version"}, want: cliOptions{version: true}},
		"state file":         {args: []string{"--state-file", "/tmp/alt.db"}, want: cliOptions{stateFile: "/tmp/alt.db"}},
		"port separate":      {args: []string{"--port", "9000"}, want: cliOptions{port: "9000"}},
		"port equals":        {args: []string{"--port=9000"}, want: cliOptions{port: "9000"}},
		"port single dash":   {args: []string{"-port", "9000"}, want: cliOptions{port: "9000"}},
		"port with web":      {args: []string{"web", "--port", "9000"}, want: cliOptions{command: "web", port: "9000"}},
		"port missing value": {args: []string{"--port"}, wantErr: "flag needs an argument"},
		"port not a number":  {args: []string{"--port", "abc"}, wantErr: `invalid port "abc"`},
		"port out of range":  {args: []string{"--port", "70000"}, wantErr: `invalid port "70000"`},
		"port zero":          {args: []string{"--port=0"}, wantErr: `invalid port "0"`},
		"unknown argument":   {args: []string{"--bogus"}, wantErr: "flag provided but not defined"},
		"unknown subcommand": {args: []string{"serve"}, wantErr: `unknown subcommand "serve"`},
		"multiple commands":  {args: []string{"web", "web"}, wantErr: `unexpected argument "web"`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			got, err := parseArgs(tc.args)
			if tc.wantErr != "" {
				r.ErrorContains(err, tc.wantErr)
				return
			}
			r.NoError(err)
			r.Equal(tc.want, got)
		})
	}
}

func TestGoreleaserExcludesCLI(t *testing.T) {
	data, err := os.ReadFile("../../.goreleaser.yaml")
	require.NoError(t, err)
	require.NotContains(t, string(data), "main: ./cmd/scimtest\n")
	require.Contains(t, string(data), "main: ./cmd/scimtest-server\n")
}
