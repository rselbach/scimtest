package main

import (
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
		"help":               {args: []string{"--debug", "--help"}, want: cliOptions{help: true}},
		"port separate":      {args: []string{"--port", "9000"}, want: cliOptions{port: "9000"}},
		"port equals":        {args: []string{"--port=9000"}, want: cliOptions{port: "9000"}},
		"port with web":      {args: []string{"web", "--port", "9000"}, want: cliOptions{command: "web", port: "9000"}},
		"port missing value": {args: []string{"--port"}, wantErr: "--port requires a value"},
		"port not a number":  {args: []string{"--port", "abc"}, wantErr: `invalid port "abc"`},
		"port out of range":  {args: []string{"--port", "70000"}, wantErr: `invalid port "70000"`},
		"port zero":          {args: []string{"--port=0"}, wantErr: `invalid port "0"`},
		"unknown argument":   {args: []string{"--bogus"}, wantErr: `unknown argument "--bogus"`},
		"multiple commands":  {args: []string{"web", "web"}, wantErr: "multiple commands provided"},
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
