package web

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadableLastError(t *testing.T) {
	r := require.New(t)
	tests := map[string]struct {
		message string
		want    string
	}{
		"empty":                    {message: "", want: ""},
		"unrelated error":          {message: "connection refused", want: "connection refused"},
		"current rate limit":       {message: "SCIM server rate limit hit (429 Too Many Requests). Try again in 5 minutes.", want: "SCIM server rate limit hit (429 Too Many Requests). Try again in 5 minutes."},
		"legacy without retry":     {message: "PUT /Users/u1 returned 429 Too Many Requests: busy", want: "SCIM server rate limit hit (429 Too Many Requests). Try again later."},
		"legacy with seconds":      {message: "POST /Users returned 429 Too Many Requests: limit; retry after 120", want: "SCIM server rate limit hit (429 Too Many Requests). Try again in 2 minutes."},
		"legacy with duration":     {message: "POST /Users returned 429 Too Many Requests: limit; retry after 90s", want: "SCIM server rate limit hit (429 Too Many Requests). Try again in 2 minutes."},
		"legacy with readable":     {message: "POST /Users returned 429 Too Many Requests: limit; retry after in 5 minutes", want: "SCIM server rate limit hit (429 Too Many Requests). Try again in 5 minutes."},
		"legacy with now":          {message: "POST /Users returned 429 Too Many Requests: limit; retry after now", want: "SCIM server rate limit hit (429 Too Many Requests). Try again now."},
		"legacy with empty value":  {message: "POST /Users returned 429 Too Many Requests: limit; retry after .", want: "SCIM server rate limit hit (429 Too Many Requests). Try again later."},
		"legacy with other value":  {message: "POST /Users returned 429 Too Many Requests: limit; retry after later", want: "SCIM server rate limit hit (429 Too Many Requests). Try again after later."},
		"legacy stops at res body": {message: "GET /Users returned 429 Too Many Requests: limit; retry after 30: details", want: "SCIM server rate limit hit (429 Too Many Requests). Try again in 30 seconds."},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r.Equal(tc.want, readableLastError(tc.message))
		})
	}
}
