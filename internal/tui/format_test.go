package tui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrettyJSONHighlightsOutput(t *testing.T) {
	r := require.New(t)

	formatted := prettyJSON(`{"active":true,"count":2,"name":"Troy","meta":null,"items":["a"]}`)

	r.Contains(formatted, "\x1b[")
	r.Contains(formatted, `"active"`)
	r.Contains(formatted, `"name"`)
	r.Contains(formatted, `"Troy"`)
	r.Contains(formatted, "true")
	r.Contains(formatted, "null")
	r.Contains(formatted, "\n")
	r.True(strings.Index(formatted, `"active"`) < strings.Index(formatted, `"count"`))
}

func TestFormatSyncTracesIncludesRetryAfter(t *testing.T) {
	r := require.New(t)

	formatted := formatSyncTraces([]syncTraceEntry{{
		CreatedAt:          "2026-05-01T10:00:00Z",
		Method:             "PUT",
		Path:               "/Users/remote-1",
		Status:             "429 Too Many Requests",
		ResponseRetryAfter: "60",
	}})

	r.Contains(formatted, "Response Status: 429 Too Many Requests")
	r.Contains(formatted, "Retry-After: 60")
}
