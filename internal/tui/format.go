package tui

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"
)

const (
	ansiReset      = "\x1b[0m"
	ansiJSONKey    = "\x1b[38;5;12m"
	ansiJSONString = "\x1b[38;5;10m"
	ansiJSONNumber = "\x1b[38;5;14m"
	ansiJSONBool   = "\x1b[1;38;5;13m"
	ansiJSONNull   = "\x1b[38;5;8m"
	ansiJSONPunct  = "\x1b[38;5;241m"
)

func formatSyncTraces(traces []syncTraceEntry) string {
	if len(traces) == 0 {
		return "No sync requests were made."
	}

	lines := make([]string, 0, len(traces)*8)
	for i, trace := range traces {
		lines = append(lines, fmt.Sprintf("[%d] %s %s %s", i+1, trace.CreatedAt, trace.Method, trace.Path))
		if trace.Operation != "" || trace.Label != "" {
			lines = append(lines, fmt.Sprintf("Target: %s %s (%s)", trace.ResourceType, trace.Label, trace.Operation))
		}
		if trace.RequestBody != "" {
			lines = append(lines, "Request:")
			lines = append(lines, indentBlock(prettyJSON(trace.RequestBody), "  "))
		}
		if trace.Status != "" {
			lines = append(lines, "Response Status: "+trace.Status)
		}
		if trace.ResponseBody != "" {
			lines = append(lines, "Response Body:")
			lines = append(lines, indentBlock(prettyJSON(trace.ResponseBody), "  "))
		}
		if trace.Err != "" {
			lines = append(lines, "Error: "+trace.Err)
		}
		if i < len(traces)-1 {
			lines = append(lines, strings.Repeat("-", 48))
		}
	}

	return strings.Join(lines, "\n")
}

func prettyJSON(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}

	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return raw
	}

	canonical := normalizeJSON(decoded)
	formatted, err := json.MarshalIndent(canonical, "", "  ")
	if err != nil {
		return raw
	}

	return highlightJSON(string(formatted))
}

func highlightJSON(formatted string) string {
	var out strings.Builder
	for i := 0; i < len(formatted); {
		switch ch := formatted[i]; {
		case ch == '"':
			end := scanJSONString(formatted, i)
			token := formatted[i:end]
			next := nextNonSpaceByte(formatted, end)
			if next == ':' {
				out.WriteString(colorizeANSI(token, ansiJSONKey))
			} else {
				out.WriteString(colorizeANSI(token, ansiJSONString))
			}
			i = end
		case isJSONPunctuation(ch):
			out.WriteString(colorizeANSI(string(ch), ansiJSONPunct))
			i++
		case isJSONNumberStart(ch):
			end := scanJSONLiteral(formatted, i)
			out.WriteString(colorizeANSI(formatted[i:end], ansiJSONNumber))
			i = end
		case strings.HasPrefix(formatted[i:], "true") || strings.HasPrefix(formatted[i:], "false"):
			end := scanJSONLiteral(formatted, i)
			out.WriteString(colorizeANSI(formatted[i:end], ansiJSONBool))
			i = end
		case strings.HasPrefix(formatted[i:], "null"):
			end := scanJSONLiteral(formatted, i)
			out.WriteString(colorizeANSI(formatted[i:end], ansiJSONNull))
			i = end
		default:
			out.WriteByte(ch)
			i++
		}
	}

	return out.String()
}

func scanJSONString(s string, start int) int {
	escaped := false
	for i := start + 1; i < len(s); i++ {
		switch {
		case escaped:
			escaped = false
		case s[i] == '\\':
			escaped = true
		case s[i] == '"':
			return i + 1
		}
	}

	return len(s)
}

func scanJSONLiteral(s string, start int) int {
	for i := start; i < len(s); i++ {
		if unicode.IsSpace(rune(s[i])) || isJSONPunctuation(s[i]) {
			return i
		}
	}

	return len(s)
}

func nextNonSpaceByte(s string, start int) byte {
	for i := start; i < len(s); i++ {
		if !unicode.IsSpace(rune(s[i])) {
			return s[i]
		}
	}

	return 0
}

func isJSONNumberStart(ch byte) bool {
	return ch == '-' || (ch >= '0' && ch <= '9')
}

func isJSONPunctuation(ch byte) bool {
	switch ch {
	case '{', '}', '[', ']', ':', ',':
		return true
	default:
		return false
	}
}

func colorizeANSI(text string, code string) string {
	return code + text + ansiReset
}

func normalizeJSON(v any) any {
	switch value := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		normalized := make(map[string]any, len(value))
		for _, key := range keys {
			normalized[key] = normalizeJSON(value[key])
		}

		return normalized
	case []any:
		normalized := make([]any, 0, len(value))
		for _, item := range value {
			normalized = append(normalized, normalizeJSON(item))
		}

		return normalized
	default:
		return value
	}
}

func indentBlock(text string, prefix string) string {
	if text == "" {
		return prefix
	}

	parts := strings.Split(text, "\n")
	for i, part := range parts {
		parts[i] = prefix + part
	}

	return strings.Join(parts, "\n")
}
