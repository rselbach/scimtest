package web

import (
	"encoding/json"
	"fmt"
	"strings"
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

func summarizeUserUpdate(existing user, givenName string, familyName string, email string, username string) string {
	switch {
	case existing.GivenName != givenName || existing.FamilyName != familyName:
		return "Updated name"
	case existing.Email != email:
		return "Updated email"
	case existing.Username != username:
		return "Updated username"
	default:
		return "Updated"
	}
}

func localDeleteSummary(deleted bool) string {
	if deleted {
		return "Marked for deletion"
	}

	return "Restored"
}

func summarizeActiveToggle(active bool) string {
	if active {
		return "Activated"
	}

	return "Deactivated"
}

func stringSlicesEqual(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}

	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}

	return true
}

func formatHistoryTimestamp(raw string) string {
	if raw == "" {
		return "-"
	}
	if len(raw) >= 19 {
		return strings.ReplaceAll(raw[:19], "T", " ")
	}

	return raw
}

func formatOperationDetail(entry operationLog) string {
	lines := []string{fmt.Sprintf("%s %s", entry.CreatedAt, entry.Summary)}
	if entry.Method != "" || entry.Path != "" {
		lines = append(lines, fmt.Sprintf("%s %s", entry.Method, entry.Path))
	}
	if entry.RequestBody != "" {
		lines = append(lines, "Request:")
		lines = append(lines, indentBlock(prettyJSON(entry.RequestBody), "  "))
	}
	if entry.Status != "" {
		lines = append(lines, "Response Status: "+entry.Status)
	}
	if entry.ResponseBody != "" {
		lines = append(lines, "Response Body:")
		lines = append(lines, indentBlock(prettyJSON(entry.ResponseBody), "  "))
	}
	if entry.Err != "" {
		lines = append(lines, "Error: "+entry.Err)
	}

	return strings.Join(lines, "\n")
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

func prettyJSON(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}

	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return raw
	}

	formatted, err := json.MarshalIndent(decoded, "", "  ")
	if err != nil {
		return raw
	}

	return string(formatted)
}
