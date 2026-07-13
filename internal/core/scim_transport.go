package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func isRateLimitError(err error) bool {
	var rateLimitErr *RateLimitError
	return errors.As(err, &rateLimitErr)
}

func (c *SCIMClient) createUser(u User) (string, bool, error) {
	if c.filter {
		remoteID, found, err := c.findUserByExternalID(u)
		if err != nil {
			return "", false, err
		}
		if found {
			u.RemoteID = remoteID
			if err := c.replaceUser(u); err != nil {
				return "", false, err
			}
			return remoteID, true, nil
		}
	}

	resource := newSCIMUserResource(u)

	var response SCIMUserResource
	if err := c.doJSON(http.MethodPost, "/Users", resource, &response, traceTargetForUser(u, "create")); err != nil {
		return "", false, err
	}

	if strings.TrimSpace(response.ID) == "" {
		err := fmt.Errorf("SCIM create response missing id")
		c.setLastTraceError(err)
		return "", false, err
	}

	return response.ID, false, nil
}

func (c *SCIMClient) findUserByExternalID(u User) (string, bool, error) {
	path := externalIDFilterPath("/Users", u.ID)
	var response SCIMListResponse[SCIMUserResource]
	if err := c.doJSON(http.MethodGet, path, nil, &response, TraceTarget{
		ResourceType: "user",
		ResourceID:   u.ID,
		Label:        UserLabel(u),
		Operation:    "adopt",
	}); err != nil {
		return "", false, err
	}
	if err := validateExternalIDMatches(response.TotalResults, len(response.Resources), u.ID); err != nil {
		c.setLastTraceError(err)
		return "", false, err
	}
	if len(response.Resources) == 0 {
		return "", false, nil
	}
	resource := response.Resources[0]
	if resource.ExternalID != u.ID {
		err := fmt.Errorf("SCIM user filter for externalId %q returned externalId %q", u.ID, resource.ExternalID)
		c.setLastTraceError(err)
		return "", false, err
	}
	if strings.TrimSpace(resource.ID) == "" {
		err := fmt.Errorf("SCIM user matched by externalId %q is missing id", u.ID)
		c.setLastTraceError(err)
		return "", false, err
	}
	return resource.ID, true, nil
}

func (c *SCIMClient) listUsers() ([]SCIMUserResource, error) {
	resources := make([]SCIMUserResource, 0, 32)
	startIndex := 1
	count := 100

	for {
		path := fmt.Sprintf("/Users?startIndex=%d&count=%d", startIndex, count)
		var response SCIMListResponse[SCIMUserResource]
		if err := c.doJSON(http.MethodGet, path, nil, &response, TraceTarget{
			ResourceType: "user",
			Label:        "SCIM /Users",
			Operation:    "import",
		}); err != nil {
			return nil, err
		}

		resources = append(resources, response.Resources...)
		if len(response.Resources) == 0 {
			return resources, nil
		}

		nextIndex := startIndex + len(response.Resources)
		if response.StartIndex > 0 {
			nextIndex = response.StartIndex + len(response.Resources)
		}
		if response.TotalResults > 0 && nextIndex > response.TotalResults {
			return resources, nil
		}
		if response.ItemsPerPage > 0 && len(response.Resources) < response.ItemsPerPage {
			return resources, nil
		}
		if response.TotalResults == 0 && response.ItemsPerPage == 0 && len(response.Resources) < count {
			return resources, nil
		}
		if nextIndex <= startIndex {
			return nil, fmt.Errorf("SCIM /Users pagination did not advance from startIndex %d", startIndex)
		}

		startIndex = nextIndex
	}
}

func (c *SCIMClient) listGroups() ([]SCIMGroupResource, error) {
	resources := make([]SCIMGroupResource, 0, 32)
	startIndex := 1
	count := 100

	for {
		path := fmt.Sprintf("/Groups?startIndex=%d&count=%d", startIndex, count)
		var response SCIMListResponse[SCIMGroupResource]
		if err := c.doJSON(http.MethodGet, path, nil, &response, TraceTarget{
			ResourceType: "group",
			Label:        "SCIM /Groups",
			Operation:    "import",
		}); err != nil {
			return nil, err
		}

		resources = append(resources, response.Resources...)
		if len(response.Resources) == 0 {
			return resources, nil
		}

		nextIndex := startIndex + len(response.Resources)
		if response.StartIndex > 0 {
			nextIndex = response.StartIndex + len(response.Resources)
		}
		if response.TotalResults > 0 && nextIndex > response.TotalResults {
			return resources, nil
		}
		if response.ItemsPerPage > 0 && len(response.Resources) < response.ItemsPerPage {
			return resources, nil
		}
		if response.TotalResults == 0 && response.ItemsPerPage == 0 && len(response.Resources) < count {
			return resources, nil
		}
		if nextIndex <= startIndex {
			return nil, fmt.Errorf("SCIM /Groups pagination did not advance from startIndex %d", startIndex)
		}

		startIndex = nextIndex
	}
}

func (c *SCIMClient) getUser(u User) (SCIMUserResource, error) {
	var resource SCIMUserResource
	err := c.doJSON(http.MethodGet, "/Users/"+url.PathEscape(u.RemoteID), nil, &resource, traceTargetForUser(u, "check"))
	return resource, err
}

func (c *SCIMClient) getGroup(g Group) (SCIMGroupResource, error) {
	var resource SCIMGroupResource
	err := c.doJSON(http.MethodGet, "/Groups/"+url.PathEscape(g.RemoteID), nil, &resource, traceTargetForGroup(g, "check"))
	return resource, err
}

func (c *SCIMClient) replaceUser(u User) error {
	resource := newSCIMUserResource(u)
	resource.ID = u.RemoteID

	return c.doJSON(http.MethodPut, "/Users/"+url.PathEscape(u.RemoteID), resource, nil, traceTargetForUser(u, "update"))
}

func newSCIMUserResource(u User) SCIMUserResource {
	active := u.Active
	formattedName := FullName(u)
	resource := SCIMUserResource{
		Schemas:     []string{scimUserSchema},
		ExternalID:  u.ID,
		UserName:    strings.TrimSpace(u.Username),
		DisplayName: formattedName,
		Active:      &active,
		Emails: []SCIMEmail{{
			Value:   strings.TrimSpace(u.Email),
			Type:    "work",
			Primary: true,
		}},
	}

	resource.Name = &SCIMName{
		GivenName:  strings.TrimSpace(u.GivenName),
		FamilyName: strings.TrimSpace(u.FamilyName),
		Formatted:  formattedName,
	}

	return resource
}

func (c *SCIMClient) deleteUser(u User, operation string) error {
	return c.doJSON(http.MethodDelete, "/Users/"+url.PathEscape(u.RemoteID), nil, nil, traceTargetForUser(u, operation))
}

func (c *SCIMClient) createGroup(g Group, users []User) (string, bool, error) {
	if c.filter {
		remoteID, found, err := c.findGroupByExternalID(g)
		if err != nil {
			return "", false, err
		}
		if found {
			g.RemoteID = remoteID
			if err := c.replaceGroup(g, users); err != nil {
				return "", false, err
			}
			return remoteID, true, nil
		}
	}

	resource, err := newSCIMGroupResource(g, users)
	if err != nil {
		return "", false, err
	}

	var response SCIMGroupResource
	if err := c.doJSON(http.MethodPost, "/Groups", resource, &response, traceTargetForGroup(g, "create")); err != nil {
		return "", false, err
	}

	if strings.TrimSpace(response.ID) == "" {
		err := fmt.Errorf("SCIM create group response missing id")
		c.setLastTraceError(err)
		return "", false, err
	}

	return response.ID, false, nil
}

func (c *SCIMClient) findGroupByExternalID(g Group) (string, bool, error) {
	path := externalIDFilterPath("/Groups", g.ID)
	var response SCIMListResponse[SCIMGroupResource]
	if err := c.doJSON(http.MethodGet, path, nil, &response, TraceTarget{
		ResourceType: "group",
		ResourceID:   g.ID,
		Label:        g.DisplayName,
		Operation:    "adopt",
	}); err != nil {
		return "", false, err
	}
	if err := validateExternalIDMatches(response.TotalResults, len(response.Resources), g.ID); err != nil {
		c.setLastTraceError(err)
		return "", false, err
	}
	if len(response.Resources) == 0 {
		return "", false, nil
	}
	resource := response.Resources[0]
	if resource.ExternalID != g.ID {
		err := fmt.Errorf("SCIM group filter for externalId %q returned externalId %q", g.ID, resource.ExternalID)
		c.setLastTraceError(err)
		return "", false, err
	}
	if strings.TrimSpace(resource.ID) == "" {
		err := fmt.Errorf("SCIM group matched by externalId %q is missing id", g.ID)
		c.setLastTraceError(err)
		return "", false, err
	}
	return resource.ID, true, nil
}

func externalIDFilterPath(resourcePath string, externalID string) string {
	value := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(externalID)
	query := url.Values{
		"count":  {"2"},
		"filter": {fmt.Sprintf(`externalId eq "%s"`, value)},
	}
	return resourcePath + "?" + query.Encode()
}

func validateExternalIDMatches(totalResults int, resourceCount int, externalID string) error {
	switch {
	case totalResults > 1 || resourceCount > 1:
		return fmt.Errorf("SCIM filter for externalId %q returned multiple resources", externalID)
	case totalResults > 0 && resourceCount == 0:
		return fmt.Errorf("SCIM filter for externalId %q reported a match without returning it", externalID)
	default:
		return nil
	}
}

func (c *SCIMClient) replaceGroup(g Group, users []User) error {
	resource, err := newSCIMGroupResource(g, users)
	if err != nil {
		return err
	}
	resource.ID = g.RemoteID

	return c.doJSON(http.MethodPut, "/Groups/"+url.PathEscape(g.RemoteID), resource, nil, traceTargetForGroup(g, "update"))
}

func (c *SCIMClient) deleteGroup(g Group, operation string) error {
	return c.doJSON(http.MethodDelete, "/Groups/"+url.PathEscape(g.RemoteID), nil, nil, traceTargetForGroup(g, operation))
}

func newSCIMGroupResource(g Group, users []User) (SCIMGroupResource, error) {
	members := make([]SCIMMember, 0, len(g.MemberIDs))
	for _, memberID := range g.MemberIDs {
		u, ok := UserByID(users, memberID)
		if !ok {
			return SCIMGroupResource{}, fmt.Errorf("group %q references unknown user %q", g.DisplayName, memberID)
		}
		if strings.TrimSpace(u.RemoteID) == "" {
			return SCIMGroupResource{}, fmt.Errorf("group %q member %q has not been synced yet", g.DisplayName, UserLabel(u))
		}

		members = append(members, SCIMMember{Value: u.RemoteID, Type: "User"})
	}

	return SCIMGroupResource{
		Schemas:     []string{scimGroupSchema},
		ExternalID:  g.ID,
		DisplayName: strings.TrimSpace(g.DisplayName),
		Members:     members,
	}, nil
}

func (c *SCIMClient) doJSON(method string, path string, body any, out any, target TraceTarget) error {
	var payload []byte
	requestBody := ""
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode SCIM %s %s body: %w", method, path, err)
		}

		payload = encoded
		requestBody = string(encoded)
	}

	for attempt := 0; ; attempt++ {
		err := c.doJSONOnce(method, path, payload, requestBody, out, target)
		if err == nil {
			return nil
		}

		var rateLimitErr *RateLimitError
		if !errors.As(err, &rateLimitErr) {
			return err
		}
		if attempt >= maxSCIMRateLimitRetries {
			return err
		}

		delay := rateLimitRetryDelay(rateLimitErr.RetryAfterHeader, attempt, currentTime())
		if delay > maxAutomaticRateLimitDelay {
			return err
		}
		if c.onRateLimit != nil {
			c.onRateLimit(target, delay, rateLimitErr.RetryAfterHeader, attempt+1)
		}
		if c.ctx.Done() == nil {
			rateLimitSleep(delay)
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-c.ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return fmt.Errorf("wait for SCIM rate limit retry: %w", c.ctx.Err())
		}
	}
}

func (c *SCIMClient) doJSONOnce(method string, path string, payload []byte, requestBody string, out any, target TraceTarget) error {
	var reader io.Reader
	if payload != nil {
		reader = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(c.ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("build SCIM %s %s request: %w", method, path, err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/scim+json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}

	trace := SyncTraceEntry{
		ResourceType: target.ResourceType,
		ResourceID:   target.ResourceID,
		Label:        target.Label,
		Operation:    target.Operation,
		Method:       method,
		Path:         path,
		RequestBody:  requestBody,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}

	resp, err := c.client.Do(req)
	if err != nil {
		trace.Err = err.Error()
		c.traces = append(c.traces, trace)
		return fmt.Errorf("run SCIM %s %s request: %w", method, path, err)
	}
	trace.ResponseRetryAfter = strings.TrimSpace(resp.Header.Get("Retry-After"))

	data, err := readSCIMResponseBody(resp.Body)
	if err != nil {
		trace.Status = resp.Status
		if closeErr := resp.Body.Close(); closeErr != nil {
			trace.Err = fmt.Sprintf("%v (close body: %v)", err, closeErr)
			c.traces = append(c.traces, trace)
			return fmt.Errorf("read SCIM %s %s response: %w (close body: %v)", method, path, err, closeErr)
		}

		trace.Err = err.Error()
		c.traces = append(c.traces, trace)
		return fmt.Errorf("read SCIM %s %s response: %w", method, path, err)
	}
	trace.Status = resp.Status
	trace.ResponseBody = strings.TrimSpace(string(data))

	if err := resp.Body.Close(); err != nil {
		trace.Err = err.Error()
		c.traces = append(c.traces, trace)
		return fmt.Errorf("close SCIM %s %s response body: %w", method, path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if method == http.MethodDelete && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone) {
			c.traces = append(c.traces, trace)
			return nil
		}

		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
			responseErr := fmt.Errorf("SCIM %s %s returned %s: %w", method, path, resp.Status, errSCIMNotFound)
			trace.Err = responseErr.Error()
			c.traces = append(c.traces, trace)
			return responseErr
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			err := &RateLimitError{
				Method:           method,
				Path:             path,
				Status:           resp.Status,
				RetryAfter:       parseRetryAfter(trace.ResponseRetryAfter, currentTime()),
				RetryAfterHeader: trace.ResponseRetryAfter,
				ResponseBody:     strings.TrimSpace(string(data)),
			}
			trace.Err = err.Error()
			c.traces = append(c.traces, trace)
			return err
		}

		var responseErr error
		if requestBody == "" {
			responseErr = fmt.Errorf("SCIM %s %s returned %s: %s", method, path, resp.Status, strings.TrimSpace(string(data)))
		} else {
			responseErr = fmt.Errorf("SCIM %s %s returned %s: %s | request body: %s", method, path, resp.Status, strings.TrimSpace(string(data)), requestBody)
		}
		trace.Err = responseErr.Error()
		c.traces = append(c.traces, trace)
		return responseErr
	}

	if out == nil || len(data) == 0 {
		c.traces = append(c.traces, trace)
		return nil
	}

	if err := json.Unmarshal(data, out); err != nil {
		responseErr := fmt.Errorf("decode SCIM %s %s response: %w", method, path, err)
		trace.Err = responseErr.Error()
		c.traces = append(c.traces, trace)
		return responseErr
	}

	c.traces = append(c.traces, trace)
	return nil
}

func readSCIMResponseBody(body io.Reader) ([]byte, error) {
	limited := io.LimitReader(body, maxSCIMResponseBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(data) > maxSCIMResponseBodyBytes {
		return nil, fmt.Errorf("SCIM response body exceeds %d bytes", maxSCIMResponseBodyBytes)
	}
	return data, nil
}

func (c *SCIMClient) setLastTraceError(err error) {
	if err == nil || len(c.traces) == 0 {
		return
	}
	c.traces[len(c.traces)-1].Err = err.Error()
}

func parseRetryAfter(value string, now time.Time) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	seconds, err := strconv.Atoi(value)
	if err == nil {
		if seconds <= 0 {
			return "now"
		}

		return "in " + humanRetryAfter(time.Duration(seconds)*time.Second)
	}

	retryAt, err := http.ParseTime(value)
	if err != nil {
		return "after " + value
	}

	delay := retryAt.Sub(now)
	if delay <= 0 {
		return "now"
	}

	return "in " + humanRetryAfter(delay)
}

func rateLimitRetryDelay(value string, attempt int, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallbackRateLimitDelay(attempt)
	}

	seconds, err := strconv.Atoi(value)
	if err == nil {
		if seconds <= 0 {
			return 0
		}

		return time.Duration(seconds) * time.Second
	}

	retryAt, err := http.ParseTime(value)
	if err != nil {
		return fallbackRateLimitDelay(attempt)
	}

	delay := retryAt.Sub(now)
	if delay <= 0 {
		return 0
	}

	return delay
}

func fallbackRateLimitDelay(attempt int) time.Duration {
	if attempt < 0 {
		return time.Second
	}
	if attempt > maxSCIMRateLimitRetries {
		attempt = maxSCIMRateLimitRetries
	}

	return time.Duration(1<<attempt) * time.Second
}

func humanRetryAfter(delay time.Duration) string {
	seconds := int64((delay + time.Second - 1) / time.Second)
	switch {
	case seconds <= 1:
		return "1 second"
	case seconds < 60:
		return fmt.Sprintf("%d seconds", seconds)
	case seconds < 3600:
		minutes := (seconds + 59) / 60
		if minutes == 1 {
			return "1 minute"
		}

		return fmt.Sprintf("%d minutes", minutes)
	case seconds < 86400:
		hours := (seconds + 3599) / 3600
		if hours == 1 {
			return "1 hour"
		}

		return fmt.Sprintf("%d hours", hours)
	default:
		days := (seconds + 86399) / 86400
		if days == 1 {
			return "1 day"
		}

		return fmt.Sprintf("%d days", days)
	}
}

func traceTargetForUser(u User, operation string) TraceTarget {
	return TraceTarget{
		ResourceType: "user",
		ResourceID:   u.ID,
		Label:        progressUserLabel(u),
		Operation:    operation,
	}
}

func traceTargetForGroup(g Group, operation string) TraceTarget {
	return TraceTarget{
		ResourceType: "group",
		ResourceID:   g.ID,
		Label:        g.DisplayName,
		Operation:    operation,
	}
}
