package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var rpDebugLogMu sync.Mutex

type debugResponseWriter struct {
	http.ResponseWriter
	status int
	body   bytes.Buffer
}

func (w *debugResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *debugResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.body.Write(data)
	return w.ResponseWriter.Write(data)
}

func (w *debugResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (a *webApp) debugRPHandler(next http.HandlerFunc) http.HandlerFunc {
	if !a.debugRP {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		requestBody, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("read RP debug request body: %v", err), http.StatusInternalServerError)
			return
		}
		if r.Body != nil {
			if err := r.Body.Close(); err != nil {
				http.Error(w, fmt.Sprintf("close RP debug request body: %v", err), http.StatusInternalServerError)
				return
			}
		}
		r.Body = io.NopCloser(bytes.NewReader(requestBody))

		capture := &debugResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next(capture, r)

		rpDebugLogMu.Lock()
		defer rpDebugLogMu.Unlock()
		writeDebugln(os.Stdout)
		writeDebugf(os.Stdout, "===== RP interaction %s =====\n", time.Now().Format(time.RFC3339))
		a.writeDebugHTTPRequest(os.Stdout, r, requestBody)
		a.writeDebugHTTPResponse(os.Stdout, capture)
		writeDebugln(os.Stdout, "===== end RP interaction =====")
	}
}

func writeDebugln(w io.Writer, args ...any) {
	if _, err := fmt.Fprintln(w, args...); err != nil {
		log.Printf("write RP debug output: %v", err)
	}
}

func writeDebugf(w io.Writer, format string, args ...any) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		log.Printf("write RP debug output: %v", err)
	}
}

func (a *webApp) writeDebugHTTPRequest(w io.Writer, r *http.Request, body []byte) {
	writeDebugln(w, "----- request from RP -----")
	writeDebugf(w, "%s %s %s\n", r.Method, r.URL.RequestURI(), r.Proto)
	writeDebugf(w, "Host: %s\n", r.Host)
	writeDebugHeaders(w, r.Header, a.debugSecrets)
	if len(body) > 0 {
		writeDebugln(w)
		writeDebugln(w, debugBody(r.Header.Get("Content-Type"), body, a.debugSecrets))
	}
	writeDebugSAMLRequest(w, "query", r.URL.Query().Get("SAMLRequest"))
	if isFormEncoded(r.Header.Get("Content-Type")) && len(body) > 0 {
		if values, err := url.ParseQuery(string(body)); err == nil {
			writeDebugSAMLRequest(w, "form", values.Get("SAMLRequest"))
		}
	}
}

func (a *webApp) writeDebugHTTPResponse(w io.Writer, response *debugResponseWriter) {
	status := response.status
	if status == 0 {
		status = http.StatusOK
	}
	body := response.body.String()
	writeDebugln(w, "----- response to RP -----")
	writeDebugf(w, "HTTP %d %s\n", status, http.StatusText(status))
	writeDebugHeaders(w, response.Header(), a.debugSecrets)
	if body != "" {
		writeDebugln(w)
		writeDebugln(w, debugResponseBody(response.Header().Get("Content-Type"), body, a.debugSecrets))
	}
	writeDebugSAMLResponse(w, body)
}

func writeDebugHeaders(w io.Writer, headers http.Header, includeSecrets bool) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range headers.Values(key) {
			if !includeSecrets && isSensitiveHeader(key) {
				value = "[REDACTED]"
			}
			writeDebugf(w, "%s: %s\n", key, value)
		}
	}
}

func isSensitiveHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Authorization", "Cookie", "Set-Cookie", "Proxy-Authorization":
		return true
	default:
		return false
	}
}

func debugBody(contentType string, body []byte, includeSecrets bool) string {
	if includeSecrets || !isFormEncoded(contentType) {
		return string(body)
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return string(body)
	}
	redactDebugValues(values)
	return values.Encode()
}

func debugResponseBody(contentType string, body string, includeSecrets bool) string {
	if includeSecrets {
		return body
	}
	if strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		var value any
		if err := json.Unmarshal([]byte(body), &value); err == nil {
			redactJSONValue(value)
			if redacted, err := json.MarshalIndent(value, "", "  "); err == nil {
				return string(redacted)
			}
		}
	}
	return redactHiddenInputs(body)
}

func redactDebugValues(values url.Values) {
	for key := range values {
		if isSensitiveDebugKey(key) {
			values[key] = []string{"[REDACTED]"}
		}
	}
}

func redactJSONValue(value any) {
	switch value := value.(type) {
	case map[string]any:
		for key, child := range value {
			if isSensitiveDebugKey(key) {
				value[key] = "[REDACTED]"
				continue
			}
			redactJSONValue(child)
		}
	case []any:
		for _, child := range value {
			redactJSONValue(child)
		}
	}
}

func isSensitiveDebugKey(key string) bool {
	switch strings.ToLower(key) {
	case "client_secret", "code", "access_token", "id_token", "refresh_token", "assertion", "samlrequest", "samlresponse":
		return true
	default:
		return false
	}
}

func redactHiddenInputs(body string) string {
	pattern := regexp.MustCompile(`(?i)(<input[^>]+name="(?:SAMLResponse|code|access_token|id_token|client_secret)"[^>]+value=")[^"]*(")`)
	return pattern.ReplaceAllString(body, `${1}[REDACTED]${2}`)
}

func writeDebugSAMLRequest(w io.Writer, source string, encodedRequest string) {
	if strings.TrimSpace(encodedRequest) == "" {
		return
	}
	xml := decodedSAMLRequestXML(encodedRequest)
	if xml == "" {
		writeDebugf(w, "\n----- decoded SAMLRequest (%s): unavailable -----\n", source)
		return
	}
	writeDebugf(w, "\n----- decoded SAMLRequest (%s) -----\n%s\n", source, xml)
}

func writeDebugSAMLResponse(w io.Writer, body string) {
	encodedResponse := hiddenInputValue(body, "SAMLResponse")
	if encodedResponse == "" {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		writeDebugln(w, "\n----- decoded SAMLResponse: unavailable -----")
		return
	}
	writeDebugf(w, "\n----- decoded SAMLResponse -----\n%s\n", string(decoded))
}

func decodedSAMLRequestXML(encodedRequest string) string {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedRequest))
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(encodedRequest), " ", "+"))
		if err != nil {
			return ""
		}
	}
	requestXML, err := inflateRawDeflate(decoded)
	if err != nil || len(requestXML) == 0 {
		requestXML = decoded
	}
	return string(requestXML)
}

func hiddenInputValue(body string, name string) string {
	pattern := fmt.Sprintf(`<input[^>]+name="%s"[^>]+value="([^"]*)"`, regexp.QuoteMeta(name))
	matches := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if len(matches) != 2 {
		return ""
	}
	return html.UnescapeString(matches[1])
}

func isFormEncoded(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.HasPrefix(contentType, "application/x-www-form-urlencoded")
}
