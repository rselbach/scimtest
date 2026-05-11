package web

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html"
	"io"
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
		requestBody, _ := io.ReadAll(r.Body)
		if r.Body != nil {
			_ = r.Body.Close()
		}
		r.Body = io.NopCloser(bytes.NewReader(requestBody))

		capture := &debugResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next(capture, r)

		rpDebugLogMu.Lock()
		defer rpDebugLogMu.Unlock()
		fmt.Fprintln(os.Stdout)
		fmt.Fprintf(os.Stdout, "===== RP interaction %s =====\n", time.Now().Format(time.RFC3339))
		writeDebugHTTPRequest(os.Stdout, r, requestBody)
		writeDebugHTTPResponse(os.Stdout, capture)
		fmt.Fprintln(os.Stdout, "===== end RP interaction =====")
	}
}

func writeDebugHTTPRequest(w io.Writer, r *http.Request, body []byte) {
	fmt.Fprintln(w, "----- request from RP -----")
	fmt.Fprintf(w, "%s %s %s\n", r.Method, r.URL.RequestURI(), r.Proto)
	fmt.Fprintf(w, "Host: %s\n", r.Host)
	writeDebugHeaders(w, r.Header)
	if len(body) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, string(body))
	}
	writeDebugSAMLRequest(w, "query", r.URL.Query().Get("SAMLRequest"))
	if isFormEncoded(r.Header.Get("Content-Type")) && len(body) > 0 {
		if values, err := url.ParseQuery(string(body)); err == nil {
			writeDebugSAMLRequest(w, "form", values.Get("SAMLRequest"))
		}
	}
}

func writeDebugHTTPResponse(w io.Writer, response *debugResponseWriter) {
	status := response.status
	if status == 0 {
		status = http.StatusOK
	}
	body := response.body.String()
	fmt.Fprintln(w, "----- response to RP -----")
	fmt.Fprintf(w, "HTTP %d %s\n", status, http.StatusText(status))
	writeDebugHeaders(w, response.Header())
	if body != "" {
		fmt.Fprintln(w)
		fmt.Fprintln(w, body)
	}
	writeDebugSAMLResponse(w, body)
}

func writeDebugHeaders(w io.Writer, headers http.Header) {
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range headers.Values(key) {
			fmt.Fprintf(w, "%s: %s\n", key, value)
		}
	}
}

func writeDebugSAMLRequest(w io.Writer, source string, encodedRequest string) {
	if strings.TrimSpace(encodedRequest) == "" {
		return
	}
	xml := decodedSAMLRequestXML(encodedRequest)
	if xml == "" {
		fmt.Fprintf(w, "\n----- decoded SAMLRequest (%s): unavailable -----\n", source)
		return
	}
	fmt.Fprintf(w, "\n----- decoded SAMLRequest (%s) -----\n%s\n", source, xml)
}

func writeDebugSAMLResponse(w io.Writer, body string) {
	encodedResponse := hiddenInputValue(body, "SAMLResponse")
	if encodedResponse == "" {
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(encodedResponse)
	if err != nil {
		fmt.Fprintln(w, "\n----- decoded SAMLResponse: unavailable -----")
		return
	}
	fmt.Fprintf(w, "\n----- decoded SAMLResponse -----\n%s\n", string(decoded))
}

func decodedSAMLRequestXML(encodedRequest string) string {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedRequest))
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(strings.TrimSpace(encodedRequest), " ", "+"))
		if err != nil {
			return ""
		}
	}
	requestXML := inflateRawDeflate(decoded)
	if len(requestXML) == 0 {
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
