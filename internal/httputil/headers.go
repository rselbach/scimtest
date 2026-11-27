package httputil

import (
	"net/http"
	"strings"
)

var HopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

func CloneHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for key, values := range h {
		for _, value := range values {
			out.Add(key, value)
		}
	}
	return out
}

func RemoveHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if key := strings.TrimSpace(token); key != "" {
				h.Del(key)
			}
		}
	}
	for key := range HopHeaders {
		h.Del(key)
	}
}
