package protocol

import (
	"fmt"
	"math"
	"net/http"
)

const MaxBodyBytesDefault = 32 << 20

const maxMessageMetadataBytes = 1 << 20

const (
	TypeRegisterTunnel       = "register_tunnel"
	TypeApplicationChallenge = "application_challenge"
	TypeApplicationSignature = "application_signature"
	TypeTunnelRegistered     = "tunnel_registered"
	TypeRequest              = "request"
	TypeResponse             = "response"
	TypePing                 = "ping"
	TypePong                 = "pong"
)

type Message struct {
	Type string `json:"type"`

	TunnelID  string `json:"tunnel_id,omitempty"`
	PublicURL string `json:"public_url,omitempty"`

	LocalPort            int    `json:"local_port,omitempty"`
	ApplicationProfileID string `json:"application_profile_id,omitempty"`
	InstanceID           string `json:"instance_id,omitempty"`
	Challenge            string `json:"challenge,omitempty"`
	Signature            []byte `json:"signature,omitempty"`

	StreamID uint64      `json:"stream_id,omitempty"`
	Method   string      `json:"method,omitempty"`
	Path     string      `json:"path,omitempty"`
	Host     string      `json:"host,omitempty"`
	Scheme   string      `json:"scheme,omitempty"`
	Header   http.Header `json:"header,omitempty"`
	Body     []byte      `json:"body,omitempty"`

	StatusCode int    `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

// MaxMessageBytes returns the WebSocket read limit needed for a message with
// maxBodyBytes of binary body data. JSON encodes byte slices as base64.
func MaxMessageBytes(maxBodyBytes int64) int64 {
	if maxBodyBytes <= 0 {
		return maxMessageMetadataBytes
	}

	blocks := maxBodyBytes / 3
	if maxBodyBytes%3 != 0 {
		blocks++
	}
	if blocks > (math.MaxInt64-maxMessageMetadataBytes)/4 {
		return math.MaxInt64
	}
	return blocks*4 + maxMessageMetadataBytes
}

// ApplicationChallengePayload returns the versioned bytes an application must
// sign to authenticate a tunnel registration.
func ApplicationChallengePayload(profileID, instanceID, challenge string) []byte {
	return []byte(fmt.Sprintf(
		"scimtest-server-application-registration-v1\n%s\n%s\n%s",
		profileID,
		instanceID,
		challenge,
	))
}
