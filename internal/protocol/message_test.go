package protocol

import (
	"encoding/base64"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMaxMessageBytesAllowsBase64EncodedBody(t *testing.T) {
	r := require.New(t)
	encodedBodyBytes := int64(base64.StdEncoding.EncodedLen(MaxBodyBytesDefault))

	r.Greater(MaxMessageBytes(MaxBodyBytesDefault), encodedBodyBytes)
}

func TestMaxMessageBytes(t *testing.T) {
	tests := map[string]struct {
		maxBodyBytes int64
		want         int64
	}{
		"empty body":         {maxBodyBytes: 0, want: maxMessageMetadataBytes},
		"one byte":           {maxBodyBytes: 1, want: maxMessageMetadataBytes + 4},
		"complete block":     {maxBodyBytes: 3, want: maxMessageMetadataBytes + 4},
		"partial block":      {maxBodyBytes: 4, want: maxMessageMetadataBytes + 8},
		"overflow saturates": {maxBodyBytes: math.MaxInt64, want: math.MaxInt64},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			r.Equal(tc.want, MaxMessageBytes(tc.maxBodyBytes))
		})
	}
}
