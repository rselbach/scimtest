package web

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListenForAdmin(t *testing.T) {
	tests := map[string]struct {
		occupied int
		explicit bool
		wantPort int
		wantErr  error
	}{
		"default port free":                {wantPort: 1},
		"default occupied uses next":       {occupied: 1, wantPort: 2},
		"multiple occupied use next":       {occupied: 3, wantPort: 4},
		"explicit occupied does not retry": {occupied: 1, explicit: true, wantErr: syscall.EADDRINUSE},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			blockers := reserveConsecutivePorts(t, tc.occupied+1)
			start := blockers[0].Addr().(*net.TCPAddr).Port
			if tc.occupied == 0 {
				r.NoError(blockers[0].Close())
			} else {
				r.NoError(blockers[tc.occupied].Close())
			}

			listener, err := listenForAdmin("127.0.0.1", strconv.Itoa(start), !tc.explicit)
			if tc.wantErr != nil {
				r.ErrorIs(err, tc.wantErr)
				r.Nil(listener)
				return
			}
			r.NoError(err)
			t.Cleanup(func() { r.NoError(listener.Close()) })
			r.Equal(start+tc.wantPort-1, listener.Addr().(*net.TCPAddr).Port)
		})
	}
}

func TestListenForAdminReturnsNonAddressInUseError(t *testing.T) {
	r := require.New(t)
	listener, err := listenForAdmin("192.0.2.1", "8080", true)
	r.Nil(listener)
	r.Error(err)
	r.False(errors.Is(err, syscall.EADDRINUSE))
}

func TestListenForAdminRejectsInvalidPorts(t *testing.T) {
	tests := map[string]string{
		"blank":        "",
		"not a number": "eight",
		"zero":         "0",
		"negative":     "-1",
		"too high":     "65536",
	}
	for name, port := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			listener, err := listenForAdmin("127.0.0.1", port, false)
			r.Nil(listener)
			r.ErrorContains(err, "invalid admin port")
		})
	}
}

func TestListenerURL(t *testing.T) {
	tests := map[string]struct {
		ip   net.IP
		want string
	}{
		"IPv4":          {ip: net.ParseIP("127.0.0.1"), want: "http://127.0.0.1:8123"},
		"IPv6":          {ip: net.ParseIP("::1"), want: "http://[::1]:8123"},
		"wildcard IPv4": {ip: net.IPv4zero, want: "http://127.0.0.1:8123"},
		"wildcard IPv6": {ip: net.IPv6zero, want: "http://[::1]:8123"},
		"zoned IPv6":    {ip: net.ParseIP("fe80::1"), want: "http://[fe80::1%25en0]:8123"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := require.New(t)
			address := &net.TCPAddr{IP: tc.ip, Port: 8123}
			if name == "zoned IPv6" {
				address.Zone = "en0"
			}
			got, err := listenerURL(stubListener{address: address})
			r.NoError(err)
			r.Equal(tc.want, got)
		})
	}
}

func TestBrowserOpenerReceivesSelectedURLAndReturnsFailure(t *testing.T) {
	r := require.New(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	r.NoError(err)
	t.Cleanup(func() { r.NoError(listener.Close()) })
	localURL, err := listenerURL(listener)
	r.NoError(err)

	wantErr := errors.New("browser unavailable")
	var got string
	opener := browserOpener(func(value string) error {
		got = value
		return wantErr
	})
	r.ErrorIs(opener(localURL), wantErr)
	r.Equal(localURL, got)
	r.False(strings.HasSuffix(got, ":0"))
}

func TestAdminListenerOwnsPortUntilClosed(t *testing.T) {
	r := require.New(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	r.NoError(err)
	address := listener.Addr().String()

	other, err := net.Listen("tcp", address)
	r.ErrorIs(err, syscall.EADDRINUSE)
	r.Nil(other)
	r.NoError(listener.Close())

	rebound, err := net.Listen("tcp", address)
	r.NoError(err)
	r.NoError(rebound.Close())
}

func reserveConsecutivePorts(t *testing.T, count int) []net.Listener {
	t.Helper()
	r := require.New(t)
	for attempts := 0; attempts < 100; attempts++ {
		first, err := net.Listen("tcp", "127.0.0.1:0")
		r.NoError(err)
		listeners := []net.Listener{first}
		port := first.Addr().(*net.TCPAddr).Port
		for offset := 1; offset < count; offset++ {
			listener, listenErr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port+offset)))
			if listenErr != nil {
				for _, existing := range listeners {
					r.NoError(existing.Close())
				}
				listeners = nil
				break
			}
			listeners = append(listeners, listener)
		}
		if listeners != nil {
			t.Cleanup(func() {
				for _, listener := range listeners {
					if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
						r.NoError(err)
					}
				}
			})
			return listeners
		}
	}
	t.Fatal("could not reserve consecutive loopback ports")
	return nil
}

type stubListener struct {
	address net.Addr
}

func (s stubListener) Accept() (net.Conn, error) { return nil, errors.New("not implemented") }
func (s stubListener) Close() error              { return nil }
func (s stubListener) Addr() net.Addr            { return s.address }
