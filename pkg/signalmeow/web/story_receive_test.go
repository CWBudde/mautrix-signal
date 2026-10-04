package web_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
)

func TestStoryReceiveNegotiation(t *testing.T) {
	original := web.SignalHTTPClient
	t.Cleanup(func() { web.SignalHTTPClient = original })
	for _, allow := range []bool{false, true} {
		want := "false"
		if allow {
			want = "true"
		}
		captured := ""
		web.SignalHTTPClient = &http.Client{Transport: websocketFixtureTransport(func(req *http.Request) (*http.Response, error) {
			captured = req.Header.Get("X-Signal-Receive-Stories")
			return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("offline"))}, nil
		})}
		conn, _, _ := web.OpenStoryWebsocketForTest(context.Background(), "wss://offline.invalid/", allow)
		if conn != nil {
			conn.CloseNow()
		}
		if captured != want {
			t.Fatalf("story negotiation = %q; want %q", captured, want)
		}
	}
}
