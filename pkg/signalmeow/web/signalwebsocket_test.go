// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package web_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/rs/zerolog"

	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/wspb"
)

type websocketLogBuffer struct {
	sync.Mutex
	buffer bytes.Buffer
}

func (b *websocketLogBuffer) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.buffer.Write(p)
}
func (b *websocketLogBuffer) String() string { b.Lock(); defer b.Unlock(); return b.buffer.String() }

func TestWebsocketCredentialLoggingPrivacy(t *testing.T) {
	for _, path := range []string{
		"/v1/profile/00000000-0000-0000-0000-000000000001/test-profile-version/test-profile-request-do-not-log?credentialType=expiringProfileKey",
		"/v1/certificate/auth/group?redemptionStartSeconds=1790985600&redemptionEndSeconds=1791590400&pniAsServiceId=true",
	} {
		for _, status := range []uint32{200, 500} {
			for _, sensitive := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%d/private=%t", strings.Split(path, "?")[0], status, sensitive), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					credential := "test-issued-credential-do-not-log"
					message := "test-response-message-do-not-log"
					header := "test-response-header-do-not-log"
					body := []byte(fmt.Sprintf(`{"credentials":[{"credential":%q}]}`, credential))
					if strings.HasPrefix(path, "/v1/profile/") {
						body = []byte(fmt.Sprintf(`{"credential":%q}`, credential))
					}
					serverResult := make(chan error, 1)
					conn, peer, err := websocketPair(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer peer.CloseNow()
					go func() {
						request := &signalpb.WebSocketMessage{}
						if err := wspb.Read(ctx, peer, request); err != nil {
							serverResult <- err
							return
						}
						if request.GetRequest().GetPath() != path || request.GetRequest().GetVerb() != http.MethodGet {
							serverResult <- fmt.Errorf("request was modified")
							return
						}
						kind := signalpb.WebSocketMessage_RESPONSE
						response := &signalpb.WebSocketMessage{Type: &kind, Response: &signalpb.WebSocketResponseMessage{Id: request.Request.Id, Status: &status, Message: &message, Headers: []string{header}, Body: body}}
						serverResult <- wspb.Write(ctx, peer, response)
					}()
					logs := &websocketLogBuffer{}
					connectionLogger := zerolog.New(logs).Level(zerolog.TraceLevel)
					socket, stop := web.RunWebsocketLoopsForTest(connectionLogger.WithContext(ctx), conn)
					callCtx := zerolog.Nop().WithContext(ctx)
					if sensitive {
						callCtx = web.WithSensitiveRequestLogging(callCtx)
					}
					response, err := socket.SendRequest(callCtx, http.MethodGet, path, nil, nil)
					stop()
					cancel()
					if err != nil {
						t.Fatal(err)
					}
					if err = <-serverResult; err != nil {
						t.Fatal(err)
					}
					if response.GetStatus() != status || !bytes.Equal(response.Body, body) || response.GetMessage() != message {
						t.Fatal("response delivery changed")
					}
					output := logs.String()
					if !strings.Contains(output, "Sending WS request") || !strings.Contains(output, "Received WS response") {
						t.Fatal("production loops did not log")
					}
					for _, secret := range []string{path, credential, message, header} {
						if sensitive && strings.Contains(output, secret) {
							t.Errorf("connection-owned logger leaked sensitive request/response field %q", secret)
						}
						if !sensitive && !strings.Contains(output, secret) {
							t.Errorf("ordinary websocket logging changed for field %q", secret)
						}
					}
				})
			}
		}
	}
}

// The handshake uses real websocket Accept/Dial over net.Pipe. The dedicated
// fixture client never opens a network socket or replaces a shared client.
type websocketUpgradeRecorder struct {
	*httptest.ResponseRecorder
	connection net.Conn
}

func (r *websocketUpgradeRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return r.connection, bufio.NewReadWriter(bufio.NewReader(r.connection), bufio.NewWriter(r.connection)), nil
}

type websocketFixtureTransport func(*http.Request) (*http.Response, error)

func (f websocketFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func websocketPair(ctx context.Context) (*websocket.Conn, *websocket.Conn, error) {
	clientPipe, serverPipe := net.Pipe()
	var server *websocket.Conn
	client := &http.Client{Transport: websocketFixtureTransport(func(r *http.Request) (*http.Response, error) {
		writer := &websocketUpgradeRecorder{ResponseRecorder: httptest.NewRecorder(), connection: serverPipe}
		var err error
		server, err = websocket.Accept(writer, r, nil)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: writer.Code, Header: writer.Header(), Body: clientPipe}, nil
	})}
	connection, _, err := websocket.Dial(ctx, "ws://offline.invalid/", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		_ = clientPipe.Close()
		_ = serverPipe.Close()
		return nil, nil, err
	}
	return connection, server, nil
}
