// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only
package signalmeow_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/web"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/wspb"
)

// Exercise the real initial key check, upload serialization and 422 handling.
// In particular, the receive worker must not join its own loopWg during logout.
func TestKeyCheckLifecyclePNI422(t *testing.T) {
	for _, failure := range []string{"success", "delete-keys", "remove-sessions", "persist-password"} {
		t.Run(failure, func(t *testing.T) { testKeyCheckLifecyclePNI422(t, failure) })
	}
}

func testKeyCheckLifecyclePNI422(t *testing.T, failure string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	fixture := &keyCheckTransport{ctx: ctx, uploaded: make(chan struct{}), releaseUpload: make(chan struct{}), failures: make(chan error, 8)}
	originalHTTP := web.SignalHTTPClient
	web.SignalHTTPClient = &http.Client{Transport: fixture}
	defer func() { web.SignalHTTPClient = originalHTTP }()

	identity, err := libsignalgo.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	aci, pni := uuid.New(), uuid.New()
	keysDeleted, sessionsRemoved, passwordSaved := make(chan struct{}), make(chan struct{}), make(chan string, 1)
	cleanupErr := errors.New("fixture cleanup failure")
	aciKeys := &keyCheckPreKeys{serviceID: libsignalgo.NewACIServiceID(aci), deleted: keysDeleted, keys: signalmeow.GeneratePreKeys(1, 1)}
	sessions := &keyCheckSessions{removed: sessionsRemoved}
	devices := &keyCheckDeviceStore{saved: passwordSaved}
	switch failure {
	case "delete-keys":
		aciKeys.deleteErr = cleanupErr
	case "remove-sessions":
		sessions.removeErr = cleanupErr
	case "persist-password":
		devices.putErr = cleanupErr
	}
	device := &store.Device{
		DeviceData:      store.DeviceData{ACI: aci, PNI: pni, DeviceID: 2, Password: "fixture-password", PNIIdentityKeyPair: identity, MasterKey: []byte{1}},
		ACIPreKeyStore:  aciKeys,
		PNIPreKeyStore:  &keyCheckPreKeys{serviceID: libsignalgo.NewPNIServiceID(pni), keys: signalmeow.GeneratePreKeys(1, 1)},
		ACISessionStore: sessions,
		DeviceStore:     devices,
	}
	loggedOut, releaseEvent := make(chan *events.LoggedOut, 1), make(chan struct{})
	var releaseOnce sync.Once
	logger := zerolog.New(io.Discard)
	client := signalmeow.NewClient(device, logger, func(event events.SignalEvent) bool {
		if logout, ok := event.(*events.LoggedOut); ok {
			for _, connection := range fixture.connections() {
				select {
				case <-connection.closed:
				default:
					fixture.failures <- errors.New("LoggedOut arrived before websocket transport closure")
				}
			}
			loggedOut <- logout
			<-releaseEvent
		}
		return true
	})
	statuses, err := client.StartReceiveLoops(logger.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	// Retain the sockets for bounded teardown of the deliberately deadlocked old
	// implementation. On success, the public StopReceiveLoops joins every loop.
	authed, unauthed, grpc := client.AuthedWS, client.UnauthedWS, client.GRPC
	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
		for range statuses {
		}
	}()
	var stopDone chan error
	defer func() {
		releaseOnce.Do(func() { close(releaseEvent) })
		cancel()
		fixture.closePipes()
		_ = authed.Close()
		_ = unauthed.Close()
		_ = grpc.Close()
		fixture.waitReaders(t)
		if stopDone != nil {
			select {
			case <-stopDone:
			case <-time.After(time.Second):
				t.Error("external StopReceiveLoops did not finish during cleanup")
			}
		}
	}()

	keyCheckWait(t, ctx, fixture.uploaded, "PNI prekey upload")
	close(fixture.releaseUpload)
	keyCheckWait(t, ctx, keysDeleted, "prekey deletion")
	if failure != "delete-keys" {
		keyCheckWait(t, ctx, sessionsRemoved, "session removal")
	}
	select {
	case password := <-passwordSaved:
		if password != "" {
			t.Errorf("persisted password = %q, want empty", password)
		}
	case <-ctx.Done():
		t.Fatal("password persistence was not attempted:", ctx.Err())
	}
	// Require both websocket readers to observe transport termination before
	// waiting for LoggedOut: a passing event alone cannot hide a live socket.
	connections := fixture.connections()
	if len(connections) != 2 {
		t.Fatalf("opened %d websocket transports, want authenticated and unauthenticated", len(connections))
	}
	for _, connection := range connections {
		keyCheckWait(t, ctx, connection.closed, "local websocket transport close")
		keyCheckWait(t, ctx, connection.readDone, "peer reader termination")
		if connection.readErr == nil {
			t.Error("peer reader exited without observing websocket closure")
		}
	}
	keyCheckWait(t, ctx, statusDone, "receive status channel closure")
	select {
	case logout := <-loggedOut:
		cause := logout.Error
		for cause != nil && errors.Unwrap(cause) != nil {
			cause = errors.Unwrap(cause)
		}
		if cause == nil || cause.Error() != "http 422 while registering prekeys" {
			t.Fatalf("LoggedOut cause = %v, want PNI upload 422", logout.Error)
		}
	case <-ctx.Done():
		t.Fatal("PNI upload returned 422 and disconnected, but LoggedOut was not delivered (receive worker may be joining itself):", ctx.Err())
	}
	if failure != "delete-keys" && len(aciKeys.keys) != 0 {
		t.Error("prekeys were not cleared")
	}
	if device.Password != "" {
		t.Errorf("device password = %q, want empty", device.Password)
	}
	if failure == "delete-keys" {
		if len(aciKeys.keys) != 1 {
			t.Error("failed prekey deletion changed stored keys")
		}
		select {
		case <-sessionsRemoved:
			t.Error("session removal followed failed prekey deletion")
		default:
		}
	}

	stopDone = make(chan error, 1)
	stopStarted := make(chan struct{})
	go func() { close(stopStarted); stopDone <- client.StopReceiveLoops() }()
	keyCheckWait(t, ctx, stopStarted, "external stop start")
	select {
	case err := <-stopDone:
		t.Fatalf("StopReceiveLoops returned before the LoggedOut callback completed: %v", err)
	case <-time.After(150 * time.Millisecond):
		// A watchdog observes noncompletion while a channel holds the callback.
	}
	releaseOnce.Do(func() { close(releaseEvent) })
	select {
	case err := <-stopDone:
		if err != nil {
			t.Errorf("StopReceiveLoops after internal disconnect: %v", err)
		}
		stopDone = nil
	case <-ctx.Done():
		t.Fatal("StopReceiveLoops did not join the released key-check worker:", ctx.Err())
	}
	if client.AuthedWS != nil || client.UnauthedWS != nil || client.GRPC != nil {
		t.Error("StopReceiveLoops did not reset connection fields")
	}
	select {
	case err := <-fixture.failures:
		t.Fatal(err)
	default:
	}
}

func keyCheckWait(t *testing.T, ctx context.Context, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatalf("%s did not complete: %v", what, ctx.Err())
	}
}

type keyCheckPreKeys struct {
	store.PreKeyStore
	serviceID libsignalgo.ServiceID
	keys      []*libsignalgo.PreKeyRecord
	deleted   chan struct{}
	deleteErr error
}

func (s *keyCheckPreKeys) GetServiceID() libsignalgo.ServiceID { return s.serviceID }
func (*keyCheckPreKeys) GetNextPreKeyID(context.Context) (uint32, uint32, error) {
	return 100, 101, nil
}
func (*keyCheckPreKeys) GetNextKyberPreKeyID(context.Context) (uint32, uint32, error) {
	return 100, 101, nil
}
func (s *keyCheckPreKeys) AllPreKeys(context.Context) ([]*libsignalgo.PreKeyRecord, error) {
	return s.keys, nil
}
func (*keyCheckPreKeys) AllNormalKyberPreKeys(context.Context) ([]*libsignalgo.KyberPreKeyRecord, error) {
	return nil, nil
}
func (s *keyCheckPreKeys) DeleteAllPreKeys(context.Context) error {
	if s.deleteErr == nil {
		s.keys = nil
	}
	close(s.deleted)
	return s.deleteErr
}

type keyCheckSessions struct {
	store.SessionStore
	removed   chan struct{}
	removeErr error
}

func (s *keyCheckSessions) RemoveAllSessions(context.Context) error {
	close(s.removed)
	return s.removeErr
}

type keyCheckDeviceStore struct {
	store.DeviceStore
	saved  chan string
	putErr error
}

func (s *keyCheckDeviceStore) PutDevice(_ context.Context, data *store.DeviceData) error {
	s.saved <- data.Password
	return s.putErr
}

type keyCheckPipe struct {
	net.Conn
	closed, readDone chan struct{}
	readErr          error
	once             sync.Once
}

func (c *keyCheckPipe) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

type keyCheckUpgradeWriter struct {
	*httptest.ResponseRecorder
	connection net.Conn
}

func (w *keyCheckUpgradeWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.connection, bufio.NewReadWriter(bufio.NewReader(w.connection), bufio.NewWriter(w.connection)), nil
}

type keyCheckTransport struct {
	ctx                     context.Context
	mu                      sync.Mutex
	pipes                   []*keyCheckPipe
	uploaded, releaseUpload chan struct{}
	failures                chan error
}

func (f *keyCheckTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	client, server := net.Pipe()
	pipe := &keyCheckPipe{Conn: client, closed: make(chan struct{}), readDone: make(chan struct{})}
	writer := &keyCheckUpgradeWriter{ResponseRecorder: httptest.NewRecorder(), connection: server}
	peer, err := websocket.Accept(writer, req, nil)
	if err != nil {
		_ = client.Close()
		_ = server.Close()
		return nil, err
	}
	f.mu.Lock()
	f.pipes = append(f.pipes, pipe)
	f.mu.Unlock()
	go f.serve(peer, pipe, req.URL.User != nil || req.Header.Get("Authorization") != "")
	return &http.Response{StatusCode: writer.Code, Header: writer.Header(), Body: pipe}, nil
}
func (f *keyCheckTransport) serve(peer *websocket.Conn, pipe *keyCheckPipe, authed bool) {
	defer close(pipe.readDone)
	defer peer.CloseNow()
	expected := []struct {
		verb, path, body string
		status           int
	}{
		{http.MethodPut, "/v1/devices/capabilities", "", http.StatusOK},
		{http.MethodGet, "/v2/keys?identity=aci", `{"count":100,"pqCount":100}`, http.StatusOK},
		{http.MethodGet, "/v2/keys?identity=pni", `{"count":0,"pqCount":100}`, http.StatusOK},
		{http.MethodPut, "/v2/keys?identity=pni", "", http.StatusUnprocessableEntity},
	}
	index := 0
	for {
		message := &signalpb.WebSocketMessage{}
		if err := wspb.Read(f.ctx, peer, message); err != nil {
			pipe.readErr = err
			return
		}
		request := message.GetRequest()
		if !authed || index >= len(expected) || request == nil {
			f.failures <- fmt.Errorf("unexpected websocket request: authed=%v message=%v", authed, message)
			return
		}
		want := expected[index]
		if request.GetVerb() != want.verb || request.GetPath() != want.path {
			f.failures <- fmt.Errorf("request %d = %s %s, want %s %s", index, request.GetVerb(), request.GetPath(), want.verb, want.path)
			return
		}
		if index == 3 {
			var upload struct {
				IdentityKey string            `json:"identityKey"`
				PreKeys     []json.RawMessage `json:"preKeys"`
			}
			if err := json.Unmarshal(request.GetBody(), &upload); err != nil || upload.IdentityKey == "" || len(upload.PreKeys) != 1 {
				f.failures <- fmt.Errorf("PNI upload did not serialize the real identity and prekey: %s (error %v)", request.GetBody(), err)
				return
			}
			close(f.uploaded)
			select {
			case <-f.releaseUpload:
			case <-f.ctx.Done():
				return
			}
		}
		response := web.CreateWSResponse(f.ctx, request.GetId(), http.StatusOK)
		status := uint32(want.status)
		response.Response.Status = &status
		response.Response.Body = []byte(want.body)
		if err := wspb.Write(f.ctx, peer, response); err != nil {
			f.failures <- fmt.Errorf("write response %d: %w", index, err)
			return
		}
		index++
	}
}
func (f *keyCheckTransport) connections() []*keyCheckPipe {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*keyCheckPipe(nil), f.pipes...)
}
func (f *keyCheckTransport) closePipes() {
	for _, pipe := range f.connections() {
		_ = pipe.Close()
	}
}
func (f *keyCheckTransport) waitReaders(t *testing.T) {
	t.Helper()
	for _, pipe := range f.connections() {
		select {
		case <-pipe.readDone:
		case <-time.After(time.Second):
			t.Error("fixture reader did not terminate")
		}
	}
}
