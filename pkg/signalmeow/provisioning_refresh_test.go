// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow_test

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/hkdf"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/wspb"
)

func TestProvisioningQRRefresh(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
		defer cancel()
		var uris []string
		attempts := 0
		var servers sync.WaitGroup
		started := time.Now()
		open := func(ctx context.Context) (*websocket.Conn, error) {
			attempts++
			attempt := attempts
			ws, peer := provisioningPair(t, ctx)
			servers.Add(1)
			go func() {
				defer servers.Done()
				defer peer.CloseNow()
				sendProvisioningAddress(t, ctx, peer, fmt.Sprintf("address-%d", attempt))
				if attempt < 4 {
					<-ctx.Done()
					return
				}
				synctest.Wait()
				sendProvisioningMessage(t, ctx, peer, uris[len(uris)-1])
			}()
			return ws, nil
		}
		message, err := signalmeow.ProvisioningMessageForTest(ctx, 45*time.Second, open, func(uri string) { uris = append(uris, uri) })
		cancel()
		servers.Wait()
		if err != nil {
			t.Fatalf("scan after refresh: %v (attempts=%d)", err, attempts)
		}
		if message.GetNumber() != "+12025550123" || attempts != 4 || len(uris) != 4 {
			t.Fatalf("message=%v attempts=%d uris=%d", message, attempts, len(uris))
		}
		if elapsed := time.Since(started); elapsed != 135*time.Second {
			t.Fatalf("refresh timing: %s", elapsed)
		}
		seen := map[string]bool{}
		for i, uri := range uris {
			parsed, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			if parsed.Query().Get("uuid") != fmt.Sprintf("address-%d", i+1) {
				t.Fatalf("wrong fresh address: %s", uri)
			}
			key := parsed.Query().Get("pub_key")
			if seen[key] {
				t.Fatal("refresh reused a key")
			}
			seen[key] = true
		}
	})
}

func TestProvisioningQRStops(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"cancel", "deadline", "socket error", "address timeout", "invalid address", "closed socket", "bad envelope", "invalid message", "unacked envelope", "scanned", "scan near expiry"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
				defer cancel()
				if mode == "deadline" {
					var stop context.CancelFunc
					ctx, stop = context.WithTimeout(ctx, 10*time.Second)
					defer stop()
				}
				attempts := 0
				var servers sync.WaitGroup
				var uri string
				open := func(ctx context.Context) (*websocket.Conn, error) {
					attempts++
					if mode == "socket error" {
						return nil, io.ErrUnexpectedEOF
					}
					ws, peer := provisioningPair(t, ctx)
					servers.Add(1)
					go func() {
						defer servers.Done()
						defer peer.CloseNow()
						if mode == "address timeout" {
							<-ctx.Done()
							return
						}
						if mode == "invalid address" {
							_ = wspb.Write(ctx, peer, &signalpb.WebSocketMessage{})
							return
						}
						sendProvisioningAddress(t, ctx, peer, "one")
						switch mode {
						case "cancel":
							time.Sleep(10 * time.Second)
							cancel()
							<-ctx.Done()
						case "deadline":
							<-ctx.Done()
						case "closed socket":
							return
						case "bad envelope":
							sendProvisioningRequest(t, ctx, peer, "/v1/message", &signalpb.ProvisionEnvelope{PublicKey: []byte("bad")})
						case "invalid message":
							_ = wspb.Write(ctx, peer, &signalpb.WebSocketMessage{})
						case "unacked envelope":
							request := &signalpb.WebSocketMessage{Type: signalpb.WebSocketMessage_REQUEST.Enum(), Request: &signalpb.WebSocketRequestMessage{Id: proto.Uint64(1), Verb: proto.String("PUT"), Path: proto.String("/v1/message")}}
							if err := wspb.Write(ctx, peer, request); err != nil {
								t.Error(err)
							}
							<-ctx.Done()
						case "scanned", "scan near expiry":
							if mode == "scan near expiry" {
								time.Sleep(44 * time.Second)
							}
							synctest.Wait()
							sendProvisioningMessage(t, ctx, peer, uri)
						}
					}()
					return ws, nil
				}
				message, err := signalmeow.ProvisioningMessageForTest(ctx, 45*time.Second, open, func(value string) { uri = value })
				cancel()
				servers.Wait()
				if attempts != 1 {
					t.Fatalf("retried %s: %d attempts", mode, attempts)
				}
				if mode == "scanned" || mode == "scan near expiry" {
					if err != nil || message.GetNumber() != "+12025550123" {
						t.Fatalf("scan: %v, %v", message, err)
					}
				} else if err == nil {
					t.Fatal("expected error")
				}
				if mode == "cancel" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
				if mode == "deadline" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("deadline: %v", err)
				}
			})
		})
	}
}

type provisioningUpgrade struct {
	*httptest.ResponseRecorder
	connection net.Conn
}

func (r *provisioningUpgrade) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return r.connection, bufio.NewReadWriter(bufio.NewReader(r.connection), bufio.NewWriter(r.connection)), nil
}

type provisioningTransport func(*http.Request) (*http.Response, error)

func (f provisioningTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func provisioningPair(t *testing.T, ctx context.Context) (*websocket.Conn, *websocket.Conn) {
	t.Helper()
	clientPipe, serverPipe := net.Pipe()
	var peer *websocket.Conn
	client := &http.Client{Transport: provisioningTransport(func(r *http.Request) (*http.Response, error) {
		writer := &provisioningUpgrade{ResponseRecorder: httptest.NewRecorder(), connection: serverPipe}
		var err error
		peer, err = websocket.Accept(writer, r, nil)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: writer.Code, Header: writer.Header(), Body: clientPipe}, nil
	})}
	ws, _, err := websocket.Dial(ctx, "ws://offline.invalid", &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	return ws, peer
}
func sendProvisioningAddress(t *testing.T, ctx context.Context, peer *websocket.Conn, address string) {
	t.Helper()
	sendProvisioningRequest(t, ctx, peer, "/v1/address", &signalpb.ProvisioningAddress{Address: proto.String(address)})
}
func sendProvisioningRequest(t *testing.T, ctx context.Context, peer *websocket.Conn, path string, body proto.Message) {
	t.Helper()
	data, err := proto.Marshal(body)
	if err != nil {
		t.Error(err)
		return
	}
	request := &signalpb.WebSocketMessage{Type: signalpb.WebSocketMessage_REQUEST.Enum(), Request: &signalpb.WebSocketRequestMessage{Id: proto.Uint64(1), Verb: proto.String("PUT"), Path: proto.String(path), Body: data}}
	if err = wspb.Write(ctx, peer, request); err != nil {
		t.Error(err)
		return
	}
	ack := &signalpb.WebSocketMessage{}
	if err = wspb.Read(ctx, peer, ack); err != nil {
		if ctx.Err() == nil {
			t.Error(err)
		}
		return
	}
	if ack.GetResponse().GetStatus() != 200 {
		t.Errorf("ack: %v", ack)
	}
}
func sendProvisioningMessage(t *testing.T, ctx context.Context, peer *websocket.Conn, uri string) {
	t.Helper()
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Error(err)
		return
	}
	public, err := base64.StdEncoding.DecodeString(parsed.Query().Get("pub_key"))
	if err != nil {
		t.Error(err)
		return
	}
	key, err := libsignalgo.DeserializePublicKey(public)
	if err != nil {
		t.Error(err)
		return
	}
	phone, err := libsignalgo.GenerateIdentityKeyPair()
	if err != nil {
		t.Error(err)
		return
	}
	agreement, err := phone.GetPrivateKey().Agree(key)
	if err != nil {
		t.Error(err)
		return
	}
	secrets := make([]byte, 64)
	if _, err = io.ReadFull(hkdf.New(sha256.New, agreement, nil, []byte("TextSecure Provisioning Message")), secrets); err != nil {
		t.Error(err)
		return
	}
	plain, err := proto.Marshal(&signalpb.ProvisionMessage{Number: proto.String("+12025550123")})
	if err != nil {
		t.Error(err)
		return
	}
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	for range padding {
		plain = append(plain, byte(padding))
	}
	block, err := aes.NewCipher(secrets[:32])
	if err != nil {
		t.Error(err)
		return
	}
	iv := make([]byte, aes.BlockSize)
	encrypted := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, plain)
	body := append(append([]byte{1}, iv...), encrypted...)
	mac := hmac.New(sha256.New, secrets[32:])
	_, _ = mac.Write(body)
	body = append(body, mac.Sum(nil)...)
	ephemeral, err := phone.GetPublicKey().Serialize()
	if err != nil {
		t.Error(err)
		return
	}
	sendProvisioningRequest(t, ctx, peer, "/v1/message", &signalpb.ProvisionEnvelope{PublicKey: ephemeral, Body: body})
}

func TestProvisioningWithoutRefresh(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		attempts := 0
		var servers sync.WaitGroup
		open := func(ctx context.Context) (*websocket.Conn, error) {
			attempts++
			ws, peer := provisioningPair(t, ctx)
			servers.Go(func() {
				defer peer.CloseNow()
				sendProvisioningAddress(t, ctx, peer, "one-shot")
				<-ctx.Done()
			})
			return ws, nil
		}
		_, err := signalmeow.ProvisioningMessageForTest(t.Context(), 0, open, func(string) {})
		servers.Wait()
		if !errors.Is(err, context.DeadlineExceeded) || attempts != 1 || time.Since(started) != 2*time.Minute {
			t.Fatalf("legacy scan: attempts=%d elapsed=%s err=%v", attempts, time.Since(started), err)
		}
	})
}
