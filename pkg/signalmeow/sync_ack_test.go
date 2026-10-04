// Copyright 2026 Christian Budde.
// SPDX-License-Identifier: AGPL-3.0-only

package signalmeow_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"google.golang.org/protobuf/proto"

	"github.com/cwbudde/mautrix-signal/pkg/libsignalgo"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/events"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/protobuf/signalpb"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/store"
	"github.com/cwbudde/mautrix-signal/pkg/signalmeow/types"
)

var timerSelf = uuid.MustParse("10000000-0000-0000-0000-000000000001")
var timerACI = uuid.MustParse("10000000-0000-0000-0000-000000000002")
var errTimerStoreFailure = errors.New("offline contact store failure")

// The no-cgo driver supplies one real DeviceByACI row and transaction failures;
// it does not emulate recipient SQL. Contact conversion uses the fixture below.
type timerDB struct {
	row                 []driver.Value
	beginErr, commitErr error
}
type timerConnector struct{ fixture *timerDB }
type timerDriver struct{}

func (timerDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }
func (c timerConnector) Driver() driver.Driver       { return timerDriver{} }
func (c timerConnector) Connect(context.Context) (driver.Conn, error) {
	return &timerConn{fixture: c.fixture}, nil
}

type timerConn struct{ fixture *timerDB }

func (*timerConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (*timerConn) Close() error                        { return nil }
func (c *timerConn) Begin() (driver.Tx, error) {
	if c.fixture.beginErr != nil {
		return nil, c.fixture.beginErr
	}
	return timerTxn{c.fixture}, nil
}
func (c *timerConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(query, "FROM signalmeow_device") {
		return nil, errors.New("unexpected query")
	}
	return &timerRows{row: c.fixture.row}, nil
}

type timerTxn struct{ fixture *timerDB }

func (tx timerTxn) Commit() error { return tx.fixture.commitErr }
func (timerTxn) Rollback() error  { return nil }

type timerRows struct {
	row  []driver.Value
	read bool
}

func (*timerRows) Columns() []string {
	return []string{"aci", "aci_key", "registration", "pni", "pni_key", "pni_registration", "device", "number", "password", "master", "account", "entropy", "ephemeral", "media"}
}
func (*timerRows) Close() error { return nil }
func (r *timerRows) Next(dst []driver.Value) error {
	if r.read {
		return io.EOF
	}
	copy(dst, r.row)
	r.read = true
	return nil
}

type timerRecipients struct {
	store.RecipientStore
	failACI      uuid.UUID
	convertedACI uuid.UUID
}

func (s *timerRecipients) LoadAndUpdateRecipient(ctx context.Context, aci, pni uuid.UUID, update store.RecipientUpdaterFunc) (*types.Recipient, error) {
	if aci == s.failACI {
		return nil, errTimerStoreFailure
	}
	if s.RecipientStore != nil {
		return s.RecipientStore.LoadAndUpdateRecipient(ctx, aci, pni, update)
	}
	recipient := &types.Recipient{ACI: aci, PNI: pni}
	if _, err := update(recipient); err != nil {
		return nil, err
	}
	if s.convertedACI != uuid.Nil {
		recipient.ACI = s.convertedACI
	}
	return recipient, nil
}

func timerDevice(t *testing.T) (*store.Device, *sql.DB, *timerDB) {
	t.Helper()
	key, err := libsignalgo.GenerateIdentityKeyPair()
	joinCheck(t, err)
	dd := &store.DeviceData{ACI: timerSelf, PNI: uuid.MustParse("10000000-0000-0000-0000-000000000003"), ACIIdentityKeyPair: key, PNIIdentityKeyPair: key, DeviceID: 1}
	db, err := sql.Open("sqlite3", ":memory:")
	joinCheck(t, err)
	if err = db.Ping(); err == nil {
		db.SetMaxOpenConns(1)
		wrapped, err := dbutil.NewWithDB(db, "sqlite3")
		joinCheck(t, err)
		container := store.NewStore(wrapped, dbutil.NoopLogger)
		joinCheck(t, container.Upgrade(context.Background()))
		joinCheck(t, container.PutDevice(context.Background(), dd))
		device, err := container.DeviceByACI(context.Background(), timerSelf)
		joinCheck(t, err)
		t.Cleanup(func() { joinCheck(t, db.Close()) })
		return device, db, nil
	}
	if !strings.Contains(err.Error(), "requires cgo") {
		t.Fatalf("unexpected SQLite fixture failure: %v", err)
	}
	joinCheck(t, db.Close())
	serialized, err := key.Serialize()
	joinCheck(t, err)
	fixture := &timerDB{row: []driver.Value{dd.ACI.String(), serialized, int64(0), dd.PNI.String(), serialized, int64(0), int64(1), "", "", nil, nil, nil, nil, nil}}
	db = sql.OpenDB(timerConnector{fixture})
	wrapped, err := dbutil.NewWithDB(db, "sqlite3")
	joinCheck(t, err)
	device, err := store.NewStore(wrapped, dbutil.NoopLogger).DeviceByACI(context.Background(), timerSelf)
	joinCheck(t, err)
	device.RecipientStore = &timerRecipients{}
	t.Cleanup(func() { joinCheck(t, db.Close()) })
	return device, db, fixture
}

func contactBytes(t *testing.T, contacts ...*signalpb.ContactDetails) []byte {
	t.Helper()
	var data []byte
	for _, contact := range contacts {
		raw, err := proto.Marshal(contact)
		joinCheck(t, err)
		data = binary.AppendUvarint(data, uint64(len(raw)))
		data = append(data, raw...)
	}
	return data
}

// Attachment encryption matches Signal's AES-CBC/HMAC framing. Only the HTTP
// transport is replaced; download, digest, MAC and decryption stay production.
func timerAttachment(t *testing.T, data []byte, fail bool) *signalpb.AttachmentPointer {
	t.Helper()
	key := bytes.Repeat([]byte{42}, 64)
	padded := bytes.Clone(data)
	padding := aes.BlockSize - len(padded)%aes.BlockSize
	padded = append(padded, bytes.Repeat([]byte{byte(padding)}, padding)...)
	block, err := aes.NewCipher(key[:32])
	joinCheck(t, err)
	iv := bytes.Repeat([]byte{24}, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	body := append(iv, padded...)
	mac := hmac.New(sha256.New, key[32:])
	_, err = mac.Write(body)
	joinCheck(t, err)
	body = mac.Sum(body)
	digest := sha256.Sum256(body)
	joinHTTP(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodGet || req.URL.Path != "/attachments/offline-contact-fixture" {
			t.Fatalf("unexpected attachment request: %s %s", req.Method, req.URL)
		}
		if fail {
			return nil, errors.New("offline download failure")
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}, nil
	})
	return &signalpb.AttachmentPointer{AttachmentIdentifier: &signalpb.AttachmentPointer_CdnKey{CdnKey: "offline-contact-fixture"}, Key: key, Digest: digest[:], Size: proto.Uint32(uint32(len(data)))}
}
func contactSync(pointer *signalpb.AttachmentPointer) *signalpb.SyncMessage {
	return &signalpb.SyncMessage{Content: &signalpb.SyncMessage_Contacts_{Contacts: &signalpb.SyncMessage_Contacts{Blob: pointer}}}
}

func malformedContactFrames(t *testing.T) []struct {
	name string
	data []byte
} {
	t.Helper()
	first := contactBytes(t, &signalpb.ContactDetails{Aci: proto.String(timerACI.String()), Name: proto.String("valid first"), ExpireTimer: proto.Uint32(60), ExpireTimerVersion: proto.Uint32(3)})
	second := &signalpb.ContactDetails{Aci: proto.String("10000000-0000-0000-0000-000000000009"), Name: proto.String("second")}
	rawSecond, err := proto.Marshal(second)
	joinCheck(t, err)
	longMessage := binary.AppendUvarint(bytes.Clone(first), uint64(len(rawSecond)+1))
	longMessage = append(longMessage, rawSecond...)
	second.Avatar = &signalpb.ContactDetails_Avatar{ContentType: proto.String("image/png"), Length: proto.Uint32(5)}
	shortAvatar := append(bytes.Clone(first), contactBytes(t, second)...)
	shortAvatar = append(shortAvatar, 1, 2)
	return []struct {
		name string
		data []byte
	}{
		{"lone nonzero prefix", append(bytes.Clone(first), 0x01)},
		{"declared message exceeds remaining protobuf", longMessage},
		{"incomplete varint", append(bytes.Clone(first), 0x80)},
		{"short advertised avatar", shortAvatar},
		{"uint64 length exceeds buffer", binary.AppendUvarint(bytes.Clone(first), ^uint64(0))},
	}
}

func checkNoPartialContactStorage(t *testing.T, device *store.Device, fixture *timerDB) {
	t.Helper()
	if fixture != nil {
		return
	}
	contacts, err := device.RecipientStore.LoadAllContacts(context.Background())
	joinCheck(t, err)
	if len(contacts) != 0 {
		t.Errorf("malformed contact attachment partially stored %d contacts", len(contacts))
	}
}

func TestSyncContactAckFailureMalformedFrames(t *testing.T) {
	for _, frame := range malformedContactFrames(t) {
		t.Run(frame.name, func(t *testing.T) {
			device, _, fixture := timerDevice(t)
			calls := 0
			cli := signalmeow.NewClient(device, zerolog.Nop(), func(events.SignalEvent) bool { calls++; return true })
			ack := cli.HandleSyncMessageForTest(context.Background(), contactSync(timerAttachment(t, frame.data, false)), &signalpb.Envelope{})
			if ack || calls != 0 {
				t.Errorf("malformed frame ack=%v events=%d; want false/0", ack, calls)
			}
			checkNoPartialContactStorage(t, device, fixture)
		})
	}
}

func TestSyncContactEmptyFrames(t *testing.T) {
	for _, data := range [][]byte{nil, {0}} {
		device, _, _ := timerDevice(t)
		calls := 0
		cli := signalmeow.NewClient(device, zerolog.Nop(), func(event events.SignalEvent) bool {
			list, ok := event.(*events.ContactList)
			if !ok || len(list.Contacts) != 0 || len(list.Timers) != 0 {
				t.Fatalf("unexpected empty contact event: %v", event)
			}
			calls++
			return true
		})
		ack := cli.HandleSyncMessageForTest(context.Background(), contactSync(timerAttachment(t, data, false)), &signalpb.Envelope{})
		if !ack || calls != 1 {
			t.Fatalf("empty-frame ack=%v events=%d; want true/1", ack, calls)
		}
	}
}

func TestSyncSentAckFailure(t *testing.T) {
	for _, edit := range []bool{false, true} {
		for _, success := range []bool{false, true} {
			name := "ordinary"
			if edit {
				name = "edit"
			}
			if success {
				name += "/accepted"
			} else {
				name += "/rejected"
			}
			t.Run(name, func(t *testing.T) {
				device := &store.Device{DeviceData: store.DeviceData{ACI: timerSelf}}
				calls := 0
				cli := signalmeow.NewClient(device, zerolog.Nop(), func(evt events.SignalEvent) bool {
					calls++
					chat, ok := evt.(*events.ChatEvent)
					if !ok || chat.Info.ChatID != timerACI.String() || chat.Info.Sender != timerSelf {
						t.Fatalf("wrong sent event: %v", evt)
					}
					return success
				})
				data := &signalpb.DataMessage{Body: proto.String("offline message"), ExpireTimer: proto.Uint32(60), ExpireTimerVersion: proto.Uint32(3)}
				sent := &signalpb.SyncMessage_Sent{DestinationServiceId: proto.String(timerACI.String())}
				if edit {
					sent.EditMessage = &signalpb.EditMessage{DataMessage: data}
				} else {
					sent.Message = data
				}
				ack := cli.HandleSyncMessageForTest(context.Background(), &signalpb.SyncMessage{Content: &signalpb.SyncMessage_Sent_{Sent: sent}}, &signalpb.Envelope{})
				if ack != success || calls != 1 {
					t.Fatalf("ack=%v calls=%d; want ack=%v calls=1", ack, calls, success)
				}
			})
		}
	}
}

func TestSyncContactAckFailure(t *testing.T) {
	for _, kind := range []string{"download", "decode", "store", "begin", "commit", "handler rejected", "handler accepted"} {
		t.Run(kind, func(t *testing.T) {
			device, db, fixture := timerDevice(t)
			data := contactBytes(t, &signalpb.ContactDetails{Aci: proto.String(timerACI.String()), Name: proto.String("offline"), ExpireTimer: proto.Uint32(60), ExpireTimerVersion: proto.Uint32(3)})
			switch kind {
			case "decode":
				data = []byte{0x80}
			case "store":
				device.RecipientStore = &timerRecipients{RecipientStore: device.RecipientStore, failACI: timerACI}
			case "begin":
				if fixture != nil {
					fixture.beginErr = errTimerStoreFailure
				} else {
					joinCheck(t, db.Close())
				}
			case "commit":
				if fixture == nil {
					t.Skip("commit error injection uses no-cgo controlled driver")
				}
				fixture.commitErr = errTimerStoreFailure
			}
			calls := 0
			success := kind == "handler accepted"
			cli := signalmeow.NewClient(device, zerolog.Nop(), func(evt events.SignalEvent) bool {
				if _, ok := evt.(*events.ContactList); !ok {
					t.Fatalf("wrong event: %T", evt)
				}
				calls++
				return success
			})
			ack := cli.HandleSyncMessageForTest(context.Background(), contactSync(timerAttachment(t, data, kind == "download")), &signalpb.Envelope{})
			wantCalls := 0
			if strings.HasPrefix(kind, "handler") {
				wantCalls = 1
			}
			if ack != success || calls != wantCalls {
				t.Fatalf("ack=%v events=%d; want ack=%v events=%d", ack, calls, success, wantCalls)
			}
		})
	}
}
