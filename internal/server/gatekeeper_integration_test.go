package server_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nats-io/nats.go"
	"github.com/roguesignalchain/rogue-nats-server/internal/auth"
	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	rcrypto "github.com/roguesignalchain/rogue-nats-server/internal/crypto"
	"github.com/roguesignalchain/rogue-nats-server/internal/gatekeeper"
	"github.com/roguesignalchain/rogue-nats-server/internal/rpc"
	"github.com/roguesignalchain/rogue-nats-server/internal/server"
	"github.com/roguesignalchain/rogue-nats-server/internal/store"
)

type mapValidator struct {
	mu     sync.RWMutex
	states map[string]rpc.AccountState
}

func (m *mapValidator) set(addr string, rogueBal float64, level uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := rpc.RogueToWei(rogueBal)
	m.states[strings.ToLower(addr)] = rpc.AccountState{
		Address:         strings.ToLower(addr),
		BalanceLatest:   new(big.Int).Set(w),
		BalanceLookback: new(big.Int).Set(w),
		MinerLevel:      level,
	}
}

func (m *mapValidator) VerifyAccount(_ context.Context, addr string) (rpc.AccountState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st, ok := m.states[strings.ToLower(addr)]
	if !ok {
		return rpc.AccountState{
			Address:         strings.ToLower(addr),
			BalanceLatest:   big.NewInt(0),
			BalanceLookback: big.NewInt(0),
		}, nil
	}
	return st, nil
}

func rpcCmd(t *testing.T, nc *nats.Conn, subject string, body any) gatekeeper.CommandResponse {
	t.Helper()
	raw, _ := json.Marshal(body)
	reply, err := nc.Request(subject, raw, 3*time.Second)
	if err != nil {
		t.Fatalf("Request(%s): %v", subject, err)
	}
	var resp gatekeeper.CommandResponse
	if err := json.Unmarshal(reply.Data, &resp); err != nil {
		t.Fatalf("unmarshal CommandResponse: %v", err)
	}
	return resp
}

func TestGatekeeperTokenomicsModerationAndE2EEDM(t *testing.T) {
	adminPriv, _ := secp256k1.GeneratePrivateKey()
	adminAddr := auth.PubKeyToAddress(adminPriv.PubKey())
	alicePriv, _ := secp256k1.GeneratePrivateKey()
	aliceAddr := auth.PubKeyToAddress(alicePriv.PubKey())
	bobPriv, _ := secp256k1.GeneratePrivateKey()
	bobAddr := auth.PubKeyToAddress(bobPriv.PubKey())

	cfg := config.Default()
	cfg.Host = "127.0.0.1"
	cfg.Port = -1
	cfg.WSPort = -1
	cfg.HTTPPort = -1
	cfg.DataDir = t.TempDir()
	cfg.AdminAddresses = []string{adminAddr}

	val := &mapValidator{states: make(map[string]rpc.AccountState)}
	val.set(adminAddr, 1000, 6)
	val.set(aliceAddr, 5, 0) // Enough for chat (>=1), not enough for links (>=10 or Lv.1+)
	val.set(bobAddr, 60, 2)  // Enough for links and room creation

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv, err := server.NewWithValidator(cfg, val, logger)
	if err != nil {
		t.Fatalf("NewWithValidator: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Shutdown()

	adminNC, _, err := connectAuthenticatedClient(t, srv.ClientURL(), adminPriv)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer adminNC.Close()

	aliceNC, _, err := connectAuthenticatedClient(t, srv.ClientURL(), alicePriv)
	if err != nil {
		t.Fatalf("connect alice: %v", err)
	}
	defer aliceNC.Close()

	bobNC, _, err := connectAuthenticatedClient(t, srv.ClientURL(), bobPriv)
	if err != nil {
		t.Fatalf("connect bob: %v", err)
	}
	defer bobNC.Close()

	// 1. Alice cannot post links at 5 ROGUE / Lv.0, and cannot post to #announcements.
	linkResp := rpcCmd(t, aliceNC, "rogue.in."+aliceAddr+".chat.general", gatekeeper.ChatMessageInput{
		Text: "check https://roguechain.org",
	})
	if linkResp.OK || linkResp.Error == nil || linkResp.Error.Code != gatekeeper.ErrLinkRestricted {
		t.Fatalf("expected ERR_LINK_RESTRICTED, got %+v", linkResp)
	}

	annResp := rpcCmd(t, aliceNC, "rogue.in."+aliceAddr+".chat.announcements", gatekeeper.ChatMessageInput{
		Text: "hello",
	})
	if annResp.OK || annResp.Error == nil || annResp.Error.Code != gatekeeper.ErrForbidden {
		t.Fatalf("expected ERR_FORBIDDEN on announcements, got %+v", annResp)
	}

	// 2. Alice posts a valid text message and Bob receives it live.
	bobSub, err := bobNC.SubscribeSync("rogue.chat.general.msg")
	if err != nil {
		t.Fatalf("bob subscribe general: %v", err)
	}
	_ = bobNC.Flush()

	okResp := rpcCmd(t, aliceNC, "rogue.in."+aliceAddr+".chat.general", gatekeeper.ChatMessageInput{
		Text: "hello rogue network",
	})
	if !okResp.OK {
		t.Fatalf("expected OK chat publish, got %+v", okResp)
	}
	liveMsg, err := bobSub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("bob NextMsg: %v", err)
	}
	var env gatekeeper.ChatMessageEnvelope
	if err := json.Unmarshal(liveMsg.Data, &env); err != nil {
		t.Fatalf("unmarshal liveMsg: %v", err)
	}
	if env.Sender != aliceAddr || env.Text != "hello rogue network" {
		t.Fatalf("unexpected envelope: %+v", env)
	}

	// 3. Room name wildcard injection must fail; valid room creation by Bob succeeds.
	badRoom := rpcCmd(t, bobNC, "rogue.in."+bobAddr+".cmd.create_room", map[string]string{"name": "bad.*"})
	if badRoom.OK || badRoom.Error.Code != gatekeeper.ErrBadRequest {
		t.Fatalf("expected ERR_BAD_REQUEST for wildcard room name, got %+v", badRoom)
	}
	goodRoom := rpcCmd(t, bobNC, "rogue.in."+bobAddr+".cmd.create_room", map[string]string{"name": "miners-lounge", "topic": "RandomX talk"})
	if !goodRoom.OK {
		t.Fatalf("expected room creation OK, got %+v", goodRoom)
	}

	// 4. Presence + descending room order (miners-lounge has 1 active member, pinned rooms stay on top).
	js, _ := srv.JetStream()
	presKV, _ := js.KeyValue(store.BucketPresence)
	presBytes, _ := json.Marshal(gatekeeper.PresenceRecord{Address: bobAddr, ActiveRoom: "miners-lounge", Level: 2, UpdatedAt: time.Now().UTC().UnixMilli()})
	_, _ = presKV.Put(bobAddr, presBytes)

	roomsResp := rpcCmd(t, bobNC, "rogue.in."+bobAddr+".cmd.rooms", map[string]any{})
	if !roomsResp.OK {
		t.Fatalf("rooms cmd failed: %+v", roomsResp)
	}
	rawRooms, _ := json.Marshal(roomsResp.Data)
	var rooms []gatekeeper.RoomSummary
	_ = json.Unmarshal(rawRooms, &rooms)
	if len(rooms) < 4 || !rooms[0].Pinned || rooms[2].Name != "miners-lounge" || rooms[2].MemberCount != 1 {
		t.Fatalf("unexpected room ordering: %+v", rooms)
	}

	// 5. E2EE DM from Alice to Bob using Bob's pubkey in ROGUE_PROFILES.
	profilesKV, _ := js.KeyValue(store.BucketProfiles)
	bobProfEntry, err := profilesKV.Get(bobAddr)
	if err != nil {
		t.Fatalf("get bob profile: %v", err)
	}
	var bobProf auth.ProfileRecord
	_ = json.Unmarshal(bobProfEntry.Value(), &bobProf)

	bobDMSub, err := bobNC.SubscribeSync("rogue.dm." + bobAddr)
	if err != nil {
		t.Fatalf("bob subscribe dm: %v", err)
	}
	_ = bobNC.Flush()

	encPayload, err := rcrypto.EncryptECIES(bobProf.PubKey, []byte("top secret dm"))
	if err != nil {
		t.Fatalf("EncryptECIES: %v", err)
	}
	dmResp := rpcCmd(t, aliceNC, "rogue.in."+aliceAddr+".dm."+bobAddr, encPayload)
	if !dmResp.OK {
		t.Fatalf("dm send failed: %+v", dmResp)
	}
	dmMsg, err := bobDMSub.NextMsg(2 * time.Second)
	if err != nil {
		t.Fatalf("bob DM NextMsg: %v", err)
	}
	var dmEnv gatekeeper.DMEnvelope
	_ = json.Unmarshal(dmMsg.Data, &dmEnv)
	plain, err := rcrypto.DecryptECIES(bobPriv, dmEnv.Payload)
	if err != nil || string(plain) != "top secret dm" {
		t.Fatalf("DecryptECIES failed: err=%v plain=%q", err, plain)
	}

	// 6. Admin physical delete of Alice's message + ban disconnecting Alice immediately.
	dataMap := okResp.Data.(map[string]any)
	seq := uint64(dataMap["seq"].(float64))
	delResp := rpcCmd(t, adminNC, "rogue.in."+adminAddr+".cmd.delete_msg", map[string]any{"room": "general", "seq": seq})
	if !delResp.OK {
		t.Fatalf("delete_msg failed: %+v", delResp)
	}
	if _, err := js.GetMsg(store.StreamChat, seq); err == nil {
		t.Fatal("expected deleted message to be physically removed from ROGUE_CHAT")
	}

	banResp := rpcCmd(t, adminNC, "rogue.in."+adminAddr+".cmd.ban", map[string]string{"target": aliceAddr, "reason": "spam"})
	if !banResp.OK {
		t.Fatalf("ban failed: %+v", banResp)
	}
	banMap := banResp.Data.(map[string]any)
	if int(banMap["disconnected_sessions"].(float64)) < 1 {
		t.Fatalf("expected Alice's active session to be disconnected on ban, got %+v", banResp.Data)
	}
}
