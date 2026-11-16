package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nats-io/nats.go"
	"github.com/roguesignalchain/rogue-nats-server/internal/auth"
	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	"github.com/roguesignalchain/rogue-nats-server/internal/rpc"
	"github.com/roguesignalchain/rogue-nats-server/internal/server"
	"github.com/roguesignalchain/rogue-nats-server/internal/store"
)

func connectAuthenticatedClient(t *testing.T, clientURL string, priv *secp256k1.PrivateKey) (*nats.Conn, string, error) {
	t.Helper()
	addr := auth.PubKeyToAddress(priv.PubKey())

	guestNC, err := nats.Connect(clientURL, nats.Token(auth.ChallengeToken))
	if err != nil {
		return nil, addr, err
	}
	reqBytes, _ := json.Marshal(auth.NonceRequest{Address: addr})
	reply, err := guestNC.Request("rogue.auth.nonce", reqBytes, 3*time.Second)
	guestNC.Close()
	if err != nil {
		return nil, addr, err
	}

	var nonceResp auth.NonceResponse
	if err := json.Unmarshal(reply.Data, &nonceResp); err != nil {
		return nil, addr, err
	}
	if nonceResp.Error != "" {
		return nil, addr, errors.New(nonceResp.Error)
	}

	sig, err := auth.SignPersonalMessage(priv, nonceResp.Message)
	if err != nil {
		return nil, addr, err
	}
	credBytes, _ := json.Marshal(auth.TokenPayload{
		Address:   addr,
		Nonce:     nonceResp.Nonce,
		Signature: sig,
	})

	nc, err := nats.Connect(clientURL, nats.Token(string(credBytes)))
	return nc, addr, err
}

func TestAuthCalloutPermissionsAndRPCEnforcement(t *testing.T) {
	cfg := config.Default()
	cfg.Host = "127.0.0.1"
	cfg.Port = -1
	cfg.WSPort = -1
	cfg.HTTPPort = -1
	cfg.DataDir = t.TempDir()

	validator := &stubValidator{
		state: rpc.AccountState{
			BalanceLatest:   rpc.RogueToWei(5),
			BalanceLookback: rpc.RogueToWei(5),
			MinerLevel:      0,
		},
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	srv, err := server.NewWithValidator(cfg, validator, logger)
	if err != nil {
		t.Fatalf("NewWithValidator: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Shutdown()

	priv, _ := secp256k1.GeneratePrivateKey()
	nc, addr, err := connectAuthenticatedClient(t, srv.ClientURL(), priv)
	if err != nil {
		t.Fatalf("connectAuthenticatedClient: %v", err)
	}
	defer nc.Close()

	// Verify profile + secp256k1 pubkey saved in ROGUE_PROFILES.
	js, err := srv.JetStream()
	if err != nil {
		t.Fatalf("JetStream: %v", err)
	}
	profilesKV, err := js.KeyValue(store.BucketProfiles)
	if err != nil {
		t.Fatalf("KeyValue(ROGUE_PROFILES): %v", err)
	}
	entry, err := profilesKV.Get(addr)
	if err != nil {
		t.Fatalf("expected profile in ROGUE_PROFILES: %v", err)
	}
	var prof auth.ProfileRecord
	if err := json.Unmarshal(entry.Value(), &prof); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	if prof.Address != addr || !strings.HasPrefix(prof.PubKey, "0x") {
		t.Fatalf("unexpected profile: %+v", prof)
	}

	// Anti-spoofing: allowed to publish to own ingress, denied to another address or direct chat stream.
	if err := nc.Publish("rogue.in."+addr+".chat.general", []byte(`{"text":"ok"}`)); err != nil {
		t.Fatalf("expected own ingress publish to succeed: %v", err)
	}
	if err := nc.Flush(); err != nil {
		t.Fatalf("flush own ingress: %v", err)
	}

	// Authenticated client must be able to write its own presence and list KV keys (ephemeral consumer creation).
	clientJS, err := nc.JetStream()
	if err != nil {
		t.Fatalf("client JetStream: %v", err)
	}
	presKV, err := clientJS.KeyValue(store.BucketPresence)
	if err != nil {
		t.Fatalf("KeyValue(ROGUE_PRESENCE): %v", err)
	}
	if _, err := presKV.Put(addr, []byte(`{"address":"`+addr+`","active_room":"general","level":0,"updated_at":1}`)); err != nil {
		t.Fatalf("presence Put: %v", err)
	}
	pKeys, err := presKV.Keys()
	if err != nil {
		t.Fatalf("presence Keys: %v", err)
	}
	if len(pKeys) != 1 || pKeys[0] != addr {
		t.Fatalf("unexpected presence keys: %v", pKeys)
	}
	chKV, err := js.KeyValue(store.BucketChannels)
	if err != nil {
		t.Fatalf("KeyValue(ROGUE_CHANNELS): %v", err)
	}
	cKeys, err := chKV.Keys()
	if err != nil {
		t.Fatalf("channels Keys: %v", err)
	}
	if len(cKeys) == 0 {
		t.Fatal("expected default channels in ROGUE_CHANNELS")
	}

	// Permission errors in NATS are reported asynchronously via ErrorHandler on Flush.
	errCh := make(chan error, 2)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		errCh <- err
	})
	_ = nc.Publish("rogue.in.0x0000000000000000000000000000000000000001.chat.general", []byte(`{}`))
	_ = nc.Flush()
	select {
	case permErr := <-errCh:
		if !strings.Contains(permErr.Error(), "Permissions Violation") {
			t.Fatalf("expected Permissions Violation, got %v", permErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for spoofed publish permission violation")
	}

	// Lv.0 user must be denied subscription to gated channel #hash-wardens.
	_, _ = nc.Subscribe("rogue.gated.hash-wardens.msg", func(_ *nats.Msg) {})
	_ = nc.Flush()
	select {
	case permErr := <-errCh:
		if !strings.Contains(permErr.Error(), "Permissions Violation") {
			t.Fatalf("expected Permissions Violation on gated sub, got %v", permErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for gated sub permission violation")
	}

	// Promote user to Lv.3 and verify gated subscription succeeds.
	validator.state.MinerLevel = 3
	ncLv3, _, err := connectAuthenticatedClient(t, srv.ClientURL(), priv)
	if err != nil {
		t.Fatalf("connectAuthenticatedClient Lv.3: %v", err)
	}
	defer ncLv3.Close()
	lv3ErrCh := make(chan error, 1)
	ncLv3.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		lv3ErrCh <- err
	})
	if _, err := ncLv3.Subscribe("rogue.gated.hash-wardens.msg", func(_ *nats.Msg) {}); err != nil {
		t.Fatalf("Lv.3 subscribe gated: %v", err)
	}
	_ = ncLv3.Flush()
	select {
	case e := <-lv3ErrCh:
		t.Fatalf("did not expect permission error for Lv.3 user: %v", e)
	case <-time.After(150 * time.Millisecond):
	}

	// Insufficient lookback balance must be rejected.
	validator.state.BalanceLookback = rpc.RogueToWei(0.5)
	if _, _, err := connectAuthenticatedClient(t, srv.ClientURL(), priv); err == nil {
		t.Fatal("expected auth rejection when lookback balance is below minimum")
	}

	// Strict RPC failure must reject auth.
	validator.state.BalanceLookback = rpc.RogueToWei(10)
	validator.err = errors.New("rpc timeout")
	if _, _, err := connectAuthenticatedClient(t, srv.ClientURL(), priv); err == nil {
		t.Fatal("expected auth rejection when RPC fails")
	}
}
