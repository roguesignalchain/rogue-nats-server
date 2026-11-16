package server_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	"github.com/roguesignalchain/rogue-nats-server/internal/rpc"
	"github.com/roguesignalchain/rogue-nats-server/internal/server"
	"github.com/roguesignalchain/rogue-nats-server/internal/store"
)

type stubValidator struct {
	state rpc.AccountState
	err   error
}

func (s *stubValidator) VerifyAccount(_ context.Context, addr string) (rpc.AccountState, error) {
	if s.err != nil {
		return rpc.AccountState{}, s.err
	}
	st := s.state
	st.Address = addr
	return st, nil
}

func TestServerBootstrapAndMonitoring(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.Default()
	cfg.Host = "127.0.0.1"
	cfg.Port = -1     // random available port
	cfg.WSPort = -1   // random available port
	cfg.HTTPPort = -1 // random available port
	cfg.DataDir = dataDir

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	validator := &stubValidator{
		state: rpc.AccountState{
			BalanceLatest:   rpc.RogueToWei(10),
			BalanceLookback: rpc.RogueToWei(10),
			MinerLevel:      1,
		},
	}
	srv, err := server.NewWithValidator(cfg, validator, logger)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("srv.Start: %v", err)
	}
	defer srv.Shutdown()

	firstAccountPub := srv.Keys().AccountPub
	if firstAccountPub == "" {
		t.Fatal("expected non-empty account public key")
	}

	js, err := srv.JetStream()
	if err != nil {
		t.Fatalf("srv.JetStream: %v", err)
	}

	for _, streamName := range []string{store.StreamChat, store.StreamGated, store.StreamDM} {
		if _, err := js.StreamInfo(streamName); err != nil {
			t.Fatalf("expected stream %s to exist: %v", streamName, err)
		}
	}

	for _, bucket := range []string{
		store.BucketChannels,
		store.BucketPresence,
		store.BucketProfiles,
		store.BucketBans,
		store.BucketMutes,
	} {
		if _, err := js.KeyValue(bucket); err != nil {
			t.Fatalf("expected KV bucket %s to exist: %v", bucket, err)
		}
	}

	channelsKV, err := js.KeyValue(store.BucketChannels)
	if err != nil {
		t.Fatalf("KeyValue(ROGUE_CHANNELS): %v", err)
	}

	for _, name := range []string{"announcements", "general", "hash-wardens"} {
		entry, err := channelsKV.Get(name)
		if err != nil {
			t.Fatalf("expected default channel %s: %v", name, err)
		}
		var meta store.ChannelMeta
		if err := json.Unmarshal(entry.Value(), &meta); err != nil {
			t.Fatalf("unmarshal channel %s: %v", name, err)
		}
		if name == "hash-wardens" && (!meta.Gated || meta.MinLevel != 3) {
			t.Fatalf("expected hash-wardens to be gated Lv.3, got %+v", meta)
		}
		if name == "announcements" && !meta.AdminOnlyWrite {
			t.Fatalf("expected announcements to be admin-only write, got %+v", meta)
		}
	}

	httpURL := srv.HTTPURL()
	if httpURL == "" {
		t.Fatal("expected HTTP monitoring URL")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	for _, endpoint := range []string{"/healthz", "/varz"} {
		resp, err := client.Get(httpURL + endpoint)
		if err != nil {
			t.Fatalf("GET %s: %v", endpoint, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", endpoint, resp.StatusCode)
		}
	}

	// Verify NKey persistence across restarts.
	srv.Shutdown()
	cancel()

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	srv2, err := server.NewWithValidator(cfg, validator, logger)
	if err != nil {
		t.Fatalf("server.New restart: %v", err)
	}
	if err := srv2.Start(ctx2); err != nil {
		t.Fatalf("srv2.Start: %v", err)
	}
	defer srv2.Shutdown()

	if srv2.Keys().AccountPub != firstAccountPub {
		t.Fatalf("account key changed across restart: %s != %s", srv2.Keys().AccountPub, firstAccountPub)
	}
}
