package cli_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/roguesignalchain/rogue-nats-server/internal/auth"
	"github.com/roguesignalchain/rogue-nats-server/internal/cli"
	"github.com/roguesignalchain/rogue-nats-server/internal/client"
	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	"github.com/roguesignalchain/rogue-nats-server/internal/rpc"
	"github.com/roguesignalchain/rogue-nats-server/internal/server"
)

type cliMockValidator struct {
	mu     sync.RWMutex
	states map[string]rpc.AccountState
}

func (m *cliMockValidator) set(addr string, rogue float64, level uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	w := rpc.RogueToWei(rogue)
	m.states[strings.ToLower(addr)] = rpc.AccountState{
		Address:         strings.ToLower(addr),
		BalanceLatest:   new(big.Int).Set(w),
		BalanceLookback: new(big.Int).Set(w),
		MinerLevel:      level,
	}
}

func (m *cliMockValidator) VerifyAccount(_ context.Context, addr string) (rpc.AccountState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if st, ok := m.states[strings.ToLower(addr)]; ok {
		return st, nil
	}
	return rpc.AccountState{
		Address:         strings.ToLower(addr),
		BalanceLatest:   big.NewInt(0),
		BalanceLookback: big.NewInt(0),
	}, nil
}

func TestCLIE2EAgentWorkflowsAndExitCodes(t *testing.T) {
	alicePriv, _ := secp256k1.GeneratePrivateKey()
	aliceKeyHex := "0x" + hex.EncodeToString(alicePriv.Serialize())
	aliceAddr := auth.PubKeyToAddress(alicePriv.PubKey())

	bobPriv, _ := secp256k1.GeneratePrivateKey()
	bobKeyHex := "0x" + hex.EncodeToString(bobPriv.Serialize())
	bobAddr := auth.PubKeyToAddress(bobPriv.PubKey())

	brokePriv, _ := secp256k1.GeneratePrivateKey()
	brokeKeyHex := "0x" + hex.EncodeToString(brokePriv.Serialize())

	cfg := config.Default()
	cfg.Host = "127.0.0.1"
	cfg.Port = -1
	cfg.WSPort = -1
	cfg.HTTPPort = -1
	cfg.DataDir = t.TempDir()
	cfg.AdminAddresses = []string{aliceAddr}

	val := &cliMockValidator{states: make(map[string]rpc.AccountState)}
	val.set(aliceAddr, 100, 3)
	val.set(bobAddr, 5, 0)

	srv, err := server.NewWithValidator(cfg, val, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewWithValidator: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Shutdown()

	srvURL := srv.ClientURL()

	// 1. Broke agent fails with ExitAuthOrBalance (2).
	var out, errOut bytes.Buffer
	code := cli.Run([]string{"rooms", "--server", srvURL, "--key", brokeKeyHex, "--json"}, &out, &errOut)
	if code != client.ExitAuthOrBalance {
		t.Fatalf("expected ExitAuthOrBalance (%d), got %d (stderr: %s)", client.ExitAuthOrBalance, code, errOut.String())
	}

	// 2. Bob registers his pubkey by running rooms, then tries sending a restricted link -> ExitGatekeeperRejected (3).
	out.Reset()
	errOut.Reset()
	if code := cli.Run([]string{"rooms", "--server", srvURL, "--key", bobKeyHex, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("bob rooms failed (%d): %s", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	code = cli.Run([]string{"send", "--server", srvURL, "--key", bobKeyHex, "--room", "general", "--json", "https://example.com"}, &out, &errOut)
	if code != client.ExitGatekeeperRejected {
		t.Fatalf("expected ExitGatekeeperRejected (%d), got %d (stderr: %s)", client.ExitGatekeeperRejected, code, errOut.String())
	}

	// 3. Alice sends a message and reads it back with --json.
	out.Reset()
	errOut.Reset()
	if code := cli.Run([]string{"send", "--server", srvURL, "--key", aliceKeyHex, "--room", "general", "--json", "agent-online"}, &out, &errOut); code != 0 {
		t.Fatalf("alice send failed (%d): %s", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := cli.Run([]string{"read", "--server", srvURL, "--key", aliceKeyHex, "--room", "general", "--limit", "200", "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("alice read failed (%d): %s", code, errOut.String())
	}
	var readResp struct {
		Count    int `json:"count"`
		Messages []struct {
			Text         string `json:"text"`
			TimestampISO string `json:"timestamp_iso"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out.Bytes(), &readResp); err != nil {
		t.Fatalf("unmarshal read JSON: %v (%s)", err, out.String())
	}
	if readResp.Count != 1 || readResp.Messages[0].Text != "agent-online" || readResp.Messages[0].TimestampISO == "" {
		t.Fatalf("unexpected read output: %+v", readResp)
	}

	// 4. Alice sends E2EE DM to Bob, Bob reads and decrypts it automatically.
	out.Reset()
	errOut.Reset()
	if code := cli.Run([]string{"dm", "send", "--server", srvURL, "--key", aliceKeyHex, "--to", bobAddr, "--json", "hello-e2ee"}, &out, &errOut); code != 0 {
		t.Fatalf("dm send failed (%d): %s", code, errOut.String())
	}

	out.Reset()
	errOut.Reset()
	if code := cli.Run([]string{"dm", "read", "--server", srvURL, "--key", bobKeyHex, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("dm read failed (%d): %s", code, errOut.String())
	}
	var dmResp struct {
		Count    int `json:"count"`
		Messages []struct {
			Sender string `json:"sender"`
			Text   string `json:"text"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(out.Bytes(), &dmResp); err != nil {
		t.Fatalf("unmarshal dm read JSON: %v", err)
	}
	if dmResp.Count != 1 || dmResp.Messages[0].Sender != aliceAddr || dmResp.Messages[0].Text != "hello-e2ee" {
		t.Fatalf("unexpected dm read output: %+v", dmResp)
	}

	// 5. Admin stats works for Alice (admin).
	out.Reset()
	errOut.Reset()
	if code := cli.Run([]string{"admin", "stats", "--server", srvURL, "--key", aliceKeyHex, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("admin stats failed (%d): %s", code, errOut.String())
	}
}
