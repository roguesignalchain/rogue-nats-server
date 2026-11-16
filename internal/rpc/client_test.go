package rpc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/roguesignalchain/rogue-nats-server/internal/rpc"
)

func TestJSONRPCClientVerifyAccount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     uint64            `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode rpc req: %v", err)
		}

		var result any
		switch req.Method {
		case "eth_blockNumber":
			result = "0x100" // 256
		case "eth_getBalance":
			// Return 5 ROGUE in Wei (5 * 10^18 = 0x4563918244f40000)
			result = "0x4563918244f40000"
		case "eth_call":
			// Return uint32(4) ABI encoded
			result = "0x0000000000000000000000000000000000000000000000000000000000000004"
		default:
			t.Fatalf("unexpected method: %s", req.Method)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      req.ID,
			"result":  result,
		})
	}))
	defer srv.Close()

	client := rpc.NewJSONRPCClient(srv.URL, 120)
	state, err := client.VerifyAccount(context.Background(), "0xe9aaE535B7971A9AC8C6af0e4B524D02260D3a03")
	if err != nil {
		t.Fatalf("VerifyAccount: %v", err)
	}
	if state.MinerLevel != 4 {
		t.Fatalf("MinerLevel = %d, want 4", state.MinerLevel)
	}
	expectedWei := rpc.RogueToWei(5)
	if state.BalanceLatest.Cmp(expectedWei) != 0 || state.BalanceLookback.Cmp(expectedWei) != 0 {
		t.Fatalf("unexpected balances: latest=%s lookback=%s", state.BalanceLatest, state.BalanceLookback)
	}

	// Strict failure when RPC is down.
	srv.Close()
	if _, err := client.VerifyAccount(context.Background(), "0xe9aaE535B7971A9AC8C6af0e4B524D02260D3a03"); err == nil {
		t.Fatal("expected strict error when RPC server is unreachable")
	}
}
