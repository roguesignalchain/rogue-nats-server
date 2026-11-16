package rpc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/sha3"
)

const (
	// ReputationContract is the RogueMinerReputation system contract deployed at Block 0.
	ReputationContract = "0x0000000000000000000000000000000000000020"
)

// AccountState holds on-chain balance and miner reputation data for a 0x address.
type AccountState struct {
	Address         string   `json:"address"`
	BalanceLatest   *big.Int `json:"balance_latest"`
	BalanceLookback *big.Int `json:"balance_lookback"`
	MinerLevel      uint32   `json:"miner_level"`
	CheckedAt       int64    `json:"checked_at"`
}

// ChainValidator verifies an address against Rogue Signal on-chain state.
type ChainValidator interface {
	VerifyAccount(ctx context.Context, address string) (AccountState, error)
}

// JSONRPCClient queries a Rogue Signal EVM JSON-RPC endpoint.
type JSONRPCClient struct {
	endpoint       string
	lookbackBlocks uint64
	httpClient     *http.Client
	reqID          atomic.Uint64
	levelSelector  string
}

// NewJSONRPCClient creates a JSON-RPC validator client with strict timeouts.
func NewJSONRPCClient(endpoint string, lookbackBlocks uint64) *JSONRPCClient {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("getMinerLevel(address)"))
	selector := "0x" + hex.EncodeToString(h.Sum(nil)[:4])

	return &JSONRPCClient{
		endpoint:       endpoint,
		lookbackBlocks: lookbackBlocks,
		httpClient:     &http.Client{Timeout: 5 * time.Second},
		levelSelector:  selector,
	}
}

// VerifyAccount fetches latest balance, historical lookback balance, and RogueMinerReputation level.
func (c *JSONRPCClient) VerifyAccount(ctx context.Context, address string) (AccountState, error) {
	addr := strings.ToLower(strings.TrimSpace(address))
	if !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
		return AccountState{}, fmt.Errorf("invalid 0x address: %s", address)
	}

	latestHex, err := c.callString(ctx, "eth_blockNumber", nil)
	if err != nil {
		return AccountState{}, fmt.Errorf("eth_blockNumber: %w", err)
	}
	latestBlock, err := parseHexUint64(latestHex)
	if err != nil {
		return AccountState{}, fmt.Errorf("parse block number: %w", err)
	}

	var lookbackBlock uint64
	if latestBlock > c.lookbackBlocks {
		lookbackBlock = latestBlock - c.lookbackBlocks
	}
	lookbackHex := fmt.Sprintf("0x%x", lookbackBlock)

	balLatestHex, err := c.callString(ctx, "eth_getBalance", []any{addr, "latest"})
	if err != nil {
		return AccountState{}, fmt.Errorf("eth_getBalance(latest): %w", err)
	}
	balLatest, err := parseHexBigInt(balLatestHex)
	if err != nil {
		return AccountState{}, fmt.Errorf("parse latest balance: %w", err)
	}

	balLookbackHex, err := c.callString(ctx, "eth_getBalance", []any{addr, lookbackHex})
	if err != nil {
		return AccountState{}, fmt.Errorf("eth_getBalance(lookback): %w", err)
	}
	balLookback, err := parseHexBigInt(balLookbackHex)
	if err != nil {
		return AccountState{}, fmt.Errorf("parse lookback balance: %w", err)
	}

	// ABI encode getMinerLevel(address): 4-byte selector + 32-byte left-padded address.
	callData := c.levelSelector + strings.Repeat("0", 24) + strings.TrimPrefix(addr, "0x")
	levelHex, err := c.callString(ctx, "eth_call", []any{
		map[string]string{
			"to":   ReputationContract,
			"data": callData,
		},
		"latest",
	})
	if err != nil {
		return AccountState{}, fmt.Errorf("eth_call(getMinerLevel): %w", err)
	}
	levelBig, err := parseHexBigInt(levelHex)
	if err != nil {
		return AccountState{}, fmt.Errorf("parse miner level: %w", err)
	}

	return AccountState{
		Address:         addr,
		BalanceLatest:   balLatest,
		BalanceLookback: balLookback,
		MinerLevel:      uint32(levelBig.Uint64()),
		CheckedAt:       time.Now().UTC().UnixMilli(),
	}, nil
}

// RogueToWei converts a whole or fractional ROGUE amount to Wei (10^18).
func RogueToWei(rogue float64) *big.Int {
	if rogue <= 0 {
		return big.NewInt(0)
	}
	f := new(big.Float).SetFloat64(rogue)
	scale := new(big.Float).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	f.Mul(f, scale)
	wei, _ := f.Int(nil)
	return wei
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      uint64 `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      uint64          `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (c *JSONRPCClient) callString(ctx context.Context, method string, params any) (string, error) {
	if params == nil {
		params = []any{}
	}
	payload, err := json.Marshal(rpcRequest{
		JSONRPC: "2.0",
		ID:      c.reqID.Add(1),
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("http status %d", resp.StatusCode)
	}

	var out rpcResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.Error != nil {
		return "", fmt.Errorf("rpc error %d: %s", out.Error.Code, out.Error.Message)
	}

	var str string
	if err := json.Unmarshal(out.Result, &str); err != nil {
		return "", err
	}
	return str, nil
}

func parseHexUint64(hexStr string) (uint64, error) {
	bi, err := parseHexBigInt(hexStr)
	if err != nil {
		return 0, err
	}
	return bi.Uint64(), nil
}

func parseHexBigInt(hexStr string) (*big.Int, error) {
	clean := strings.TrimPrefix(strings.TrimSpace(hexStr), "0x")
	if clean == "" {
		return big.NewInt(0), nil
	}
	bi, ok := new(big.Int).SetString(clean, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex integer: %s", hexStr)
	}
	return bi, nil
}
