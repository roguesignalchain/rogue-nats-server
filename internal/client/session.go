package client

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nats-io/nats.go"
	"github.com/roguesignalchain/rogue-nats-server/internal/auth"
	"github.com/roguesignalchain/rogue-nats-server/internal/gatekeeper"
)

// Standard UNIX exit codes for agent automation.
const (
	ExitOK                 = 0
	ExitNetworkOrError     = 1
	ExitAuthOrBalance      = 2
	ExitGatekeeperRejected = 3
)

// ExitError wraps an error with a deterministic CLI exit code.
type ExitError struct {
	Code    int
	ErrCode string
	Message string
}

func (e *ExitError) Error() string {
	if e.ErrCode != "" {
		return fmt.Sprintf("%s: %s", e.ErrCode, e.Message)
	}
	return e.Message
}

// Session represents an authenticated NATS connection bound to a 0x secp256k1 key.
type Session struct {
	ServerURL string
	ChainID   uint64
	PrivKey   *secp256k1.PrivateKey
	Address   string
	NC        *nats.Conn
	JS        nats.JetStreamContext
}

// LoadPrivateKey resolves a secp256k1 private key from an explicit hex/path string or env vars.
func LoadPrivateKey(keySpec string) (*secp256k1.PrivateKey, error) {
	spec := strings.TrimSpace(keySpec)
	if spec == "" {
		spec = strings.TrimSpace(os.Getenv("ROGUE_PRIVATE_KEY"))
	}
	if spec == "" {
		if path := strings.TrimSpace(os.Getenv("ROGUE_KEY_FILE")); path != "" {
			spec = path
		}
	}
	if spec == "" {
		return nil, &ExitError{Code: ExitAuthOrBalance, ErrCode: "ERR_NO_KEY", Message: "private key required (--key, ROGUE_PRIVATE_KEY, or ROGUE_KEY_FILE)"}
	}

	if info, err := os.Stat(spec); err == nil && !info.IsDir() {
		raw, err := os.ReadFile(spec)
		if err != nil {
			return nil, &ExitError{Code: ExitAuthOrBalance, ErrCode: "ERR_KEY_READ", Message: err.Error()}
		}
		spec = strings.TrimSpace(string(raw))
	}

	rawHex := strings.TrimPrefix(spec, "0x")
	b, err := hex.DecodeString(rawHex)
	if err != nil || len(b) != 32 {
		return nil, &ExitError{Code: ExitAuthOrBalance, ErrCode: "ERR_INVALID_KEY", Message: "private key must be 32-byte hex"}
	}
	return secp256k1.PrivKeyFromBytes(b), nil
}

// Connect authenticates against rogue-nats-server using EIP-191 challenge-response
// and caches per-address session metadata under the user's cache directory.
func Connect(serverURL string, chainID uint64, priv *secp256k1.PrivateKey) (*Session, error) {
	addr := auth.PubKeyToAddress(priv.PubKey())
	token, err := signChallenge(serverURL, priv, addr)
	if err != nil {
		return nil, err
	}

	nc, err := nats.Connect(
		serverURL,
		nats.Token(token),
		nats.MaxReconnects(5),
		nats.ReconnectWait(500*time.Millisecond),
		nats.CustomReconnectDelay(func(attempts int) time.Duration {
			return time.Duration(attempts) * 500 * time.Millisecond
		}),
	)
	if err != nil {
		return nil, classifyConnectError(err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, &ExitError{Code: ExitNetworkOrError, ErrCode: "ERR_JETSTREAM", Message: err.Error()}
	}

	_ = writeSessionMetadata(addr, serverURL, chainID)

	return &Session{
		ServerURL: serverURL,
		ChainID:   chainID,
		PrivKey:   priv,
		Address:   addr,
		NC:        nc,
		JS:        js,
	}, nil
}

// Close closes the underlying NATS connection.
func (s *Session) Close() {
	if s.NC != nil {
		s.NC.Close()
	}
}

// RequestJSON sends a synchronous Gatekeeper ingress command and decodes CommandResponse.
func (s *Session) RequestJSON(subject string, body any) (gatekeeper.CommandResponse, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return gatekeeper.CommandResponse{}, &ExitError{Code: ExitNetworkOrError, Message: err.Error()}
	}
	msg, err := s.NC.Request(subject, raw, 6*time.Second)
	if err != nil {
		return gatekeeper.CommandResponse{}, &ExitError{Code: ExitNetworkOrError, ErrCode: "ERR_RPC_TIMEOUT", Message: err.Error()}
	}
	var resp gatekeeper.CommandResponse
	if err := json.Unmarshal(msg.Data, &resp); err != nil {
		return gatekeeper.CommandResponse{}, &ExitError{Code: ExitNetworkOrError, Message: err.Error()}
	}
	if !resp.OK {
		code := "ERR_REJECTED"
		msgText := "request rejected"
		if resp.Error != nil {
			code = resp.Error.Code
			msgText = resp.Error.Message
		}
		return resp, &ExitError{Code: ExitGatekeeperRejected, ErrCode: code, Message: msgText}
	}
	return resp, nil
}

func signChallenge(serverURL string, priv *secp256k1.PrivateKey, addr string) (string, error) {
	guestNC, err := nats.Connect(serverURL, nats.Token(auth.ChallengeToken), nats.Timeout(5*time.Second))
	if err != nil {
		return "", &ExitError{Code: ExitNetworkOrError, ErrCode: "ERR_CONNECT", Message: err.Error()}
	}
	defer guestNC.Close()

	reqBytes, _ := json.Marshal(auth.NonceRequest{Address: addr})
	reply, err := guestNC.Request("rogue.auth.nonce", reqBytes, 5*time.Second)
	if err != nil {
		return "", &ExitError{Code: ExitNetworkOrError, ErrCode: "ERR_NONCE", Message: err.Error()}
	}
	var nr auth.NonceResponse
	if err := json.Unmarshal(reply.Data, &nr); err != nil {
		return "", &ExitError{Code: ExitNetworkOrError, Message: err.Error()}
	}
	if nr.Error != "" {
		return "", &ExitError{Code: ExitAuthOrBalance, ErrCode: "ERR_NONCE_REJECTED", Message: nr.Error}
	}

	sig, err := auth.SignPersonalMessage(priv, nr.Message)
	if err != nil {
		return "", &ExitError{Code: ExitAuthOrBalance, ErrCode: "ERR_SIGN", Message: err.Error()}
	}
	cred, _ := json.Marshal(auth.TokenPayload{
		Address:   addr,
		Nonce:     nr.Nonce,
		Signature: sig,
	})
	return string(cred), nil
}

func classifyConnectError(err error) error {
	msg := err.Error()
	if strings.Contains(msg, "Authorization Violation") ||
		strings.Contains(msg, "insufficient") ||
		strings.Contains(msg, "banned") ||
		strings.Contains(msg, "rpc validation") ||
		strings.Contains(msg, "auth callout") {
		return &ExitError{Code: ExitAuthOrBalance, ErrCode: "ERR_AUTH_REJECTED", Message: msg}
	}
	return &ExitError{Code: ExitNetworkOrError, ErrCode: "ERR_CONNECT", Message: msg}
}

func writeSessionMetadata(addr, serverURL string, chainID uint64) error {
	cacheBase, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(cacheBase, "rogue-nats", "sessions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	meta := map[string]any{
		"address":    addr,
		"server_url": serverURL,
		"chain_id":   chainID,
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}
	b, _ := json.MarshalIndent(meta, "", "  ")
	return os.WriteFile(filepath.Join(dir, addr+".json"), b, 0o600)
}

// GenerateRandomHexKey generates a fresh secp256k1 private key hex string (helper for tests/setup).
func GenerateRandomHexKey() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "0x" + hex.EncodeToString(buf), nil
}

// ExitCode extracts the CLI exit code from any error.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return ee.Code
	}
	return ExitNetworkOrError
}
