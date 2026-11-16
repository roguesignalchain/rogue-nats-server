package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	"github.com/roguesignalchain/rogue-nats-server/internal/keys"
	"github.com/roguesignalchain/rogue-nats-server/internal/rpc"
	"github.com/roguesignalchain/rogue-nats-server/internal/store"
)

const (
	// ChallengeToken is sent by clients in ConnectOptions.Token to request a single-use nonce.
	ChallengeToken = "challenge"
	// SessionTTL is the lifetime of an issued NATS user JWT before transparent re-auth.
	SessionTTL = 15 * time.Minute
	// NonceTTL is the lifetime of an issued authentication challenge.
	NonceTTL = 60 * time.Second
)

// ProfileRecord is stored in ROGUE_PROFILES for each authenticated 0x address.
type ProfileRecord struct {
	Address    string `json:"address"`
	PubKey     string `json:"pubkey"`
	MinerLevel uint32 `json:"miner_level"`
	UpdatedAt  int64  `json:"updated_at"`
}

// TokenPayload is the JSON credential sent by clients/agents in ConnectOptions.Token.
type TokenPayload struct {
	Address   string `json:"address"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// NonceRequest is sent to rogue.auth.nonce.
type NonceRequest struct {
	Address string `json:"address"`
}

// NonceResponse is returned by rogue.auth.nonce.
type NonceResponse struct {
	Nonce     string `json:"nonce,omitempty"`
	Message   string `json:"message,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Service handles NATS Auth Callout ($SYS.REQ.USER.AUTH) and nonce issuance (rogue.auth.nonce).
type Service struct {
	cfg        config.Config
	keys       *keys.OperatorKeys
	validator  rpc.ChainValidator
	nonces     *NonceStore
	js         nats.JetStreamContext
	nc         *nats.Conn
	logger     *slog.Logger
	subs       []*nats.Subscription
	adminSet   map[string]struct{}
}

// NewService constructs an Auth Callout service.
func NewService(cfg config.Config, opKeys *keys.OperatorKeys, validator rpc.ChainValidator, js nats.JetStreamContext, nc *nats.Conn, logger *slog.Logger) *Service {
	admins := make(map[string]struct{}, len(cfg.AdminAddresses))
	for _, a := range cfg.AdminAddresses {
		admins[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}
	return &Service{
		cfg:       cfg,
		keys:      opKeys,
		validator: validator,
		nonces:    NewNonceStore(NonceTTL),
		js:        js,
		nc:        nc,
		logger:    logger,
		adminSet:  admins,
	}
}

// Start subscribes to nonce requests and NATS auth callout requests.
func (s *Service) Start() error {
	nonceSub, err := s.nc.Subscribe("rogue.auth.nonce", s.handleNonceRequest)
	if err != nil {
		return fmt.Errorf("subscribe rogue.auth.nonce: %w", err)
	}
	authSub, err := s.nc.Subscribe("$SYS.REQ.USER.AUTH", s.handleAuthRequest)
	if err != nil {
		_ = nonceSub.Unsubscribe()
		return fmt.Errorf("subscribe $SYS.REQ.USER.AUTH: %w", err)
	}
	s.subs = append(s.subs, nonceSub, authSub)
	return s.nc.Flush()
}

// Stop unsubscribes internal auth handlers.
func (s *Service) Stop() {
	for _, sub := range s.subs {
		_ = sub.Unsubscribe()
	}
	s.subs = nil
}

func (s *Service) handleNonceRequest(msg *nats.Msg) {
	var req NonceRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.replyJSON(msg, NonceResponse{Error: "invalid nonce request"})
		return
	}
	addr := strings.ToLower(strings.TrimSpace(req.Address))
	if !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
		s.replyJSON(msg, NonceResponse{Error: "invalid 0x address"})
		return
	}
	nonce, exp, err := s.nonces.Issue(addr)
	if err != nil {
		s.replyJSON(msg, NonceResponse{Error: "failed to issue nonce"})
		return
	}
	s.replyJSON(msg, NonceResponse{
		Nonce:     nonce,
		Message:   BuildChallengeMessage(s.cfg.ChainID, addr, nonce),
		ExpiresAt: exp.UnixMilli(),
	})
}

func (s *Service) handleAuthRequest(msg *nats.Msg) {
	req, err := jwt.DecodeAuthorizationRequestClaims(string(msg.Data))
	if err != nil {
		s.logger.Warn("failed to decode auth callout request", "error", err)
		return
	}

	resp := jwt.NewAuthorizationResponseClaims(req.UserNkey)
	resp.Audience = req.Server.ID

	token := strings.TrimSpace(req.ConnectOptions.Token)
	if token == ChallengeToken {
		userJWT, err := s.issueChallengeGuestJWT(req.UserNkey)
		if err != nil {
			resp.Error = err.Error()
		} else {
			resp.Jwt = userJWT
		}
		s.sendAuthResponse(msg, resp)
		return
	}

	userJWT, err := s.authenticateToken(req.UserNkey, token)
	if err != nil {
		resp.Error = err.Error()
		s.logger.Info("auth rejected", "reason", err.Error())
	} else {
		resp.Jwt = userJWT
	}
	s.sendAuthResponse(msg, resp)
}

func (s *Service) issueChallengeGuestJWT(userNkey string) (string, error) {
	uc := jwt.NewUserClaims(userNkey)
	uc.Name = "challenge-guest"
	uc.Audience = "ROGUE"
	uc.Expires = time.Now().UTC().Add(30 * time.Second).Unix()
	uc.Pub.Allow.Add("rogue.auth.nonce")
	uc.Sub.Allow.Add("_INBOX.>")
	return uc.Encode(s.keys.AccountKP)
}

func (s *Service) authenticateToken(userNkey, rawToken string) (string, error) {
	var cred TokenPayload
	if err := json.Unmarshal([]byte(rawToken), &cred); err != nil {
		return "", errors.New("invalid auth token payload")
	}

	addr := strings.ToLower(strings.TrimSpace(cred.Address))
	if !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
		return "", errors.New("invalid 0x address")
	}
	if !s.nonces.Consume(addr, cred.Nonce) {
		return "", errors.New("invalid or expired nonce")
	}

	challengeMsg := BuildChallengeMessage(s.cfg.ChainID, addr, cred.Nonce)
	pubKeyHex, err := VerifyPersonalSignature(addr, challengeMsg, cred.Signature)
	if err != nil {
		return "", fmt.Errorf("signature verification failed: %w", err)
	}

	// Reject banned addresses immediately.
	if banned, err := s.isBanned(addr); err != nil {
		return "", fmt.Errorf("ban check failed: %w", err)
	} else if banned {
		return "", errors.New("address is banned")
	}

	// Strict on-chain RPC check (latest + lookback balance + MinerLevel).
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	state, err := s.validator.VerifyAccount(ctx, addr)
	if err != nil {
		return "", fmt.Errorf("rpc validation unavailable: %w", err)
	}

	minWei := rpc.RogueToWei(s.cfg.MinBalanceChat)
	if state.BalanceLatest.Cmp(minWei) < 0 || state.BalanceLookback.Cmp(minWei) < 0 {
		return "", fmt.Errorf("insufficient mature balance: minimum %.4f ROGUE required for %d blocks", s.cfg.MinBalanceChat, s.cfg.LookbackBlocks)
	}

	if err := s.upsertProfile(addr, pubKeyHex, state.MinerLevel); err != nil {
		s.logger.Warn("failed to update profile in ROGUE_PROFILES", "address", addr, "error", err)
	}

	uc := jwt.NewUserClaims(userNkey)
	uc.Name = addr
	uc.Audience = "ROGUE"
	uc.Expires = time.Now().UTC().Add(SessionTTL).Unix()

	// Protocol-level anti-spoofing: user can only publish to their own ingress namespace.
	uc.Pub.Allow.Add(
		fmt.Sprintf("rogue.in.%s.>", addr),
		"_INBOX.>",
		"$JS.API.INFO",
		fmt.Sprintf("$JS.API.STREAM.INFO.%s", store.StreamChat),
		fmt.Sprintf("$JS.API.STREAM.MSG.GET.%s", store.StreamChat),
		fmt.Sprintf("$JS.API.STREAM.INFO.%s", store.StreamDM),
		fmt.Sprintf("$JS.API.STREAM.MSG.GET.%s", store.StreamDM),
		"$KV.ROGUE_CHANNELS.>",
		"$KV.ROGUE_PRESENCE.>",
		"$KV.ROGUE_PROFILES.>",
	)
	uc.Sub.Allow.Add(
		"rogue.chat.*.msg",
		"rogue.chat.*.delete",
		fmt.Sprintf("rogue.dm.%s", addr),
		fmt.Sprintf("rogue.err.%s", addr),
		"_INBOX.>",
		"$KV.ROGUE_CHANNELS.>",
		"$KV.ROGUE_PRESENCE.>",
		"$KV.ROGUE_PROFILES.>",
	)

	// Grant gated stream/channel subscriptions only if the user meets MinLevel (or is admin).
	_, isAdmin := s.adminSet[addr]
	gatedChannels, err := s.eligibleGatedChannels(state.MinerLevel, isAdmin)
	if err != nil {
		return "", fmt.Errorf("load gated channels: %w", err)
	}
	if len(gatedChannels) > 0 {
		uc.Pub.Allow.Add(
			fmt.Sprintf("$JS.API.STREAM.INFO.%s", store.StreamGated),
			fmt.Sprintf("$JS.API.STREAM.MSG.GET.%s", store.StreamGated),
		)
		for _, ch := range gatedChannels {
			uc.Sub.Allow.Add(
				fmt.Sprintf("rogue.gated.%s.msg", ch),
				fmt.Sprintf("rogue.gated.%s.delete", ch),
			)
		}
	}

	return uc.Encode(s.keys.AccountKP)
}

func (s *Service) isBanned(addr string) (bool, error) {
	kv, err := s.js.KeyValue(store.BucketBans)
	if err != nil {
		return false, err
	}
	_, err = kv.Get(addr)
	if errors.Is(err, nats.ErrKeyNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (s *Service) upsertProfile(addr, pubKeyHex string, level uint32) error {
	kv, err := s.js.KeyValue(store.BucketProfiles)
	if err != nil {
		return err
	}
	rec := ProfileRecord{
		Address:    addr,
		PubKey:     pubKeyHex,
		MinerLevel: level,
		UpdatedAt:  time.Now().UTC().UnixMilli(),
	}
	payload, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = kv.Put(addr, payload)
	return err
}

func (s *Service) eligibleGatedChannels(level uint32, isAdmin bool) ([]string, error) {
	kv, err := s.js.KeyValue(store.BucketChannels)
	if err != nil {
		return nil, err
	}
	keys, err := kv.Keys(nats.IgnoreDeletes())
	if errors.Is(err, nats.ErrNoKeysFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var allowed []string
	for _, k := range keys {
		entry, err := kv.Get(k)
		if err != nil {
			continue
		}
		var meta store.ChannelMeta
		if err := json.Unmarshal(entry.Value(), &meta); err != nil {
			continue
		}
		if meta.Gated && (isAdmin || level >= meta.MinLevel) {
			allowed = append(allowed, meta.Name)
		}
	}
	return allowed, nil
}

func (s *Service) sendAuthResponse(msg *nats.Msg, resp *jwt.AuthorizationResponseClaims) {
	encoded, err := resp.Encode(s.keys.AccountKP)
	if err != nil {
		s.logger.Error("encode auth response", "error", err)
		return
	}
	if err := msg.Respond([]byte(encoded)); err != nil {
		s.logger.Warn("respond auth callout", "error", err)
	}
}

func (s *Service) replyJSON(msg *nats.Msg, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = msg.Respond(data)
}

// SignNKeyHelper builds a nats.SignatureHandler for an NKeyPair.
func SignNKeyHelper(kp nkeys.KeyPair) nats.SignatureHandler {
	return func(nonce []byte) ([]byte, error) {
		return kp.Sign(nonce)
	}
}
