package gatekeeper

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	rcrypto "github.com/roguesignalchain/rogue-nats-server/internal/crypto"
	"github.com/roguesignalchain/rogue-nats-server/internal/rpc"
	"github.com/roguesignalchain/rogue-nats-server/internal/store"
)

// Error codes returned by the Gatekeeper on rogue.err.<0x> and RPC replies.
const (
	ErrBadRequest             = "ERR_BAD_REQUEST"
	ErrBanned                 = "ERR_BANNED"
	ErrMuted                  = "ERR_MUTED"
	ErrRateLimit              = "ERR_RATE_LIMIT"
	ErrRoomNotFound           = "ERR_ROOM_NOT_FOUND"
	ErrRoomExists             = "ERR_ROOM_EXISTS"
	ErrRoomLimit              = "ERR_ROOM_LIMIT"
	ErrForbidden              = "ERR_FORBIDDEN"
	ErrInsufficientBalance    = "ERR_INSUFFICIENT_BALANCE"
	ErrLinkRestricted         = "ERR_LINK_RESTRICTED"
	ErrInvalidContent         = "ERR_INVALID_CONTENT"
	ErrRecipientPubKeyUnknown = "ERR_RECIPIENT_PUBKEY_UNKNOWN"
	ErrRPCUnavailable         = "ERR_RPC_UNAVAILABLE"
	ErrInternal               = "ERR_INTERNAL"
)

// ErrorEvent is published to rogue.err.<0x> and included in synchronous RPC failures.
type ErrorEvent struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Room    string `json:"room,omitempty"`
	Ts      int64  `json:"ts"`
}

// CommandResponse is the standard envelope returned for Request/Reply calls on rogue.in.<0x>.*.
type CommandResponse struct {
	OK    bool        `json:"ok"`
	Data  any         `json:"data,omitempty"`
	Error *ErrorEvent `json:"error,omitempty"`
}

// ChatMessageInput is sent by clients/agents to rogue.in.<0x>.chat.<room>.
type ChatMessageInput struct {
	Text    string `json:"text"`
	ReplyTo string `json:"reply_to,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

// ChatMessageEnvelope is the v1 validated message stored in ROGUE_CHAT / ROGUE_GATED.
type ChatMessageEnvelope struct {
	V       int    `json:"v"`
	ID      string `json:"id"`
	Seq     uint64 `json:"seq,omitempty"`
	Room    string `json:"room"`
	Sender  string `json:"sender"`
	Level   uint32 `json:"level"`
	Kind    string `json:"kind"`
	Text    string `json:"text"`
	ReplyTo string `json:"reply_to,omitempty"`
	Ts      int64  `json:"ts"`
}

// DeleteMessageEvent is published when a message is physically deleted from JetStream.
type DeleteMessageEvent struct {
	Room      string `json:"room"`
	Seq       uint64 `json:"seq"`
	DeletedBy string `json:"deleted_by"`
	Ts        int64  `json:"ts"`
}

// DMEnvelope is routed to rogue.dm.<dest0x> and stored in ROGUE_DM.
type DMEnvelope struct {
	V       int                      `json:"v"`
	ID      string                   `json:"id"`
	Sender  string                   `json:"sender"`
	Dest    string                   `json:"dest"`
	Ts      int64                    `json:"ts"`
	Payload rcrypto.EncryptedPayload `json:"payload"`
}

// RoomSummary is returned by rogue.in.<0x>.cmd.rooms sorted by pinned then member_count DESC.
type RoomSummary struct {
	store.ChannelMeta
	MemberCount int `json:"member_count"`
}

// PresenceRecord is stored in ROGUE_PRESENCE (30s TTL).
type PresenceRecord struct {
	Address    string `json:"address"`
	ActiveRoom string `json:"active_room"`
	Level      uint32 `json:"level"`
	UpdatedAt  int64  `json:"updated_at"`
}

type muteRecord struct {
	Target  string `json:"target"`
	Room    string `json:"room"`
	By      string `json:"by"`
	Reason  string `json:"reason"`
	UntilTs int64  `json:"until_ts"`
}

type banRecord struct {
	Target string `json:"target"`
	By     string `json:"by"`
	Reason string `json:"reason"`
	Ts     int64  `json:"ts"`
}

// Service validates and routes all client/agent ingress traffic from rogue.in.>.
type Service struct {
	cfg       config.Config
	validator rpc.ChainValidator
	natsSrv   *server.Server
	nc        *nats.Conn
	js        nats.JetStreamContext
	limiter   *RateLimiter
	logger    *slog.Logger
	adminSet  map[string]struct{}
	sub       *nats.Subscription
}

// NewService creates a Gatekeeper service.
func NewService(cfg config.Config, validator rpc.ChainValidator, natsSrv *server.Server, nc *nats.Conn, js nats.JetStreamContext, logger *slog.Logger) *Service {
	admins := make(map[string]struct{}, len(cfg.AdminAddresses))
	for _, a := range cfg.AdminAddresses {
		admins[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}
	return &Service{
		cfg:       cfg,
		validator: validator,
		natsSrv:   natsSrv,
		nc:        nc,
		js:        js,
		limiter:   NewRateLimiter(),
		logger:    logger,
		adminSet:  admins,
	}
}

// Start subscribes to rogue.in.> and processes incoming messages and commands.
func (s *Service) Start() error {
	sub, err := s.nc.Subscribe("rogue.in.>", s.handleIngress)
	if err != nil {
		return fmt.Errorf("subscribe rogue.in.>: %w", err)
	}
	s.sub = sub
	return s.nc.Flush()
}

// Stop unsubscribes the Gatekeeper handler.
func (s *Service) Stop() {
	if s.sub != nil {
		_ = s.sub.Unsubscribe()
		s.sub = nil
	}
}

func (s *Service) handleIngress(msg *nats.Msg) {
	// Expected subject shapes:
	// - rogue.in.<0x>.chat.<room>
	// - rogue.in.<0x>.dm.<dest0x>
	// - rogue.in.<0x>.cmd.<action>
	parts := strings.Split(msg.Subject, ".")
	if len(parts) < 4 {
		s.fail(msg, "", "", ErrBadRequest, "malformed ingress subject")
		return
	}
	sender := strings.ToLower(parts[2])
	if !isHexAddr(sender) {
		s.fail(msg, "", "", ErrBadRequest, "invalid sender address")
		return
	}

	if banned, err := s.isBanned(sender); err != nil {
		s.fail(msg, sender, "", ErrInternal, "ban lookup failed")
		return
	} else if banned {
		s.fail(msg, sender, "", ErrBanned, "address is banned")
		return
	}

	switch parts[3] {
	case "chat":
		if len(parts) != 5 {
			s.fail(msg, sender, "", ErrBadRequest, "expected rogue.in.<0x>.chat.<room>")
			return
		}
		s.handleChat(msg, sender, parts[4])
	case "dm":
		if len(parts) != 5 {
			s.fail(msg, sender, "", ErrBadRequest, "expected rogue.in.<0x>.dm.<dest0x>")
			return
		}
		s.handleDM(msg, sender, strings.ToLower(parts[4]))
	case "cmd":
		if len(parts) != 5 {
			s.fail(msg, sender, "", ErrBadRequest, "expected rogue.in.<0x>.cmd.<action>")
			return
		}
		s.handleCommand(msg, sender, parts[4])
	default:
		s.fail(msg, sender, "", ErrBadRequest, "unknown ingress route")
	}
}

func (s *Service) handleChat(msg *nats.Msg, sender, room string) {
	if err := ValidateRoomName(room); err != nil {
		s.fail(msg, sender, room, ErrBadRequest, err.Error())
		return
	}

	chMeta, err := s.getChannel(room)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			s.fail(msg, sender, room, ErrRoomNotFound, "channel does not exist")
			return
		}
		s.fail(msg, sender, room, ErrInternal, "channel lookup failed")
		return
	}

	isAdmin := s.isAdmin(sender)
	if chMeta.AdminOnlyWrite && !isAdmin {
		s.fail(msg, sender, room, ErrForbidden, "channel is read-only for non-administrators")
		return
	}

	if muted, reason := s.isMuted(sender, room); muted {
		s.fail(msg, sender, room, ErrMuted, reason)
		return
	}

	var in ChatMessageInput
	if err := json.Unmarshal(msg.Data, &in); err != nil {
		s.fail(msg, sender, room, ErrBadRequest, "invalid chat JSON payload")
		return
	}
	cleanText, err := SanitizeAndValidateText(in.Text)
	if err != nil {
		s.fail(msg, sender, room, ErrInvalidContent, err.Error())
		return
	}

	hasLink, linkErr := InspectLinks(cleanText)
	if linkErr != nil {
		s.fail(msg, sender, room, ErrLinkRestricted, linkErr.Error())
		return
	}

	state, err := s.verifyOnChain(sender)
	if err != nil {
		s.fail(msg, sender, room, ErrRPCUnavailable, err.Error())
		return
	}

	if chMeta.Gated && !isAdmin && state.MinerLevel < chMeta.MinLevel {
		s.fail(msg, sender, room, ErrForbidden, fmt.Sprintf("channel requires MinerLevel >= %d", chMeta.MinLevel))
		return
	}

	minChatWei := rpc.RogueToWei(s.cfg.MinBalanceChat)
	if !isAdmin && (state.BalanceLatest.Cmp(minChatWei) < 0 || state.BalanceLookback.Cmp(minChatWei) < 0) {
		s.fail(msg, sender, room, ErrInsufficientBalance, "insufficient mature ROGUE balance")
		return
	}

	if hasLink && !isAdmin {
		minLinkWei := rpc.RogueToWei(s.cfg.MinBalanceLinks)
		if state.BalanceLatest.Cmp(minLinkWei) < 0 && state.MinerLevel < 1 {
			s.fail(msg, sender, room, ErrLinkRestricted, fmt.Sprintf("links require >= %.2f ROGUE or MinerLevel >= 1", s.cfg.MinBalanceLinks))
			return
		}
	}

	if !s.limiter.AllowMessage(sender, state.MinerLevel, isAdmin) {
		s.fail(msg, sender, room, ErrRateLimit, "message rate limit exceeded")
		return
	}

	kind := strings.TrimSpace(in.Kind)
	if kind == "" {
		kind = "text"
	}
	env := ChatMessageEnvelope{
		V:       1,
		ID:      randomID(),
		Room:    room,
		Sender:  sender,
		Level:   state.MinerLevel,
		Kind:    kind,
		Text:    cleanText,
		ReplyTo: strings.TrimSpace(in.ReplyTo),
		Ts:      time.Now().UTC().UnixMilli(),
	}

	targetSubject := fmt.Sprintf("rogue.chat.%s.msg", room)
	if chMeta.Gated {
		targetSubject = fmt.Sprintf("rogue.gated.%s.msg", room)
	}
	payload, err := json.Marshal(env)
	if err != nil {
		s.fail(msg, sender, room, ErrInternal, "marshal message")
		return
	}

	ack, err := s.js.Publish(targetSubject, payload)
	if err != nil {
		s.fail(msg, sender, room, ErrInternal, "persist message failed")
		return
	}
	env.Seq = ack.Sequence
	s.ok(msg, env)
}

func (s *Service) handleDM(msg *nats.Msg, sender, dest string) {
	if !isHexAddr(dest) {
		s.fail(msg, sender, "", ErrBadRequest, "invalid destination 0x address")
		return
	}
	if muted, reason := s.isMuted(sender, ""); muted {
		s.fail(msg, sender, "", ErrMuted, reason)
		return
	}

	profilesKV, err := s.js.KeyValue(store.BucketProfiles)
	if err != nil {
		s.fail(msg, sender, "", ErrInternal, "profiles bucket unavailable")
		return
	}
	if _, err := profilesKV.Get(dest); err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			s.fail(msg, sender, "", ErrRecipientPubKeyUnknown, "recipient has not connected yet to register their secp256k1 public key")
			return
		}
		s.fail(msg, sender, "", ErrInternal, "recipient lookup failed")
		return
	}

	var enc rcrypto.EncryptedPayload
	if err := json.Unmarshal(msg.Data, &enc); err != nil || enc.V != 1 || enc.Ciphertext == "" || enc.EphemeralPubKey == "" || enc.Nonce == "" {
		s.fail(msg, sender, "", ErrBadRequest, "invalid ECIES encrypted DM payload")
		return
	}

	state, err := s.verifyOnChain(sender)
	if err != nil {
		s.fail(msg, sender, "", ErrRPCUnavailable, err.Error())
		return
	}
	isAdmin := s.isAdmin(sender)
	minChatWei := rpc.RogueToWei(s.cfg.MinBalanceChat)
	if !isAdmin && (state.BalanceLatest.Cmp(minChatWei) < 0 || state.BalanceLookback.Cmp(minChatWei) < 0) {
		s.fail(msg, sender, "", ErrInsufficientBalance, "insufficient mature ROGUE balance")
		return
	}
	if !s.limiter.AllowMessage(sender, state.MinerLevel, isAdmin) {
		s.fail(msg, sender, "", ErrRateLimit, "DM rate limit exceeded")
		return
	}

	dm := DMEnvelope{
		V:       1,
		ID:      randomID(),
		Sender:  sender,
		Dest:    dest,
		Ts:      time.Now().UTC().UnixMilli(),
		Payload: enc,
	}
	data, err := json.Marshal(dm)
	if err != nil {
		s.fail(msg, sender, "", ErrInternal, "marshal DM")
		return
	}
	ack, err := s.js.Publish(fmt.Sprintf("rogue.dm.%s", dest), data)
	if err != nil {
		s.fail(msg, sender, "", ErrInternal, "persist DM failed")
		return
	}
	s.ok(msg, map[string]any{"id": dm.ID, "seq": ack.Sequence, "ts": dm.Ts})
}

func (s *Service) handleCommand(msg *nats.Msg, sender, action string) {
	switch action {
	case "rooms":
		s.cmdRooms(msg, sender)
	case "create_room":
		s.cmdCreateRoom(msg, sender)
	case "delete_room":
		s.cmdDeleteRoom(msg, sender)
	case "topic":
		s.cmdTopic(msg, sender)
	case "delete_msg":
		s.cmdDeleteMsg(msg, sender)
	case "mute":
		s.cmdMute(msg, sender)
	case "unmute":
		s.cmdUnmute(msg, sender)
	case "ban":
		s.cmdBan(msg, sender)
	case "unban":
		s.cmdUnban(msg, sender)
	case "stats":
		s.cmdStats(msg, sender)
	default:
		s.fail(msg, sender, "", ErrBadRequest, "unknown command: "+action)
	}
}

func (s *Service) cmdRooms(msg *nats.Msg, sender string) {
	chKV, err := s.js.KeyValue(store.BucketChannels)
	if err != nil {
		s.fail(msg, sender, "", ErrInternal, "channels bucket unavailable")
		return
	}
	presKV, err := s.js.KeyValue(store.BucketPresence)
	if err != nil {
		s.fail(msg, sender, "", ErrInternal, "presence bucket unavailable")
		return
	}

	counts := make(map[string]int)
	if pKeys, err := presKV.Keys(nats.IgnoreDeletes()); err == nil {
		for _, pk := range pKeys {
			if entry, err := presKV.Get(pk); err == nil {
				var pr PresenceRecord
				if json.Unmarshal(entry.Value(), &pr) == nil && pr.ActiveRoom != "" {
					counts[pr.ActiveRoom]++
				}
			}
		}
	}

	cKeys, err := chKV.Keys(nats.IgnoreDeletes())
	if err != nil && !errors.Is(err, nats.ErrNoKeysFound) {
		s.fail(msg, sender, "", ErrInternal, "list channels failed")
		return
	}

	rooms := make([]RoomSummary, 0, len(cKeys))
	for _, k := range cKeys {
		entry, err := chKV.Get(k)
		if err != nil {
			continue
		}
		var meta store.ChannelMeta
		if json.Unmarshal(entry.Value(), &meta) != nil {
			continue
		}
		rooms = append(rooms, RoomSummary{
			ChannelMeta: meta,
			MemberCount: counts[meta.Name],
		})
	}

	sort.Slice(rooms, func(i, j int) bool {
		if rooms[i].Pinned != rooms[j].Pinned {
			return rooms[i].Pinned
		}
		if rooms[i].MemberCount != rooms[j].MemberCount {
			return rooms[i].MemberCount > rooms[j].MemberCount
		}
		return rooms[i].Name < rooms[j].Name
	})

	s.ok(msg, rooms)
}

func (s *Service) cmdCreateRoom(msg *nats.Msg, sender string) {
	var req struct {
		Name  string `json:"name"`
		Topic string `json:"topic"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.fail(msg, sender, "", ErrBadRequest, "invalid create_room payload")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := ValidateRoomName(req.Name); err != nil {
		s.fail(msg, sender, req.Name, ErrBadRequest, err.Error())
		return
	}
	if utf8.RuneCountInString(req.Topic) > MaxTopicRunes {
		s.fail(msg, sender, req.Name, ErrInvalidContent, "topic too long")
		return
	}

	isAdmin := s.isAdmin(sender)
	state, err := s.verifyOnChain(sender)
	if err != nil {
		s.fail(msg, sender, req.Name, ErrRPCUnavailable, err.Error())
		return
	}

	minRoomWei := rpc.RogueToWei(s.cfg.MinBalanceCreateRoom)
	if !isAdmin && state.BalanceLatest.Cmp(minRoomWei) < 0 && state.MinerLevel < 2 {
		s.fail(msg, sender, req.Name, ErrForbidden, fmt.Sprintf("creating rooms requires >= %.2f ROGUE or MinerLevel >= 2", s.cfg.MinBalanceCreateRoom))
		return
	}
	if !s.limiter.AllowCreateRoom(sender, isAdmin) {
		s.fail(msg, sender, req.Name, ErrRateLimit, "room creation rate limit exceeded (1 every 5m)")
		return
	}

	chKV, err := s.js.KeyValue(store.BucketChannels)
	if err != nil {
		s.fail(msg, sender, req.Name, ErrInternal, "channels bucket unavailable")
		return
	}
	if !isAdmin && s.countRoomsCreatedBy(chKV, sender) >= s.cfg.MaxRoomsPerAccount {
		s.fail(msg, sender, req.Name, ErrRoomLimit, fmt.Sprintf("maximum %d rooms per account reached", s.cfg.MaxRoomsPerAccount))
		return
	}

	meta := store.ChannelMeta{
		Name:      req.Name,
		Topic:     strings.TrimSpace(req.Topic),
		CreatedBy: sender,
		CreatedAt: time.Now().UTC().UnixMilli(),
	}
	payload, _ := json.Marshal(meta)
	if _, err := chKV.Create(meta.Name, payload); err != nil {
		if errors.Is(err, nats.ErrKeyExists) {
			s.fail(msg, sender, req.Name, ErrRoomExists, "channel already exists")
			return
		}
		s.fail(msg, sender, req.Name, ErrInternal, "create channel failed")
		return
	}
	s.ok(msg, meta)
}

func (s *Service) cmdDeleteRoom(msg *nats.Msg, sender string) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.fail(msg, sender, "", ErrBadRequest, "invalid delete_room payload")
		return
	}
	meta, err := s.getChannel(req.Name)
	if err != nil {
		s.fail(msg, sender, req.Name, ErrRoomNotFound, "channel not found")
		return
	}
	if meta.System {
		s.fail(msg, sender, req.Name, ErrForbidden, "system channels cannot be deleted")
		return
	}
	if !s.isAdmin(sender) && meta.CreatedBy != sender {
		s.fail(msg, sender, req.Name, ErrForbidden, "only channel creator or admin can delete channel")
		return
	}
	chKV, _ := s.js.KeyValue(store.BucketChannels)
	if err := chKV.Delete(req.Name); err != nil {
		s.fail(msg, sender, req.Name, ErrInternal, "delete channel failed")
		return
	}
	s.ok(msg, map[string]string{"deleted": req.Name})
}

func (s *Service) cmdTopic(msg *nats.Msg, sender string) {
	var req struct {
		Name  string `json:"name"`
		Topic string `json:"topic"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.fail(msg, sender, "", ErrBadRequest, "invalid topic payload")
		return
	}
	if utf8.RuneCountInString(req.Topic) > MaxTopicRunes {
		s.fail(msg, sender, req.Name, ErrInvalidContent, "topic too long")
		return
	}
	meta, err := s.getChannel(req.Name)
	if err != nil {
		s.fail(msg, sender, req.Name, ErrRoomNotFound, "channel not found")
		return
	}
	if !s.isAdmin(sender) && meta.CreatedBy != sender {
		s.fail(msg, sender, req.Name, ErrForbidden, "only channel creator or admin can update topic")
		return
	}
	meta.Topic = strings.TrimSpace(req.Topic)
	chKV, _ := s.js.KeyValue(store.BucketChannels)
	payload, _ := json.Marshal(meta)
	if _, err := chKV.Put(meta.Name, payload); err != nil {
		s.fail(msg, sender, req.Name, ErrInternal, "update topic failed")
		return
	}
	s.ok(msg, meta)
}

func (s *Service) cmdDeleteMsg(msg *nats.Msg, sender string) {
	var req struct {
		Room string `json:"room"`
		Seq  uint64 `json:"seq"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil || req.Seq == 0 {
		s.fail(msg, sender, "", ErrBadRequest, "invalid delete_msg payload")
		return
	}
	meta, err := s.getChannel(req.Room)
	if err != nil {
		s.fail(msg, sender, req.Room, ErrRoomNotFound, "channel not found")
		return
	}

	streamName := store.StreamChat
	delSubject := fmt.Sprintf("rogue.chat.%s.delete", req.Room)
	if meta.Gated {
		streamName = store.StreamGated
		delSubject = fmt.Sprintf("rogue.gated.%s.delete", req.Room)
	}

	rawMsg, err := s.js.GetMsg(streamName, req.Seq)
	if err != nil {
		s.fail(msg, sender, req.Room, ErrBadRequest, "message sequence not found")
		return
	}
	var env ChatMessageEnvelope
	_ = json.Unmarshal(rawMsg.Data, &env)

	if !s.isAdmin(sender) && meta.CreatedBy != sender && env.Sender != sender {
		s.fail(msg, sender, req.Room, ErrForbidden, "insufficient permissions to delete message")
		return
	}

	if err := s.js.DeleteMsg(streamName, req.Seq); err != nil {
		s.fail(msg, sender, req.Room, ErrInternal, "failed to delete message from stream")
		return
	}

	ev := DeleteMessageEvent{
		Room:      req.Room,
		Seq:       req.Seq,
		DeletedBy: sender,
		Ts:        time.Now().UTC().UnixMilli(),
	}
	evBytes, _ := json.Marshal(ev)
	_, _ = s.js.Publish(delSubject, evBytes)
	s.ok(msg, ev)
}

func (s *Service) cmdMute(msg *nats.Msg, sender string) {
	var req struct {
		Target      string `json:"target"`
		Room        string `json:"room"`
		DurationSec int64  `json:"duration_sec"`
		Reason      string `json:"reason"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.fail(msg, sender, "", ErrBadRequest, "invalid mute payload")
		return
	}
	req.Target = strings.ToLower(strings.TrimSpace(req.Target))
	if !isHexAddr(req.Target) {
		s.fail(msg, sender, req.Room, ErrBadRequest, "invalid target 0x address")
		return
	}

	isAdmin := s.isAdmin(sender)
	if req.Room == "" {
		if !isAdmin {
			s.fail(msg, sender, "", ErrForbidden, "global mute requires admin privileges")
			return
		}
	} else {
		meta, err := s.getChannel(req.Room)
		if err != nil {
			s.fail(msg, sender, req.Room, ErrRoomNotFound, "channel not found")
			return
		}
		if !isAdmin && meta.CreatedBy != sender {
			s.fail(msg, sender, req.Room, ErrForbidden, "only channel creator or admin can mute in this room")
			return
		}
	}

	if req.DurationSec <= 0 {
		req.DurationSec = 900 // 15m default
	}
	if req.DurationSec > 86400 {
		req.DurationSec = 86400
	}

	mutesKV, err := s.js.KeyValue(store.BucketMutes)
	if err != nil {
		s.fail(msg, sender, req.Room, ErrInternal, "mutes bucket unavailable")
		return
	}
	rec := muteRecord{
		Target:  req.Target,
		Room:    req.Room,
		By:      sender,
		Reason:  req.Reason,
		UntilTs: time.Now().UTC().Add(time.Duration(req.DurationSec) * time.Second).UnixMilli(),
	}
	data, _ := json.Marshal(rec)
	if _, err := mutesKV.Put(muteKey(req.Target, req.Room), data); err != nil {
		s.fail(msg, sender, req.Room, ErrInternal, "store mute failed")
		return
	}
	s.ok(msg, rec)
}

func (s *Service) cmdUnmute(msg *nats.Msg, sender string) {
	var req struct {
		Target string `json:"target"`
		Room   string `json:"room"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.fail(msg, sender, "", ErrBadRequest, "invalid unmute payload")
		return
	}
	req.Target = strings.ToLower(strings.TrimSpace(req.Target))
	if req.Room == "" && !s.isAdmin(sender) {
		s.fail(msg, sender, "", ErrForbidden, "global unmute requires admin privileges")
		return
	}
	if req.Room != "" {
		meta, err := s.getChannel(req.Room)
		if err != nil {
			s.fail(msg, sender, req.Room, ErrRoomNotFound, "channel not found")
			return
		}
		if !s.isAdmin(sender) && meta.CreatedBy != sender {
			s.fail(msg, sender, req.Room, ErrForbidden, "forbidden")
			return
		}
	}
	mutesKV, _ := s.js.KeyValue(store.BucketMutes)
	_ = mutesKV.Delete(muteKey(req.Target, req.Room))
	s.ok(msg, map[string]string{"unmuted": req.Target, "room": req.Room})
}

func (s *Service) cmdBan(msg *nats.Msg, sender string) {
	if !s.isAdmin(sender) {
		s.fail(msg, sender, "", ErrForbidden, "ban requires admin privileges")
		return
	}
	var req struct {
		Target string `json:"target"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.fail(msg, sender, "", ErrBadRequest, "invalid ban payload")
		return
	}
	req.Target = strings.ToLower(strings.TrimSpace(req.Target))
	if !isHexAddr(req.Target) || s.isAdmin(req.Target) {
		s.fail(msg, sender, "", ErrBadRequest, "invalid or protected target address")
		return
	}

	bansKV, err := s.js.KeyValue(store.BucketBans)
	if err != nil {
		s.fail(msg, sender, "", ErrInternal, "bans bucket unavailable")
		return
	}
	rec := banRecord{
		Target: req.Target,
		By:     sender,
		Reason: req.Reason,
		Ts:     time.Now().UTC().UnixMilli(),
	}
	data, _ := json.Marshal(rec)
	if _, err := bansKV.Put(req.Target, data); err != nil {
		s.fail(msg, sender, "", ErrInternal, "store ban failed")
		return
	}

	disconnected := s.disconnectAddress(req.Target)
	s.ok(msg, map[string]any{"banned": req.Target, "disconnected_sessions": disconnected})
}

func (s *Service) cmdUnban(msg *nats.Msg, sender string) {
	if !s.isAdmin(sender) {
		s.fail(msg, sender, "", ErrForbidden, "unban requires admin privileges")
		return
	}
	var req struct {
		Target string `json:"target"`
	}
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		s.fail(msg, sender, "", ErrBadRequest, "invalid unban payload")
		return
	}
	req.Target = strings.ToLower(strings.TrimSpace(req.Target))
	bansKV, _ := s.js.KeyValue(store.BucketBans)
	_ = bansKV.Delete(req.Target)
	s.ok(msg, map[string]string{"unbanned": req.Target})
}

func (s *Service) cmdStats(msg *nats.Msg, sender string) {
	if !s.isAdmin(sender) {
		s.fail(msg, sender, "", ErrForbidden, "admin stats requires admin privileges")
		return
	}
	varz, err := s.natsSrv.Varz(nil)
	if err != nil {
		s.fail(msg, sender, "", ErrInternal, "varz unavailable")
		return
	}
	chatInfo, _ := s.js.StreamInfo(store.StreamChat)
	gatedInfo, _ := s.js.StreamInfo(store.StreamGated)
	dmInfo, _ := s.js.StreamInfo(store.StreamDM)

	stats := map[string]any{
		"connections": varz.Connections,
		"in_msgs":     varz.InMsgs,
		"out_msgs":    varz.OutMsgs,
		"uptime":      varz.Uptime,
		"streams": map[string]any{
			store.StreamChat:  streamMsgCount(chatInfo),
			store.StreamGated: streamMsgCount(gatedInfo),
			store.StreamDM:    streamMsgCount(dmInfo),
		},
	}
	s.ok(msg, stats)
}

func streamMsgCount(info *nats.StreamInfo) uint64 {
	if info == nil {
		return 0
	}
	return info.State.Msgs
}

func (s *Service) disconnectAddress(target string) int {
	if s.natsSrv == nil {
		return 0
	}
	connz, err := s.natsSrv.Connz(&server.ConnzOptions{Account: "ROGUE", Username: true})
	if err != nil || connz == nil {
		return 0
	}
	count := 0
	for _, c := range connz.Conns {
		if strings.EqualFold(c.AuthorizedUser, target) || strings.EqualFold(c.Name, target) {
			if err := s.natsSrv.DisconnectClientByID(c.Cid); err == nil {
				count++
			}
		}
	}
	return count
}

func (s *Service) verifyOnChain(addr string) (rpc.AccountState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	return s.validator.VerifyAccount(ctx, addr)
}

func (s *Service) getChannel(name string) (store.ChannelMeta, error) {
	kv, err := s.js.KeyValue(store.BucketChannels)
	if err != nil {
		return store.ChannelMeta{}, err
	}
	entry, err := kv.Get(name)
	if err != nil {
		return store.ChannelMeta{}, err
	}
	var meta store.ChannelMeta
	if err := json.Unmarshal(entry.Value(), &meta); err != nil {
		return store.ChannelMeta{}, err
	}
	return meta, nil
}

func (s *Service) countRoomsCreatedBy(kv nats.KeyValue, addr string) int {
	keys, err := kv.Keys(nats.IgnoreDeletes())
	if err != nil {
		return 0
	}
	count := 0
	for _, k := range keys {
		if entry, err := kv.Get(k); err == nil {
			var meta store.ChannelMeta
			if json.Unmarshal(entry.Value(), &meta) == nil && !meta.System && meta.CreatedBy == addr {
				count++
			}
		}
	}
	return count
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

func (s *Service) isMuted(addr, room string) (bool, string) {
	kv, err := s.js.KeyValue(store.BucketMutes)
	if err != nil {
		return false, ""
	}
	now := time.Now().UTC().UnixMilli()
	keys := []string{muteKey(addr, "")}
	if room != "" {
		keys = append(keys, muteKey(addr, room))
	}
	for _, k := range keys {
		entry, err := kv.Get(k)
		if err != nil {
			continue
		}
		var rec muteRecord
		if json.Unmarshal(entry.Value(), &rec) == nil {
			if rec.UntilTs > now {
				return true, fmt.Sprintf("muted until %s (%s)", time.UnixMilli(rec.UntilTs).UTC().Format(time.RFC3339), rec.Reason)
			}
			_ = kv.Delete(k)
		}
	}
	return false, ""
}

func muteKey(addr, room string) string {
	if room == "" {
		return addr + ".global"
	}
	return addr + "." + room
}

func (s *Service) isAdmin(addr string) bool {
	_, ok := s.adminSet[strings.ToLower(addr)]
	return ok
}

func (s *Service) ok(msg *nats.Msg, data any) {
	if msg.Reply == "" {
		return
	}
	resp, _ := json.Marshal(CommandResponse{OK: true, Data: data})
	_ = msg.Respond(resp)
}

func (s *Service) fail(msg *nats.Msg, sender, room, code, message string) {
	ev := ErrorEvent{
		Code:    code,
		Message: message,
		Room:    room,
		Ts:      time.Now().UTC().UnixMilli(),
	}
	if sender != "" {
		evBytes, _ := json.Marshal(ev)
		_ = s.nc.Publish(fmt.Sprintf("rogue.err.%s", sender), evBytes)
	}
	if msg.Reply != "" {
		resp, _ := json.Marshal(CommandResponse{OK: false, Error: &ev})
		_ = msg.Respond(resp)
	}
}

func isHexAddr(addr string) bool {
	if !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
		return false
	}
	_, err := hex.DecodeString(addr[2:])
	return err == nil
}

func randomID() string {
	buf := make([]byte, 8)
	_, _ = rand.Read(buf)
	return hex.EncodeToString(buf)
}
