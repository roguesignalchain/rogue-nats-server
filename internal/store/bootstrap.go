package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/roguesignalchain/rogue-nats-server/internal/config"
)

const (
	StreamChat  = "ROGUE_CHAT"
	StreamGated = "ROGUE_GATED"
	StreamDM    = "ROGUE_DM"

	BucketChannels = "ROGUE_CHANNELS"
	BucketPresence = "ROGUE_PRESENCE"
	BucketProfiles = "ROGUE_PROFILES"
	BucketBans     = "ROGUE_BANS"
	BucketMutes    = "ROGUE_MUTES"

	PresenceTTL = 30 * time.Second
)

// ChannelMeta describes a messaging channel stored in ROGUE_CHANNELS.
type ChannelMeta struct {
	Name           string `json:"name"`
	Topic          string `json:"topic"`
	System         bool   `json:"system"`
	Gated          bool   `json:"gated"`
	MinLevel       uint32 `json:"min_level"`
	AdminOnlyWrite bool   `json:"admin_only_write"`
	Pinned         bool   `json:"pinned"`
	CreatedBy      string `json:"created_by"`
	CreatedAt      int64  `json:"created_at"`
}

// Bootstrap idempotently creates all required JetStream streams, KV buckets, and default channels.
func Bootstrap(js nats.JetStreamContext, cfg config.Config) error {
	streams := []nats.StreamConfig{
		{
			Name:      StreamChat,
			Subjects:  []string{"rogue.chat.*.msg", "rogue.chat.*.delete"},
			Storage:   nats.FileStorage,
			Retention: nats.LimitsPolicy,
			MaxAge:    cfg.StreamMaxAge,
			MaxMsgs:   cfg.StreamMaxMsgs,
			MaxBytes:  cfg.StreamMaxBytes,
		},
		{
			Name:      StreamGated,
			Subjects:  []string{"rogue.gated.*.msg", "rogue.gated.*.delete"},
			Storage:   nats.FileStorage,
			Retention: nats.LimitsPolicy,
			MaxAge:    cfg.StreamMaxAge,
			MaxMsgs:   cfg.StreamMaxMsgs,
			MaxBytes:  cfg.StreamMaxBytes,
		},
		{
			Name:      StreamDM,
			Subjects:  []string{"rogue.dm.*"},
			Storage:   nats.FileStorage,
			Retention: nats.LimitsPolicy,
			MaxAge:    cfg.DMMaxAge,
			MaxBytes:  cfg.StreamMaxBytes,
		},
	}

	for _, sc := range streams {
		if err := ensureStream(js, sc); err != nil {
			return fmt.Errorf("ensure stream %s: %w", sc.Name, err)
		}
	}

	buckets := []nats.KeyValueConfig{
		{Bucket: BucketChannels, Storage: nats.FileStorage, History: 1},
		{Bucket: BucketPresence, Storage: nats.MemoryStorage, TTL: PresenceTTL, History: 1},
		{Bucket: BucketProfiles, Storage: nats.FileStorage, History: 1},
		{Bucket: BucketBans, Storage: nats.FileStorage, History: 1},
		{Bucket: BucketMutes, Storage: nats.FileStorage, TTL: 24 * time.Hour, History: 1},
	}

	var channelsKV nats.KeyValue
	for _, bc := range buckets {
		kv, err := ensureKV(js, bc)
		if err != nil {
			return fmt.Errorf("ensure kv %s: %w", bc.Bucket, err)
		}
		if bc.Bucket == BucketChannels {
			channelsKV = kv
		}
	}

	if err := ensureDefaultChannels(channelsKV); err != nil {
		return fmt.Errorf("ensure default channels: %w", err)
	}

	return nil
}

func ensureStream(js nats.JetStreamContext, cfg nats.StreamConfig) error {
	_, err := js.StreamInfo(cfg.Name)
	if err == nil {
		return nil
	}
	if !errors.Is(err, nats.ErrStreamNotFound) {
		return err
	}
	_, err = js.AddStream(&cfg)
	return err
}

func ensureKV(js nats.JetStreamContext, cfg nats.KeyValueConfig) (nats.KeyValue, error) {
	kv, err := js.KeyValue(cfg.Bucket)
	if err == nil {
		return kv, nil
	}
	if !errors.Is(err, nats.ErrBucketNotFound) {
		return nil, err
	}
	return js.CreateKeyValue(&cfg)
}

func ensureDefaultChannels(kv nats.KeyValue) error {
	now := time.Now().UTC().UnixMilli()
	defaults := []ChannelMeta{
		{
			Name:           "announcements",
			Topic:          "Official Rogue Signal announcements",
			System:         true,
			Gated:          false,
			MinLevel:       0,
			AdminOnlyWrite: true,
			Pinned:         true,
			CreatedBy:      "system",
			CreatedAt:      now,
		},
		{
			Name:           "general",
			Topic:          "General Rogue Signal community & agent coordination",
			System:         true,
			Gated:          false,
			MinLevel:       0,
			AdminOnlyWrite: false,
			Pinned:         true,
			CreatedBy:      "system",
			CreatedAt:      now,
		},
		{
			Name:           "hash-wardens",
			Topic:          "Miners & operators Lv.3+ (Hash Warden and above)",
			System:         true,
			Gated:          true,
			MinLevel:       3,
			AdminOnlyWrite: false,
			Pinned:         false,
			CreatedBy:      "system",
			CreatedAt:      now,
		},
	}

	for _, ch := range defaults {
		payload, err := json.Marshal(ch)
		if err != nil {
			return err
		}
		// Create only writes if the key does not exist yet.
		if _, err := kv.Create(ch.Name, payload); err != nil && !errors.Is(err, nats.ErrKeyExists) {
			return fmt.Errorf("create channel %s: %w", ch.Name, err)
		}
	}
	return nil
}
