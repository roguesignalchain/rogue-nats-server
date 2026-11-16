package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultTreasuryAddress is Rogue Signal's protocol treasury address.
	DefaultTreasuryAddress = "0xe9aaE535B7971A9AC8C6af0e4B524D02260D3a03"
	// DefaultChainID is Rogue Signal's EVM chain ID.
	DefaultChainID uint64 = 800055
)

// Config holds all runtime configuration for rogue-nats-server.
type Config struct {
	Host     string
	Port     int
	WSPort   int
	HTTPPort int
	DataDir  string
	LogLevel string

	RPCURL         string
	ChainID        uint64
	LookbackBlocks uint64

	TLSCert   string
	TLSKey    string
	WSOrigins []string

	StreamMaxAge   time.Duration
	StreamMaxMsgs  int64
	StreamMaxBytes int64
	DMMaxAge       time.Duration

	MinBalanceChat       float64
	MinBalanceLinks      float64
	MinBalanceCreateRoom float64
	MaxRoomsPerAccount   int
	AdminAddresses       []string
}

// Default returns a Config populated with production-safe defaults.
func Default() Config {
	return Config{
		Host:                 "0.0.0.0",
		Port:                 4222,
		WSPort:               4223,
		HTTPPort:             8222,
		DataDir:              "./data",
		LogLevel:             "info",
		RPCURL:               "http://127.0.0.1:38845",
		ChainID:              DefaultChainID,
		LookbackBlocks:       120,
		StreamMaxAge:         30 * 24 * time.Hour,
		StreamMaxMsgs:        100_000,
		StreamMaxBytes:       512 * 1024 * 1024,
		DMMaxAge:             30 * 24 * time.Hour,
		MinBalanceChat:       1,
		MinBalanceLinks:      10,
		MinBalanceCreateRoom: 50,
		MaxRoomsPerAccount:   3,
		AdminAddresses:       []string{strings.ToLower(DefaultTreasuryAddress)},
	}
}

// ApplyEnv overrides configuration fields from ROGUE_* environment variables.
func (c *Config) ApplyEnv() {
	if v := os.Getenv("ROGUE_NATS_HOST"); v != "" {
		c.Host = v
	}
	if v, ok := envInt("ROGUE_NATS_PORT"); ok {
		c.Port = v
	}
	if v, ok := envInt("ROGUE_NATS_WS_PORT"); ok {
		c.WSPort = v
	}
	if v, ok := envInt("ROGUE_NATS_HTTP_PORT"); ok {
		c.HTTPPort = v
	}
	if v := os.Getenv("ROGUE_NATS_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := os.Getenv("ROGUE_NATS_LOG_LEVEL"); v != "" {
		c.LogLevel = strings.ToLower(v)
	}
	if v := os.Getenv("ROGUE_RPC_URL"); v != "" {
		c.RPCURL = v
	}
	if v, ok := envUint64("ROGUE_CHAIN_ID"); ok {
		c.ChainID = v
	}
	if v, ok := envUint64("ROGUE_LOOKBACK_BLOCKS"); ok {
		c.LookbackBlocks = v
	}
	if v := os.Getenv("ROGUE_NATS_TLS_CERT"); v != "" {
		c.TLSCert = v
	}
	if v := os.Getenv("ROGUE_NATS_TLS_KEY"); v != "" {
		c.TLSKey = v
	}
	if v := os.Getenv("ROGUE_NATS_WS_ORIGINS"); v != "" {
		c.WSOrigins = splitTrim(v)
	}
	if v, ok := envFloat64("ROGUE_MIN_BALANCE_CHAT"); ok {
		c.MinBalanceChat = v
	}
	if v, ok := envFloat64("ROGUE_MIN_BALANCE_LINKS"); ok {
		c.MinBalanceLinks = v
	}
	if v, ok := envFloat64("ROGUE_MIN_BALANCE_CREATE_ROOM"); ok {
		c.MinBalanceCreateRoom = v
	}
	if v, ok := envInt("ROGUE_MAX_ROOMS_PER_ACCOUNT"); ok {
		c.MaxRoomsPerAccount = v
	}
	if v := os.Getenv("ROGUE_ADMIN_ADDRESSES"); v != "" {
		raw := splitTrim(v)
		normalized := make([]string, 0, len(raw))
		for _, addr := range raw {
			normalized = append(normalized, strings.ToLower(addr))
		}
		c.AdminAddresses = normalized
	}
}

// Validate checks configuration invariants before starting the server.
func (c Config) Validate() error {
	if c.Port < -1 || c.Port > 65535 {
		return fmt.Errorf("invalid TCP port: %d", c.Port)
	}
	if c.WSPort < -1 || c.WSPort > 65535 {
		return fmt.Errorf("invalid WebSocket port: %d", c.WSPort)
	}
	if c.HTTPPort < -1 || c.HTTPPort > 65535 {
		return fmt.Errorf("invalid HTTP monitoring port: %d", c.HTTPPort)
	}
	if c.DataDir == "" {
		return fmt.Errorf("data directory cannot be empty")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return fmt.Errorf("both TLS cert and TLS key must be provided together")
	}
	if c.LookbackBlocks == 0 {
		return fmt.Errorf("lookback blocks must be greater than zero")
	}
	return nil
}

func envInt(key string) (int, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	parsed, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func envUint64(key string) (uint64, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func envFloat64(key string) (float64, bool) {
	v := os.Getenv(key)
	if v == "" {
		return 0, false
	}
	parsed, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, false
	}
	return parsed, true
}

func splitTrim(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
