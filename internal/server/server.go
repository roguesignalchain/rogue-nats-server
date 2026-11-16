package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"path/filepath"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/roguesignalchain/rogue-nats-server/internal/auth"
	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	"github.com/roguesignalchain/rogue-nats-server/internal/keys"
	"github.com/roguesignalchain/rogue-nats-server/internal/rpc"
	"github.com/roguesignalchain/rogue-nats-server/internal/store"
)

// RogueServer wraps the embedded NATS + JetStream daemon and internal services.
type RogueServer struct {
	cfg       config.Config
	logger    *slog.Logger
	validator rpc.ChainValidator
	keys      *keys.OperatorKeys
	natsSrv   *server.Server
	adminNC   *nats.Conn
	authSvc   *auth.Service
}

// New validates configuration and prepares a RogueServer with the default JSON-RPC validator.
func New(cfg config.Config, logger *slog.Logger) (*RogueServer, error) {
	validator := rpc.NewJSONRPCClient(cfg.RPCURL, cfg.LookbackBlocks)
	return NewWithValidator(cfg, validator, logger)
}

// NewWithValidator constructs a RogueServer with a custom ChainValidator (useful for tests).
func NewWithValidator(cfg config.Config, validator rpc.ChainValidator, logger *slog.Logger) (*RogueServer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if validator == nil {
		return nil, fmt.Errorf("chain validator cannot be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RogueServer{
		cfg:       cfg,
		logger:    logger,
		validator: validator,
	}, nil
}

// Start initializes NKeys, boots the embedded NATS/JetStream server with Auth Callout,
// and bootstraps streams/KV buckets.
func (r *RogueServer) Start(ctx context.Context) error {
	opKeys, err := keys.LoadOrCreate(filepath.Join(r.cfg.DataDir, "keys"))
	if err != nil {
		return fmt.Errorf("load operator keys: %w", err)
	}
	r.keys = opKeys

	rogueAcc := server.NewAccount("ROGUE")
	opts := &server.Options{
		ServerName: "rogue-nats-server",
		Host:       r.cfg.Host,
		Port:       r.cfg.Port,
		HTTPPort:   r.cfg.HTTPPort,
		JetStream:  true,
		StoreDir:   filepath.Join(r.cfg.DataDir, "jetstream"),
		NoSigs:     true,
		MaxPayload: 64 * 1024,
		Accounts:   []*server.Account{rogueAcc},
		Nkeys: []*server.NkeyUser{
			{
				Nkey:    opKeys.AuthCalloutPub,
				Account: rogueAcc,
			},
		},
		AuthCallout: &server.AuthCallout{
			Issuer:          opKeys.AccountPub,
			Account:         "ROGUE",
			AuthUsers:       []string{opKeys.AuthCalloutPub},
			AllowedAccounts: []string{"ROGUE"},
		},
		Websocket: server.WebsocketOpts{
			Host:           r.cfg.Host,
			Port:           r.cfg.WSPort,
			NoTLS:          r.cfg.TLSCert == "",
			AllowedOrigins: r.cfg.WSOrigins,
		},
	}

	if r.cfg.TLSCert != "" {
		tlsCfg, err := server.GenTLSConfig(&server.TLSConfigOpts{
			CertFile: r.cfg.TLSCert,
			KeyFile:  r.cfg.TLSKey,
		})
		if err != nil {
			return fmt.Errorf("load TLS config: %w", err)
		}
		opts.TLSConfig = tlsCfg
		opts.Websocket.TLSConfig = tlsCfg
	}

	ns, err := server.NewServer(opts)
	if err != nil {
		return fmt.Errorf("create nats server: %w", err)
	}

	go ns.Start()
	if !ns.ReadyForConnections(10 * time.Second) {
		ns.Shutdown()
		return fmt.Errorf("nats server did not become ready within timeout")
	}
	r.natsSrv = ns

	if acc, err := ns.LookupAccount("ROGUE"); err == nil {
		if err := acc.EnableJetStream(nil, nil); err != nil {
			ns.Shutdown()
			return fmt.Errorf("enable jetstream on ROGUE account: %w", err)
		}
	}

	nc, err := nats.Connect(
		"",
		nats.InProcessServer(ns),
		nats.Nkey(opKeys.AuthCalloutPub, auth.SignNKeyHelper(opKeys.AuthCalloutKP)),
	)
	if err != nil {
		ns.Shutdown()
		return fmt.Errorf("connect in-process service client: %w", err)
	}
	r.adminNC = nc

	js, err := nc.JetStream()
	if err != nil {
		r.Shutdown()
		return fmt.Errorf("init jetstream context: %w", err)
	}

	if err := store.Bootstrap(js, r.cfg); err != nil {
		r.Shutdown()
		return fmt.Errorf("bootstrap jetstream store: %w", err)
	}

	r.authSvc = auth.NewService(r.cfg, opKeys, r.validator, js, nc, r.logger)
	if err := r.authSvc.Start(); err != nil {
		r.Shutdown()
		return fmt.Errorf("start auth callout service: %w", err)
	}

	r.logger.Info("rogue-nats-server started",
		"client_url", r.ClientURL(),
		"ws_port", r.WSPort(),
		"http_url", r.HTTPURL(),
		"account_pub", r.keys.AccountPub,
		"data_dir", r.cfg.DataDir,
	)

	go func() {
		<-ctx.Done()
		r.Shutdown()
	}()

	return nil
}

// Shutdown gracefully closes internal services and the embedded NATS server.
func (r *RogueServer) Shutdown() {
	if r.authSvc != nil {
		r.authSvc.Stop()
		r.authSvc = nil
	}
	if r.adminNC != nil {
		r.adminNC.Close()
		r.adminNC = nil
	}
	if r.natsSrv != nil {
		r.natsSrv.Shutdown()
		r.natsSrv.WaitForShutdown()
		r.natsSrv = nil
	}
}

// ClientURL returns the active TCP NATS URL.
func (r *RogueServer) ClientURL() string {
	if r.natsSrv == nil {
		return ""
	}
	return r.natsSrv.ClientURL()
}

// WSPort returns the configured WebSocket port.
func (r *RogueServer) WSPort() int {
	return r.cfg.WSPort
}

// HTTPURL returns the monitoring HTTP base URL (empty if HTTP monitoring is disabled).
func (r *RogueServer) HTTPURL() string {
	if r.natsSrv == nil {
		return ""
	}
	addr := r.natsSrv.MonitorAddr()
	if addr == nil {
		return ""
	}
	u := url.URL{Scheme: "http", Host: addr.String()}
	return u.String()
}

// Keys returns the loaded operator NKeys.
func (r *RogueServer) Keys() *keys.OperatorKeys {
	return r.keys
}

// JetStream returns an in-process JetStream context for server subsystems and tests.
func (r *RogueServer) JetStream() (nats.JetStreamContext, error) {
	if r.adminNC == nil {
		return nil, fmt.Errorf("server is not started")
	}
	return r.adminNC.JetStream()
}
