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
	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	"github.com/roguesignalchain/rogue-nats-server/internal/keys"
	"github.com/roguesignalchain/rogue-nats-server/internal/store"
)

// RogueServer wraps the embedded NATS + JetStream daemon and internal state.
type RogueServer struct {
	cfg      config.Config
	logger   *slog.Logger
	keys     *keys.OperatorKeys
	natsSrv  *server.Server
	adminNC  *nats.Conn
}

// New validates configuration and prepares a RogueServer instance.
func New(cfg config.Config, logger *slog.Logger) (*RogueServer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &RogueServer{
		cfg:    cfg,
		logger: logger,
	}, nil
}

// Start initializes NKeys, boots the embedded NATS/JetStream server, and bootstraps streams/KVs.
func (r *RogueServer) Start(ctx context.Context) error {
	opKeys, err := keys.LoadOrCreate(filepath.Join(r.cfg.DataDir, "keys"))
	if err != nil {
		return fmt.Errorf("load operator keys: %w", err)
	}
	r.keys = opKeys

	opts := &server.Options{
		ServerName: "rogue-nats-server",
		Host:       r.cfg.Host,
		Port:       r.cfg.Port,
		HTTPPort:   r.cfg.HTTPPort,
		JetStream:  true,
		StoreDir:   filepath.Join(r.cfg.DataDir, "jetstream"),
		NoSigs:     true,
		MaxPayload: 64 * 1024,
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

	nc, err := nats.Connect("", nats.InProcessServer(ns))
	if err != nil {
		ns.Shutdown()
		return fmt.Errorf("connect in-process admin client: %w", err)
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

// Shutdown gracefully closes the internal client and embedded NATS server.
func (r *RogueServer) Shutdown() {
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
