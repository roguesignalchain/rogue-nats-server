package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/roguesignalchain/rogue-nats-server/internal/auth"
	"github.com/roguesignalchain/rogue-nats-server/internal/client"
	"github.com/roguesignalchain/rogue-nats-server/internal/config"
	rcrypto "github.com/roguesignalchain/rogue-nats-server/internal/crypto"
	"github.com/roguesignalchain/rogue-nats-server/internal/gatekeeper"
	"github.com/roguesignalchain/rogue-nats-server/internal/store"
)

// GlobalOptions holds common CLI flags shared across all agent subcommands.
type GlobalOptions struct {
	ServerURL string
	KeySpec   string
	JSONOut   bool
	ChainID   uint64
}

func defaultGlobalOptions() GlobalOptions {
	srv := os.Getenv("ROGUE_NATS_SERVER")
	if srv == "" {
		srv = "nats://127.0.0.1:4222"
	}
	return GlobalOptions{
		ServerURL: srv,
		ChainID:   config.DefaultChainID,
	}
}

func registerGlobalFlags(fs *flag.FlagSet, g *GlobalOptions) {
	fs.StringVar(&g.ServerURL, "server", g.ServerURL, "Rogue NATS server URL")
	fs.StringVar(&g.KeySpec, "key", g.KeySpec, "secp256k1 private key hex or file path")
	fs.BoolVar(&g.JSONOut, "json", g.JSONOut, "Emit machine-readable JSON output")
	fs.Uint64Var(&g.ChainID, "chain-id", g.ChainID, "Rogue Signal Chain ID")
}

// Run executes a CLI subcommand and writes output to out/errOut.
func Run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 {
		PrintUsage(errOut)
		return client.ExitNetworkOrError
	}

	var err error
	var jsonMode bool

	switch args[0] {
	case "send":
		err, jsonMode = runSend(args[1:], out)
	case "read":
		err, jsonMode = runRead(args[1:], out)
	case "listen":
		err, jsonMode = runListen(args[1:], out)
	case "rooms":
		err, jsonMode = runRooms(args[1:], out)
	case "create-room":
		err, jsonMode = runCreateRoom(args[1:], out)
	case "delete-room":
		err, jsonMode = runDeleteRoom(args[1:], out)
	case "topic":
		err, jsonMode = runTopic(args[1:], out)
	case "who":
		err, jsonMode = runWho(args[1:], out)
	case "dm":
		err, jsonMode = runDM(args[1:], out, errOut)
	case "admin":
		err, jsonMode = runAdmin(args[1:], out, errOut)
	default:
		PrintUsage(errOut)
		return client.ExitNetworkOrError
	}

	if err != nil {
		if jsonMode {
			var ee *client.ExitError
			code := "ERR_UNKNOWN"
			if errors.As(err, &ee) && ee.ErrCode != "" {
				code = ee.ErrCode
			}
			_ = json.NewEncoder(errOut).Encode(map[string]any{
				"ok":    false,
				"error": map[string]any{"code": code, "message": err.Error()},
			})
		} else {
			fmt.Fprintf(errOut, "error: %v\n", err)
		}
		return client.ExitCode(err)
	}
	return client.ExitOK
}

// PrintUsage writes the CLI command summary.
func PrintUsage(w io.Writer) {
	fmt.Fprintln(w, `Usage: rogue-nats <command> [flags]

Server & Info:
  serve         Start the Rogue Signal NATS + JetStream server
  version       Print version information

Agent & Client Commands (--server, --key, --json):
  send          Publish a message to a room
  read          Read message history (default 200) from a room
  listen        Stream live room or DM messages as NDJSON
  rooms         List rooms ordered by active member count DESC
  create-room   Create a new public room
  delete-room   Delete an existing user-created room
  topic         Update a room topic
  who           List online users from ROGUE_PRESENCE
  dm            Send or read E2EE direct messages (dm send | dm read)
  admin         Moderation & stats (ban|unban|mute|unmute|delete-msg|stats)`)
}

func connectFromGlobals(g GlobalOptions) (*client.Session, error) {
	priv, err := client.LoadPrivateKey(g.KeySpec)
	if err != nil {
		return nil, err
	}
	return client.Connect(g.ServerURL, g.ChainID, priv)
}

func runSend(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	var room, replyTo string
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&room, "room", "general", "Target room name")
	fs.StringVar(&replyTo, "reply-to", "", "Optional message ID to reply to")
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}
	text := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if text == "" {
		return &client.ExitError{Code: client.ExitNetworkOrError, ErrCode: "ERR_ARGS", Message: "message text is required"}, g.JSONOut
	}

	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	resp, err := sess.RequestJSON(
		fmt.Sprintf("rogue.in.%s.chat.%s", sess.Address, room),
		gatekeeper.ChatMessageInput{Text: text, ReplyTo: replyTo},
	)
	if err != nil {
		return err, g.JSONOut
	}
	return emitOutput(out, g.JSONOut, resp.Data, fmt.Sprintf("sent to #%s", room)), g.JSONOut
}

func runRead(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	var room string
	var limit int
	var beforeSeq uint64
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&room, "room", "general", "Room name")
	fs.IntVar(&limit, "limit", 200, "Maximum messages to read")
	fs.Uint64Var(&beforeSeq, "before-seq", 0, "Read messages strictly before this JetStream sequence")
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}

	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	chKV, err := sess.JS.KeyValue(store.BucketChannels)
	if err != nil {
		return err, g.JSONOut
	}
	entry, err := chKV.Get(room)
	if err != nil {
		return &client.ExitError{Code: client.ExitGatekeeperRejected, ErrCode: gatekeeper.ErrRoomNotFound, Message: "room not found"}, g.JSONOut
	}
	var meta store.ChannelMeta
	_ = json.Unmarshal(entry.Value(), &meta)

	streamName := store.StreamChat
	subj := fmt.Sprintf("rogue.chat.%s.msg", room)
	if meta.Gated {
		streamName = store.StreamGated
		subj = fmt.Sprintf("rogue.gated.%s.msg", room)
	}

	msgs, err := fetchRoomHistory(sess.JS, streamName, subj, limit, beforeSeq)
	if err != nil {
		return err, g.JSONOut
	}

	if g.JSONOut {
		type cliMsg struct {
			gatekeeper.ChatMessageEnvelope
			TimestampISO string `json:"timestamp_iso"`
		}
		wrapped := make([]cliMsg, 0, len(msgs))
		for _, m := range msgs {
			wrapped = append(wrapped, cliMsg{
				ChatMessageEnvelope: m,
				TimestampISO:        time.UnixMilli(m.Ts).UTC().Format(time.RFC3339),
			})
		}
		return json.NewEncoder(out).Encode(map[string]any{"room": room, "count": len(wrapped), "messages": wrapped}), true
	}

	for _, m := range msgs {
		fmt.Fprintf(out, "[seq:%d %s] %s (Lv.%d): %s\n", m.Seq, time.UnixMilli(m.Ts).UTC().Format("15:04:05"), m.Sender, m.Level, m.Text)
	}
	return nil, false
}

func fetchRoomHistory(js nats.JetStreamContext, streamName, subject string, limit int, beforeSeq uint64) ([]gatekeeper.ChatMessageEnvelope, error) {
	if limit <= 0 {
		limit = 200
	}
	info, err := js.StreamInfo(streamName)
	if err != nil {
		return nil, &client.ExitError{Code: client.ExitGatekeeperRejected, ErrCode: gatekeeper.ErrForbidden, Message: err.Error()}
	}
	if info.State.Msgs == 0 || info.State.LastSeq == 0 {
		return []gatekeeper.ChatMessageEnvelope{}, nil
	}

	high := info.State.LastSeq
	if beforeSeq > 0 && beforeSeq <= high {
		if beforeSeq == 1 {
			return []gatekeeper.ChatMessageEnvelope{}, nil
		}
		high = beforeSeq - 1
	}

	low := info.State.FirstSeq
	if low == 0 {
		low = 1
	}

	var collected []gatekeeper.ChatMessageEnvelope
	for seq := high; seq >= low && len(collected) < limit; seq-- {
		raw, err := js.GetMsg(streamName, seq)
		if err != nil || raw.Subject != subject {
			if seq == 1 {
				break
			}
			continue
		}
		var env gatekeeper.ChatMessageEnvelope
		if json.Unmarshal(raw.Data, &env) == nil {
			env.Seq = seq
			collected = append(collected, env)
		}
		if seq == 1 {
			break
		}
	}

	// Reverse to chronological order.
	for i, j := 0, len(collected)-1; i < j; i, j = i+1, j-1 {
		collected[i], collected[j] = collected[j], collected[i]
	}
	return collected, nil
}

func runListen(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	var room string
	var dmOnly bool
	fs := flag.NewFlagSet("listen", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&room, "room", "", "Room to listen to (empty for all public rooms)")
	fs.BoolVar(&dmOnly, "dm", false, "Listen for incoming E2EE DMs")
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}

	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	subj := "rogue.chat.*.msg"
	if dmOnly {
		subj = fmt.Sprintf("rogue.dm.%s", sess.Address)
	} else if room != "" {
		subj = fmt.Sprintf("rogue.chat.%s.msg", room)
		if chKV, err := sess.JS.KeyValue(store.BucketChannels); err == nil {
			if entry, err := chKV.Get(room); err == nil {
				var meta store.ChannelMeta
				if json.Unmarshal(entry.Value(), &meta) == nil && meta.Gated {
					subj = fmt.Sprintf("rogue.gated.%s.msg", room)
				}
			}
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	sub, err := sess.NC.SubscribeSync(subj)
	if err != nil {
		return err, g.JSONOut
	}
	defer sub.Unsubscribe()
	_ = sess.NC.Flush()

	enc := json.NewEncoder(out)
	for {
		msg, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil, g.JSONOut
			}
			return err, g.JSONOut
		}
		if dmOnly {
			var dm gatekeeper.DMEnvelope
			if json.Unmarshal(msg.Data, &dm) == nil {
				if plain, decErr := rcrypto.DecryptECIES(sess.PrivKey, dm.Payload); decErr == nil {
					_ = enc.Encode(map[string]any{
						"id":            dm.ID,
						"sender":        dm.Sender,
						"dest":          dm.Dest,
						"text":          string(plain),
						"ts":            dm.Ts,
						"timestamp_iso": time.UnixMilli(dm.Ts).UTC().Format(time.RFC3339),
					})
				}
			}
			continue
		}
		var env gatekeeper.ChatMessageEnvelope
		if json.Unmarshal(msg.Data, &env) == nil {
			_ = enc.Encode(env)
		}
	}
}

func runRooms(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	fs := flag.NewFlagSet("rooms", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}
	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	resp, err := sess.RequestJSON(fmt.Sprintf("rogue.in.%s.cmd.rooms", sess.Address), map[string]any{})
	if err != nil {
		return err, g.JSONOut
	}
	return emitOutput(out, g.JSONOut, resp.Data, fmt.Sprintf("%v", resp.Data)), g.JSONOut
}

func runCreateRoom(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	var name, topic string
	fs := flag.NewFlagSet("create-room", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&name, "name", "", "Room name (lowercase a-z, 0-9, -)")
	fs.StringVar(&topic, "topic", "", "Room topic")
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}
	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	resp, err := sess.RequestJSON(fmt.Sprintf("rogue.in.%s.cmd.create_room", sess.Address), map[string]string{
		"name":  name,
		"topic": topic,
	})
	if err != nil {
		return err, g.JSONOut
	}
	return emitOutput(out, g.JSONOut, resp.Data, fmt.Sprintf("created room #%s", name)), g.JSONOut
}

func runDeleteRoom(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	var name string
	fs := flag.NewFlagSet("delete-room", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&name, "name", "", "Room name")
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}
	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	resp, err := sess.RequestJSON(fmt.Sprintf("rogue.in.%s.cmd.delete_room", sess.Address), map[string]string{"name": name})
	if err != nil {
		return err, g.JSONOut
	}
	return emitOutput(out, g.JSONOut, resp.Data, fmt.Sprintf("deleted room #%s", name)), g.JSONOut
}

func runTopic(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	var room, topic string
	fs := flag.NewFlagSet("topic", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&room, "room", "", "Room name")
	fs.StringVar(&topic, "topic", "", "New topic")
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}
	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	resp, err := sess.RequestJSON(fmt.Sprintf("rogue.in.%s.cmd.topic", sess.Address), map[string]string{
		"name":  room,
		"topic": topic,
	})
	if err != nil {
		return err, g.JSONOut
	}
	return emitOutput(out, g.JSONOut, resp.Data, fmt.Sprintf("updated topic for #%s", room)), g.JSONOut
}

func runWho(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	var room string
	fs := flag.NewFlagSet("who", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&room, "room", "", "Filter by active room")
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}
	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	kv, err := sess.JS.KeyValue(store.BucketPresence)
	if err != nil {
		return err, g.JSONOut
	}
	keys, err := kv.Keys(nats.IgnoreDeletes())
	if err != nil && !errors.Is(err, nats.ErrNoKeysFound) {
		return err, g.JSONOut
	}
	online := make([]gatekeeper.PresenceRecord, 0, len(keys))
	for _, k := range keys {
		entry, err := kv.Get(k)
		if err != nil {
			continue
		}
		var rec gatekeeper.PresenceRecord
		if json.Unmarshal(entry.Value(), &rec) == nil {
			if room == "" || rec.ActiveRoom == room {
				online = append(online, rec)
			}
		}
	}
	if g.JSONOut {
		return json.NewEncoder(out).Encode(map[string]any{"count": len(online), "online": online}), true
	}
	for _, u := range online {
		fmt.Fprintf(out, "%s (Lv.%d) [#%s]\n", u.Address, u.Level, u.ActiveRoom)
	}
	return nil, false
}

func runDM(args []string, out, errOut io.Writer) (error, bool) {
	if len(args) == 0 {
		return fmt.Errorf("usage: rogue-nats dm <send|read> [flags]"), false
	}
	switch args[0] {
	case "send":
		return runDMSend(args[1:], out)
	case "read":
		return runDMRead(args[1:], out)
	default:
		fmt.Fprintln(errOut, "usage: rogue-nats dm <send|read> [flags]")
		return fmt.Errorf("unknown dm subcommand: %s", args[0]), false
	}
}

func runDMSend(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	var to string
	fs := flag.NewFlagSet("dm send", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&to, "to", "", "Recipient 0x address")
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}
	to = strings.ToLower(strings.TrimSpace(to))
	text := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if to == "" || text == "" {
		return &client.ExitError{Code: client.ExitNetworkOrError, ErrCode: "ERR_ARGS", Message: "--to and message text are required"}, g.JSONOut
	}

	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	profilesKV, err := sess.JS.KeyValue(store.BucketProfiles)
	if err != nil {
		return err, g.JSONOut
	}
	entry, err := profilesKV.Get(to)
	if err != nil {
		return &client.ExitError{
			Code:    client.ExitGatekeeperRejected,
			ErrCode: gatekeeper.ErrRecipientPubKeyUnknown,
			Message: "recipient has not connected yet to register their secp256k1 public key",
		}, g.JSONOut
	}
	var prof auth.ProfileRecord
	if err := json.Unmarshal(entry.Value(), &prof); err != nil {
		return err, g.JSONOut
	}

	enc, err := rcrypto.EncryptECIES(prof.PubKey, []byte(text))
	if err != nil {
		return err, g.JSONOut
	}

	resp, err := sess.RequestJSON(fmt.Sprintf("rogue.in.%s.dm.%s", sess.Address, to), enc)
	if err != nil {
		return err, g.JSONOut
	}
	return emitOutput(out, g.JSONOut, resp.Data, fmt.Sprintf("encrypted DM sent to %s", to)), g.JSONOut
}

func runDMRead(args []string, out io.Writer) (error, bool) {
	g := defaultGlobalOptions()
	var from string
	var limit int
	fs := flag.NewFlagSet("dm read", flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&from, "from", "", "Optional sender 0x filter")
	fs.IntVar(&limit, "limit", 200, "Maximum DMs to read")
	if err := fs.Parse(args); err != nil {
		return err, g.JSONOut
	}
	from = strings.ToLower(strings.TrimSpace(from))

	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	info, err := sess.JS.StreamInfo(store.StreamDM)
	if err != nil {
		return err, g.JSONOut
	}

	type decryptedDM struct {
		ID           string `json:"id"`
		Sender       string `json:"sender"`
		Dest         string `json:"dest"`
		Text         string `json:"text"`
		Ts           int64  `json:"ts"`
		TimestampISO string `json:"timestamp_iso"`
	}

	var results []decryptedDM
	if info.State.Msgs > 0 && info.State.LastSeq > 0 {
		low := info.State.FirstSeq
		if low == 0 {
			low = 1
		}
		targetSubj := fmt.Sprintf("rogue.dm.%s", sess.Address)
		for seq := info.State.LastSeq; seq >= low && len(results) < limit; seq-- {
			raw, err := sess.JS.GetMsg(store.StreamDM, seq)
			if err != nil || raw.Subject != targetSubj {
				if seq == 1 {
					break
				}
				continue
			}
			var dm gatekeeper.DMEnvelope
			if json.Unmarshal(raw.Data, &dm) != nil {
				if seq == 1 {
					break
				}
				continue
			}
			if from != "" && dm.Sender != from {
				if seq == 1 {
					break
				}
				continue
			}
			plain, err := rcrypto.DecryptECIES(sess.PrivKey, dm.Payload)
			if err != nil {
				if seq == 1 {
					break
				}
				continue
			}
			results = append(results, decryptedDM{
				ID:           dm.ID,
				Sender:       dm.Sender,
				Dest:         dm.Dest,
				Text:         string(plain),
				Ts:           dm.Ts,
				TimestampISO: time.UnixMilli(dm.Ts).UTC().Format(time.RFC3339),
			})
			if seq == 1 {
				break
			}
		}
	}

	for i, j := 0, len(results)-1; i < j; i, j = i+1, j-1 {
		results[i], results[j] = results[j], results[i]
	}

	if g.JSONOut {
		return json.NewEncoder(out).Encode(map[string]any{"count": len(results), "messages": results}), true
	}
	for _, dm := range results {
		fmt.Fprintf(out, "[%s] %s -> you: %s\n", dm.TimestampISO, dm.Sender, dm.Text)
	}
	return nil, false
}

func runAdmin(args []string, out, errOut io.Writer) (error, bool) {
	if len(args) == 0 {
		return fmt.Errorf("usage: rogue-nats admin <ban|unban|mute|unmute|delete-msg|stats> [flags]"), false
	}
	g := defaultGlobalOptions()
	var target, room, reason, duration string
	var seq uint64
	fs := flag.NewFlagSet("admin "+args[0], flag.ContinueOnError)
	registerGlobalFlags(fs, &g)
	fs.StringVar(&target, "target", "", "Target 0x address")
	fs.StringVar(&room, "room", "", "Room name")
	fs.StringVar(&reason, "reason", "", "Moderation reason")
	fs.StringVar(&duration, "duration", "15m", "Mute duration (e.g. 15m, 1h, 24h)")
	fs.Uint64Var(&seq, "seq", 0, "Message sequence number")
	if err := fs.Parse(args[1:]); err != nil {
		return err, g.JSONOut
	}

	sess, err := connectFromGlobals(g)
	if err != nil {
		return err, g.JSONOut
	}
	defer sess.Close()

	var cmd string
	var body any
	switch args[0] {
	case "ban":
		cmd = "ban"
		body = map[string]string{"target": target, "reason": reason}
	case "unban":
		cmd = "unban"
		body = map[string]string{"target": target}
	case "mute":
		d, err := time.ParseDuration(duration)
		if err != nil {
			return err, g.JSONOut
		}
		cmd = "mute"
		body = map[string]any{"target": target, "room": room, "duration_sec": int64(d.Seconds()), "reason": reason}
	case "unmute":
		cmd = "unmute"
		body = map[string]string{"target": target, "room": room}
	case "delete-msg":
		cmd = "delete_msg"
		body = map[string]any{"room": room, "seq": seq}
	case "stats":
		cmd = "stats"
		body = map[string]any{}
	default:
		fmt.Fprintln(errOut, "unknown admin subcommand:", args[0])
		return fmt.Errorf("unknown admin subcommand: %s", args[0]), g.JSONOut
	}

	resp, err := sess.RequestJSON(fmt.Sprintf("rogue.in.%s.cmd.%s", sess.Address, cmd), body)
	if err != nil {
		return err, g.JSONOut
	}
	return emitOutput(out, g.JSONOut, resp.Data, fmt.Sprintf("admin %s succeeded", args[0])), g.JSONOut
}

func emitOutput(out io.Writer, jsonOut bool, data any, textSummary string) error {
	if jsonOut {
		return json.NewEncoder(out).Encode(map[string]any{"ok": true, "data": data})
	}
	fmt.Fprintln(out, textSummary)
	return nil
}
