package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ahmetozer/gosamba/internal/config"
	"github.com/ahmetozer/gosamba/internal/discovery"
	"github.com/ahmetozer/gosamba/internal/logging"
	"github.com/ahmetozer/gosamba/internal/parent"
	"github.com/ahmetozer/gosamba/internal/transport"
	"github.com/ahmetozer/gosamba/internal/userdb"
)

// version is the build version; overridden at release time via
// -ldflags "-X main.version=...".
var version = "0.0.0-dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-V":
			fmt.Println("gosamba", version)
			return
		case "hash":
			if err := runHash(os.Stdin, os.Stdout, os.Stderr); err != nil {
				fmt.Fprintln(os.Stderr, "gosamba:", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gosamba:", err)
		os.Exit(1)
	}
}

// runHash implements the "hash" subcommand: read a password and print its NT
// hash (the value for a user's nt_hash). When stdin is a terminal it prompts on
// stderr so the hash on stdout stays clean for capture/piping.
func runHash(in *os.File, out, errOut io.Writer) error {
	if fi, err := in.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(errOut, "Password: ")
	}
	h, err := nthashFromReader(in)
	if err != nil {
		return err
	}
	fmt.Fprintln(out, h)
	return nil
}

// nthashFromReader reads a single line (one password) and returns its NT hash as
// a 32-char hex string. A trailing CR/LF is stripped; an empty password is an
// error.
func nthashFromReader(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	pw := strings.TrimRight(line, "\r\n")
	if pw == "" {
		return "", errors.New("empty password")
	}
	h := userdb.NTHash(pw)
	return hex.EncodeToString(h[:]), nil
}

func run(args []string) error {
	cli, err := config.ParseCLI(args)
	if err != nil {
		return err
	}

	var file config.File
	if cli.ConfigFile != nil {
		f, err := config.ParseFile(*cli.ConfigFile)
		if err != nil {
			return fmt.Errorf("config file: %w", err)
		}
		file = f
	}

	cfg, err := config.Merge(cli, file)
	if err != nil {
		return err
	}
	if err := config.Validate(&cfg); err != nil {
		return fmt.Errorf("config invalid: %w", err)
	}

	log, err := logging.New(os.Stderr, cfg.Log.Level, cfg.Log.Format)
	if err != nil {
		return err
	}

	if hasPlaintextPasswordFlag(args) {
		log.Warn("plaintext password on -u is visible to other processes via /proc/PID/cmdline; use -c with nt_hash for production")
	}

	baseOpts := parent.ConnOptions{
		RequireEncryption: cfg.Server.Encryption == config.EncryptionRequired,
		RequireSigning:    cfg.Server.Signing == config.SigningRequired,
		MaxIOSize:         8 << 20,
		Users:             cfg.Users,
		Shares:            cfg.Shares,
		DurableTimeout:    cfg.Server.DurableTimeout,
	}

	// Worker mode: we were re-exec'd to serve a single inherited connection.
	// Parse config exactly as above (no secrets cross the boundary — only the
	// socket fd), then serve the one connection and exit. Privilege drop fires
	// inside RunWorker after SESSION_SETUP resolves the user.
	if parent.IsWorker() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		opts := baseOpts
		// Each worker owns its own connection; a per-worker durable table is
		// fine because the worker only serves one connection. However, because
		// each worker is a separate process, the durable table is not shared
		// across connections: durable-handle reclaim after a TCP reconnect will
		// not work under --per-user-privdrop.
		opts.Durable = parent.NewDurableTable()
		opts.DurableTimeout = cfg.Server.DurableTimeout
		// Likewise the session index: one worker process serves exactly one
		// connection, so "server-scoped" and "connection-scoped" are the same
		// thing here. PreviousSessionId therefore only reaches a previous
		// session on this same connection under --per-user-privdrop.
		opts.Sessions = parent.NewSessionIndex()
		if err := parent.RunWorker(ctx, log, transport.MaxFrameSize, opts); err != nil {
			return fmt.Errorf("worker: %w", err)
		}
		return nil
	}

	log.Info("gosamba starting",
		"version", version,
		"listen", cfg.Server.Listen,
		"shares", len(cfg.Shares),
		"users", len(cfg.Users),
		"encryption", string(cfg.Server.Encryption),
		"signing", string(cfg.Server.Signing),
	)

	// Gating: decide whether to serve via per-connection re-exec workers (so
	// each connection can drop to the authenticated user's uid) or in-process
	// exactly as before. The default path is byte-for-byte unchanged.
	usePrivdrop := parent.ShouldUsePrivdropWorker(cfg.Server.PerUserPrivdrop, os.Geteuid(), cfg.Users)
	if usePrivdrop && os.Geteuid() != 0 {
		log.Warn("per-user privilege drop requested but not running as root; serving without privilege drop")
		usePrivdrop = false
	}
	if usePrivdrop {
		log.Warn("durable handle reclaim is disabled under --per-user-privdrop (each connection runs in its own worker process); clients will re-open handles after reconnect")
	}

	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Server.Listen, err)
	}
	log.Info("listening", "addr", ln.Addr().String(), "per_user_privdrop", usePrivdrop)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-sigs
		log.Info("shutdown signal received", "signal", s.String())
		cancel()
	}()

	// mDNS/Bonjour: advertise the SMB service so Apple clients auto-discover it.
	if cfg.Server.MDNS && !parent.IsWorker() {
		host, port, err := net.SplitHostPort(ln.Addr().String())
		if err == nil {
			var portNum int
			fmt.Sscanf(port, "%d", &portNum)
			instance, _ := os.Hostname()
			if host == "" || host == "0.0.0.0" {
				h, _ := os.Hostname()
				host = h
			}
			mdnsCloser, mdnsErr := discovery.Advertise(ctx, instance, host, portNum, log)
			if mdnsErr != nil {
				log.Debug("mDNS advertise failed (continuing without it)", "err", mdnsErr)
			} else {
				defer mdnsCloser.Close()
			}
		}
	}

	// One server-scoped durable-handle table, shared across every connection so
	// durable opens survive a dropped TCP connection and can be reclaimed.
	durable := parent.NewDurableTable()
	// Sweep expired durable entries every 30 s so abandoned handles don't leak
	// fds indefinitely. The sweeper stops when the server context is cancelled.
	durable.StartSweeper(ctx, 30*time.Second)

	// One server-scoped session index, shared the same way. It is what lets a
	// client whose own side broke reconnect on a NEW TCP connection, name its
	// old session in PreviousSessionId, and have the server close it —
	// releasing the descriptors, byte-range locks, share-mode reservations,
	// resume keys and change-notify watches that would otherwise block the
	// reconnecting client until the idle reaper ran (MS-SMB2 §3.3.5.5.3).
	sessionIndex := parent.NewSessionIndex()

	srv := &parent.Listener{
		Log:      log,
		MaxFrame: transport.MaxFrameSize,
		ReExec:   usePrivdrop,
		Handler: func(ctx context.Context, c net.Conn, lg *slog.Logger, maxFrame uint32) {
			opts := baseOpts
			opts.Durable = durable
			opts.Sessions = sessionIndex
			parent.ServeConn(ctx, c, lg, maxFrame, opts)
		},
	}

	if err := srv.Serve(ctx, ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	log.Info("gosamba stopped")
	return nil
}

func hasPlaintextPasswordFlag(args []string) bool {
	for _, a := range args {
		if a == "-u" || a == "--user" || strings.HasPrefix(a, "-u=") || strings.HasPrefix(a, "--user=") {
			return true
		}
	}
	return false
}
