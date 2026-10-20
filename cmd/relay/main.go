// SPDX-License-Identifier: EUPL-1.2

// Command relay runs the eID Forge Remote relay (PLAN.md §1).
//
// Usage:
//
//	relay [serve]              run the relay (the default)
//	relay healthcheck [--ready] exit 0 if /livez (or /readyz) answers 200
//	relay version              print the release
//
// Settings come from RELAY_* environment variables (PLAN.md §8).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"eid-forge-remote/internal/config"
	"eid-forge-remote/internal/fit"
	"eid-forge-remote/internal/forward"
	"eid-forge-remote/internal/server"
)

// version is the release, stamped at build time with
// -ldflags "-X main.version=1.2.0" (PLAN.md §7). It is the only
// package-level variable: the linker can set nothing else.
var version = "0.0.0-dev"

// Exit codes. A configuration error exits with 2 (PLAN.md §6 R-13).
const (
	exitOK     = 0
	exitFail   = 1
	exitConfig = 2
)

// healthcheckTimeout bounds `relay healthcheck`, which a container runtime
// runs every few seconds (PLAN.md §7 O-3).
const healthcheckTimeout = 3 * time.Second

func main() {
	os.Exit(run(os.Args[1:], os.Environ(), os.Stdout, os.Stderr))
}

func run(args, environ []string, stdout, stderr io.Writer) int {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	switch {
	case cmd == "serve" && len(args) == 0:
		// SIGTERM is how Docker and Kubernetes stop a container, SIGINT is
		// Ctrl-C; either starts the graceful shutdown (PLAN.md §6 R-11).
		// serve takes the context so that tests can stop it without a signal.
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
		defer stop()
		return serve(ctx, "", environ, stdout, fit.JWKSClient())
	case cmd == "healthcheck":
		return healthcheck(context.Background(), args, environ, stderr)
	case cmd == "version" && len(args) == 0:
		if _, err := fmt.Fprintln(stdout, version); err != nil {
			return exitFail
		}
		return exitOK
	}
	_, _ = fmt.Fprintln(stderr, "usage: relay [serve | healthcheck [--ready] | version]") // stderr is all there is to report to
	return exitConfig
}

// serve runs the relay until ctx is done, then shuts down gracefully
// (PLAN.md §6 R-11). host is empty, every interface, in production, since
// the proxy reaches the relay over the container network; tests pass
// 127.0.0.1, so Windows Firewall does not ask about each test binary.
// jwksClient is fit.JWKSClient in production; tests pass one that trusts
// their loopback JWKS server.
func serve(ctx context.Context, host string, environ []string, stdout io.Writer, jwksClient *http.Client) int {
	// net/http can print raw unsolicited upstream bytes through the process's
	// standard logger. Only our explicit, classified slog records may reach
	// output (PLAN.md §10); Transport has no per-client diagnostic logger.
	log.SetOutput(io.Discard)
	cfg, unknown, err := config.Load(environ)
	level := slog.LevelInfo
	if err == nil {
		level = cfg.LogLevel
	}
	logger := newLogger(stdout, level)
	for _, name := range unknown {
		// A typo in a RELAY_* name would otherwise be silently ignored, and
		// it often explains a "required" error below.
		logger.Warn("unknown setting", "name", name)
	}
	if err != nil {
		var ce *config.Error
		if errors.As(err, &ce) {
			// Names the setting, never its value (PLAN.md §8).
			logger.Error("invalid configuration", "setting", ce.Setting, "reason", ce.Reason)
		} else {
			logger.Error("invalid configuration")
		}
		return exitConfig
	}
	attrs := []slog.Attr{
		slog.String("version", version),
		slog.String("go", runtime.Version()),
		slog.Bool("upstream_proxy", forward.ProxyInUse(cfg.Upstream.String())),
		slog.Bool("jwks_proxy", forward.ProxyInUse(cfg.JWKSURL)),
	}
	logger.LogAttrs(ctx, slog.LevelInfo, "starting", append(attrs, cfg.Summary()...)...)
	if cfg.Credential != nil && !cfg.CredentialFromFile {
		// An inline secret shows in docker inspect, orchestrator UIs and
		// /proc/<pid>/environ; _FILE keeps it in a secret mount (PLAN.md §8,
		// SR-4). A warning, not a refusal, so a test setup still starts.
		logger.Warn("credential set inline", "setting", "RELAY_UPSTREAM_AUTH", "use", "RELAY_UPSTREAM_AUTH_FILE")
	}

	keys := fit.NewCache(cfg.JWKSURL, jwksClient, cfg.JWKSRefresh, cfg.JWKSMaxAge, logger)
	verifier := fit.NewVerifier(fit.Policy{
		AppID:           cfg.AppID,
		EnvironmentID:   cfg.EnvironmentID,
		CloudIDs:        cfg.CloudIDs,
		InstallationIDs: cfg.InstallationIDs,
		ClockSkew:       cfg.ClockSkew,
	}, keys)
	fwd := forward.New(forward.Options{
		Upstream:   cfg.Upstream,
		Credential: cfg.Credential,
		RootCAs:    cfg.UpstreamCAs,
		Timeout:    cfg.UpstreamTimeout,
	})
	srv := server.New(server.Options{
		Config:    cfg,
		Verifier:  verifier,
		Keys:      keys,
		Forwarder: fwd,
		Logger:    logger,
		Version:   version,
	})

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(cfg.Port)))
	if err != nil {
		logger.Error("listen failed", "error", "listen")
		return exitFail
	}

	// The key worker outlives the listener: in-flight requests may still
	// need keys during the shutdown grace period (R-11).
	keyCtx, stopKeys := context.WithCancel(context.WithoutCancel(ctx))
	keysDone := make(chan struct{})
	go func() {
		defer close(keysDone)
		keys.Run(keyCtx)
	}()

	err = srv.Run(ctx, ln)
	stopKeys()
	<-keysDone
	switch {
	case errors.Is(err, server.ErrShutdownTimeout):
		logger.Warn("stopped", "error", "shutdown_timeout")
		return exitFail
	case err != nil:
		logger.Error("stopped", "error", "serve")
		return exitFail
	}
	logger.Info("stopped")
	return exitOK
}

// newLogger writes JSON lines to stdout (PLAN.md §7 Logging).
func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// healthcheck asks the local relay for /livez, or /readyz with --ready, and
// exits 0 only on 200 (PLAN.md §7 O-3). Every other outcome exits 1, a usage
// error included: Docker reserves exit code 2 for health checks. It reads
// only the port, never the credential.
func healthcheck(ctx context.Context, args, environ []string, stderr io.Writer) int {
	// The probe's HTTP client can emit the same raw net/http diagnostics as
	// serve. Keep its output restricted to the fixed errors below (§10).
	log.SetOutput(io.Discard)
	fs := flag.NewFlagSet("healthcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ready := fs.Bool("ready", false, "check /readyz instead of /livez")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "usage: relay healthcheck [--ready]") // stderr is all there is to report to
		return exitFail
	}
	port, err := config.HealthPort(environ)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err) // a *config.Error names the setting, never its value
		return exitFail
	}
	path := "/livez"
	if *ready {
		path = "/readyz"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+path, nil)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "healthcheck: bad request")
		return exitFail
	}
	client := &http.Client{
		Timeout: healthcheckTimeout,
		Transport: &http.Transport{
			Proxy: nil, // loopback; never through a proxy
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "healthcheck: no answer")
		return exitFail
	}
	// The process exits next, so the body is neither read nor reused.
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintln(stderr, "healthcheck: status", resp.StatusCode)
		return exitFail
	}
	return exitOK
}
