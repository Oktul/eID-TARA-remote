// SPDX-License-Identifier: EUPL-1.2

// Package server is the relay's HTTP front end. It applies the check order
// of PLAN.md §4.2, writes the responses of §4.3, answers the health and info
// endpoints of §4.1, logs one line per request (§10) and implements the
// server-side robustness rules of §6: timeouts, the concurrency cap, panic
// recovery and graceful shutdown.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"eid-forge-remote/internal/config"
	"eid-forge-remote/internal/fit"
	"eid-forge-remote/internal/forward"
)

// Server limits from PLAN.md §6 R-1. The write timeout is the upstream
// timeout plus config.WriteTimeoutMargin.
const (
	ReadHeaderTimeout = 5 * time.Second
	ReadTimeout       = 10 * time.Second
	IdleTimeout       = 60 * time.Second
	MaxHeaderBytes    = 16 << 10
)

// Fixed limits sized for token calls (PLAN.md D8, §6 R-4 and R-5; owner,
// 2026-10-16). With forward.MaxResponseBytes they bound the bodies held at
// once to MaxConcurrent × 128 KiB = 6.25 MiB.
const (
	// MaxRequestBytes is the request body limit; a token request is a few KB.
	MaxRequestBytes = 64 << 10
	// MaxConcurrent is the number of requests forwarded at once; above it,
	// 503 too_busy.
	MaxConcurrent = 50
)

// ProtocolVersion is the relay protocol this code speaks (PLAN.md §4).
const ProtocolVersion = 1

// Header names and error codes are wire protocol (PLAN.md §4.3). Changing one
// is a protocol change and follows §4.6.
const (
	headerProtocol       = "Relay-Protocol"
	headerVersion        = "Relay-Version"
	headerUpstreamStatus = "Relay-Upstream-Status"
	headerError          = "Relay-Error"

	codeInvalidToken        = "invalid_token"
	codeRouteNotAllowed     = "route_not_allowed"
	codeBodyTooLarge        = "body_too_large"
	codeInternal            = "internal_error"
	codeUpstreamUnreachable = "upstream_unreachable"
	codeUpstreamTooLarge    = "upstream_too_large"
	codeNotReady            = "not_ready"
	codeTooBusy             = "too_busy"
	codeUpstreamTimeout     = "upstream_timeout"
)

// Log-only error classes for failures that have no relay error code of their
// own (PLAN.md §10: fixed classifications, never raw errors).
const (
	errClassRequestRead    = "request_read"
	errClassClientCanceled = "client_canceled"
	errClassPanic          = "panic"
)

// Endpoints the relay answers itself (PLAN.md §4.1). They are matched against
// the raw request target, so "/livez?x" or "//livez" is not a health check.
const (
	pathLive  = "/livez"
	pathReady = "/readyz"
	pathInfo  = "/relay/v1/info"

	routeLive      = "GET " + pathLive
	routeReady     = "GET " + pathReady
	routeInfo      = "GET " + pathInfo
	routeUnmatched = "unmatched"
)

// ErrShutdownTimeout reports that in-flight requests were still running when
// RELAY_SHUTDOWN_GRACE ended, so their connections were closed.
var ErrShutdownTimeout = errors.New("server: shutdown grace period exceeded")

// Options are the server's dependencies.
type Options struct {
	Config    *config.Config
	Verifier  *fit.Verifier
	Keys      *fit.Cache
	Forwarder *forward.Forwarder
	Logger    *slog.Logger
	Version   string // the release, sent as Relay-Version
}

// Server is the relay's http.Handler and its listener lifecycle.
type Server struct {
	cfg      *config.Config
	verifier *fit.Verifier
	keys     *fit.Cache
	fwd      *forward.Forwarder
	log      *slog.Logger
	version  string
	info     []byte // the /relay/v1/info body, fixed at startup

	// slots is the forwarding semaphore (PLAN.md §6 R-5). Only an
	// authenticated token POST takes a slot, so a full relay still answers
	// its probes, info and every refusal.
	slots chan struct{}

	// stopping turns /readyz false once shutdown begins (R-11).
	stopping atomic.Bool
}

// New builds a Server. It starts nothing; Run serves.
func New(o Options) *Server {
	info, err := json.Marshal(struct {
		RelayVersion    string   `json:"relay_version"`
		ProtocolVersion int      `json:"protocol_version"`
		UpstreamURL     string   `json:"upstream_url"`
		Routes          []string `json:"routes"`
		CredentialSet   bool     `json:"credential_set"`
	}{o.Version, ProtocolVersion, o.Config.Upstream.String(), []string{forward.TokenRoute}, o.Config.Credential != nil})
	if err != nil {
		// Encoding strings, ints and a bool cannot fail.
		panic("server: encode info: " + err.Error())
	}
	return &Server{
		cfg:      o.Config,
		verifier: o.Verifier,
		keys:     o.Keys,
		fwd:      o.Forwarder,
		log:      o.Logger,
		version:  o.Version,
		info:     info,
		slots:    make(chan struct{}, MaxConcurrent),
	}
}

// record collects one request's log fields (PLAN.md §10). Every value is a
// constant or verified data.
type record struct {
	requestID      string
	method         string
	route          string
	upstreamStatus int
	err            string
	authReason     string
	cloudID        string
	authenticated  bool
	health         bool
}

// ServeHTTP is the whole request path. A panic anywhere below is recovered
// here and becomes 500 internal_error (R-6); handlers start no goroutines,
// so no panic can escape this frame.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	sw := &statusWriter{ResponseWriter: w}
	rec := &record{requestID: requestID(r.Header), method: forward.LogMethod(r.Method), route: routeUnmatched}
	defer func() {
		// The panic value is never logged: it may hold request data.
		if recover() != nil {
			rec.err = errClassPanic
			if sw.status == 0 {
				s.writeError(sw, rec, http.StatusInternalServerError, codeInternal)
			}
		}
		s.logRequest(r.Context(), rec, sw.status, time.Since(start))
	}()
	s.handle(sw, r, rec)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request, rec *record) {
	// An early answer refuses the body. Without close, net/http drains it
	// before flushing; a slow body can outlast the write deadline and lose
	// that answer (PLAN.md §4.3, §6). Restore keep-alive only after a full read.
	if r.ContentLength != 0 {
		w.Header().Set("Connection", "close")
	}
	// Health checks: exact method and raw target, no query, before the
	// semaphore and FIT verification (PLAN.md §4.2). They contact nothing.
	if r.Method == http.MethodGet && (r.RequestURI == pathLive || r.RequestURI == pathReady) {
		rec.health = true
		rec.route = routeLive
		if r.RequestURI == pathReady {
			rec.route = routeReady
			if s.stopping.Load() || !s.keys.Ready() {
				s.writeError(w, rec, http.StatusServiceUnavailable, codeNotReady)
				return
			}
		}
		writeJSON(w, http.StatusOK, []byte(`{"status":"ok"}`))
		return
	}

	// Step 1: usable keys, then the FIT. Shutdown does not stop in-flight or
	// keep-alive requests from being served; only /readyz reflects it.
	if !s.keys.Ready() {
		s.writeError(w, rec, http.StatusServiceUnavailable, codeNotReady)
		return
	}
	claims, err := s.verifier.Verify(r.Context(), r.Header.Values("Authorization"))
	if err != nil {
		var fe *fit.Error
		switch {
		case errors.Is(err, fit.ErrNotReady):
			// The snapshot expired between the readiness check and the
			// key lookup; the token was never judged.
			s.writeError(w, rec, http.StatusServiceUnavailable, codeNotReady)
		case errors.As(err, &fe):
			rec.authReason = string(fe.Reason)
			s.writeError(w, rec, http.StatusUnauthorized, codeInvalidToken)
		default:
			s.writeError(w, rec, http.StatusUnauthorized, codeInvalidToken)
		}
		return
	}
	rec.authenticated = true
	rec.cloudID = claims.CloudID

	// Step 2: the route. Only after authentication, so a caller without a
	// valid FIT learns nothing about the routes (F-2).
	if r.Method == http.MethodGet && r.RequestURI == pathInfo {
		rec.route = routeInfo
		w.Header().Set(headerVersion, s.version)
		writeJSON(w, http.StatusOK, s.info)
		return
	}
	// Compare the raw request target, never a cleaned or decoded path.
	if r.Method != http.MethodPost || r.RequestURI != forward.TokenPath {
		s.writeError(w, rec, http.StatusNotFound, codeRouteNotAllowed)
		return
	}
	rec.route = forward.TokenRoute

	// Step 3: a concurrency slot without waiting (R-5). Only now, so a
	// caller without a valid FIT, or one waiting for a key refresh, never
	// holds a slot a token exchange needs (PLAN.md §4.2, owner 2026-10-20).
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		s.writeError(w, rec, http.StatusServiceUnavailable, codeTooBusy)
		return
	}

	// Step 4: the body, bounded (R-4).
	body, err := readBody(w, r)
	// Restart the write deadline, which net/http started at the request
	// header, whether the body was read or refused: a slow body or key wait
	// must not eat the answer's time, or a token exchange could succeed
	// upstream while its answer, or a late 413, is dropped (PLAN.md §6, R-8).
	// The error only means the writer cannot set deadlines (a test
	// recorder); the server's timeout then applies.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(s.cfg.UpstreamTimeout + config.WriteTimeoutMargin))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			// Closing, rather than reading the rest of the body to reuse
			// the connection, answers at once; this also covers the
			// declared Content-Length, which never reaches MaxBytesReader.
			w.Header().Set("Connection", "close")
			s.writeError(w, rec, http.StatusRequestEntityTooLarge, codeBodyTooLarge)
			return
		}
		// A client that disconnects, times out or sends broken chunked
		// framing gets no answer: this is a transport-level failure, where
		// relay headers are not promised (PLAN.md §4.3).
		rec.err = errClassRequestRead
		s.abort(w, rec)
		return
	}
	w.Header().Del("Connection")

	// Step 5: forward (PLAN.md §5).
	resp, err := s.fwd.Forward(r.Context(), r.Header, body)
	if err != nil {
		switch {
		case errors.Is(err, forward.ErrTooLarge):
			s.writeError(w, rec, http.StatusBadGateway, codeUpstreamTooLarge)
		case errors.Is(err, forward.ErrTimeout):
			s.writeError(w, rec, http.StatusGatewayTimeout, codeUpstreamTimeout)
		case errors.Is(err, forward.ErrCanceled):
			// Nobody is left to read the answer; the code is for the log.
			rec.err = errClassClientCanceled
			s.writeError(w, rec, http.StatusBadGateway, codeUpstreamUnreachable)
		default:
			s.writeError(w, rec, http.StatusBadGateway, codeUpstreamUnreachable)
		}
		return
	}
	rec.upstreamStatus = resp.Status
	s.writeUpstream(w, resp)
}

// readBody reads the request body up to MaxRequestBytes.
// http.MaxBytesReader, unlike a plain io.LimitReader, also tells net/http
// that the limit was hit, so it half-closes the connection after the 413 and
// waits briefly: bytes the client is still sending cannot reset the
// connection before it has read the 413. Only net/http's own ResponseWriter
// takes that signal, so it gets that one, not the statusWriter.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.ContentLength > MaxRequestBytes {
		return nil, &http.MaxBytesError{Limit: MaxRequestBytes}
	}
	if sw, ok := w.(*statusWriter); ok {
		w = sw.ResponseWriter
	}
	return io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
}

// writeUpstream sends an upstream answer as PLAN.md D7 requires: always 200,
// the upstream status in Relay-Upstream-Status, the body unchanged and only
// the allowed headers. The relay's own headers are set last, so an upstream
// header can never replace them (§5).
func (s *Server) writeUpstream(w http.ResponseWriter, resp *forward.Response) {
	h := w.Header()
	for name, values := range resp.Header {
		h[name] = values
	}
	if _, ok := resp.Header["Content-Type"]; !ok {
		// Without this, net/http would sniff the body and invent a
		// Content-Type the upstream never sent.
		h["Content-Type"] = nil
	}
	// A token answer must never be stored (RFC 6749 §5.1); TARA says so
	// itself, and the relay adds it only when the upstream did not
	// (PLAN.md §4.3, SR-8).
	if _, ok := resp.Header["Cache-Control"]; !ok {
		h.Set("Cache-Control", "no-store")
	}
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set(headerProtocol, strconv.Itoa(ProtocolVersion))
	h.Set(headerVersion, s.version)
	h.Set(headerUpstreamStatus, strconv.Itoa(resp.Status))
	h.Set("Content-Length", strconv.Itoa(len(resp.Body)))
	w.WriteHeader(http.StatusOK)
	// A write error means the caller has gone; there is no one to tell.
	_, _ = w.Write(resp.Body)
}

// writeError sends a relay-generated error (PLAN.md §4.3). Relay-Version is
// added only after a valid FIT, so an anonymous caller cannot read the
// release.
func (s *Server) writeError(w http.ResponseWriter, rec *record, status int, code string) {
	if rec.err == "" {
		rec.err = code
	}
	h := w.Header()
	h.Set(headerError, code)
	if rec.authenticated {
		h.Set(headerVersion, s.version)
	}
	writeJSON(w, status, []byte(`{"error":"`+code+`"}`))
}

// writeJSON sends a relay-generated body with the protocol header that every
// application response carries (F-8). Its answers are never worth storing
// or sniffing (PLAN.md §4.3, SR-8).
func writeJSON(w http.ResponseWriter, status int, body []byte) {
	h := w.Header()
	h.Set(headerProtocol, strconv.Itoa(ProtocolVersion))
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	// A write error means the caller has gone; there is no one to tell.
	_, _ = w.Write(body)
}

// abort drops the connection without a response. If the connection cannot
// be taken over, a 500 is the fallback: returning without writing would
// make net/http send an empty 200.
func (s *Server) abort(w http.ResponseWriter, rec *record) {
	conn, _, err := http.NewResponseController(w).Hijack()
	if err != nil {
		s.writeError(w, rec, http.StatusInternalServerError, codeInternal)
		return
	}
	// The connection is dropped on purpose; a close error changes nothing.
	_ = conn.Close()
}

// requestID returns the validated x-b3-traceid, the one header value the
// relay may log (PLAN.md §10), or a random ID. A missing, repeated or
// malformed trace header is replaced, never logged.
func requestID(h http.Header) string {
	if v := h.Values("X-B3-Traceid"); len(v) == 1 && validTraceID(v[0]) {
		return strings.ToLower(v[0])
	}
	var id [16]byte
	// crypto/rand.Read never returns an error (it crashes the program
	// instead, since Go 1.24).
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

// validTraceID reports a B3 trace ID: 16 or 32 hexadecimal characters, not
// all zero.
func validTraceID(s string) bool {
	if len(s) != 16 && len(s) != 32 {
		return false
	}
	nonZero := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '0':
		case c >= '1' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
			nonZero = true
		default:
			return false
		}
	}
	return nonZero
}

// logRequest writes the request's single log line (PLAN.md §10). Health
// probes log at debug, since an orchestrator sends them every few seconds.
func (s *Server) logRequest(ctx context.Context, rec *record, status int, d time.Duration) {
	level := slog.LevelInfo
	if rec.health {
		level = slog.LevelDebug
	}
	attrs := []slog.Attr{
		slog.String("request_id", rec.requestID),
		slog.String("method", rec.method),
		slog.String("route", rec.route),
		slog.Int("status", status),
		slog.Int64("duration_ms", d.Milliseconds()),
	}
	if rec.upstreamStatus != 0 {
		attrs = append(attrs, slog.Int("upstream_status", rec.upstreamStatus))
	}
	if rec.err != "" {
		attrs = append(attrs, slog.String("error", rec.err))
	}
	if rec.authReason != "" {
		attrs = append(attrs, slog.String("auth_reason", rec.authReason))
	}
	if rec.cloudID != "" {
		attrs = append(attrs, slog.String("cloud_id", rec.cloudID))
	}
	s.log.LogAttrs(ctx, level, "request", attrs...)
}

// statusWriter records the status for the log line. Unwrap lets
// http.ResponseController reach the connection for abort.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Run serves on ln until ctx is done, then shuts down (PLAN.md §6 R-11):
// /readyz turns false, the listener closes, in-flight requests get
// RELAY_SHUTDOWN_GRACE to finish, and remaining connections are closed.
// The serving goroutine belongs to Run and has exited when Run returns.
func (s *Server) Run(ctx context.Context, ln net.Listener) error {
	hs := s.httpServer()
	served := make(chan error, 1)
	go func() { served <- hs.Serve(ln) }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	s.stopping.Store(true)
	graceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.ShutdownGrace)
	defer cancel()
	err := hs.Shutdown(graceCtx)
	if err != nil {
		// Close ends the remaining connections; its error adds nothing.
		_ = hs.Close()
		err = ErrShutdownTimeout
	}
	if serveErr := <-served; !errors.Is(serveErr, http.ErrServerClosed) && err == nil {
		err = serveErr
	}
	return err
}

// httpServer builds the listener-side server with the limits of PLAN.md §6.
func (s *Server) httpServer() *http.Server {
	// HTTP/1.1 only, inbound and outbound (PLAN.md §7).
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: ReadHeaderTimeout,
		ReadTimeout:       ReadTimeout,
		WriteTimeout:      s.cfg.UpstreamTimeout + config.WriteTimeoutMargin, // config rejects an overflowing sum
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		Protocols:         protocols,
		// Without this, net/http answers "OPTIONS *" itself, before the
		// FIT check and without relay headers.
		DisableGeneralOptionsHandler: true,
		ErrorLog:                     log.New(serverErrorWriter{s.log}, "", 0),
	}
}

// serverErrorWriter replaces net/http's error log. Its messages, about
// malformed requests for one, contain client addresses and raw
// error text, which PLAN.md §10 keeps out of the logs, so only a fixed
// message is written.
type serverErrorWriter struct{ log *slog.Logger }

func (w serverErrorWriter) Write(p []byte) (int, error) {
	w.log.Debug("http server error")
	return len(p), nil
}
