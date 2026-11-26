// SPDX-License-Identifier: EUPL-1.2

package server_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"eid-tara-remote/internal/config"
	"eid-tara-remote/internal/fit"
	"eid-tara-remote/internal/forward"
	"eid-tara-remote/internal/server"
)

// Synthetic identifiers. None belongs to a real app, environment, site or
// installation (CONTRIBUTING.md, Tests).
const (
	testAppID     = "ari:cloud:ecosystem::app/00000000-0000-4000-8000-000000000001"
	testEnvID     = "ari:cloud:ecosystem::environment/00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000002"
	testInstallID = "ari:cloud:ecosystem::installation/00000000-0000-4000-8000-000000000003"
	testSiteA     = "00000000-0000-4000-8000-00000000000a" // allowed
	testSiteB     = "00000000-0000-4000-8000-00000000000b" // allowed
	testKID       = "synthetic-relay-key"
	testVersion   = "1.2.0"
)

// secretMarker is planted in every input that must never reach a log line:
// paths, queries, headers, bodies, the credential and upstream error text
// (PLAN.md §10, §13).
const secretMarker = "SECRETMARKER"

// testCredential is the synthetic RELAY_UPSTREAM_AUTH value.
const testCredential = "Basic " + secretMarker + "credential"

// upstreamBody is the answer of the default synthetic upstream.
const upstreamBody = `{"access_token":"synthetic-access-token","token_type":"Bearer"}`

// unset removes a setting from the synthetic environment.
const unset = "\x00unset"

// waitTimeout only ends a test that would otherwise hang; no test passes by
// running into it. pollInterval paces the checks of state that changes in
// another goroutine.
const (
	waitTimeout  = 10 * time.Second
	pollInterval = 2 * time.Millisecond
)

// signingKeys are generated once per test run, so no private key is ever
// committed (CONTRIBUTING.md, Tests).
type signingKeys struct {
	published *rsa.PrivateKey // served by the JWKS under testKID
	other     *rsa.PrivateKey // never published
}

var testKeys = sync.OnceValue(func() signingKeys {
	gen := func() *rsa.PrivateKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		return k
	}
	return signingKeys{published: gen(), other: gen()}
})

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// serveJWKS answers with a JWKS that holds only the published key.
func serveJWKS(w http.ResponseWriter, _ *http.Request) {
	pub := testKeys().published.PublicKey
	doc := `{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"` + testKID +
		`","n":"` + b64(pub.N.Bytes()) + `","e":"` + b64(big.NewInt(int64(pub.E)).Bytes()) + `"}]}`
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, doc) // the cache reports a failed read as a failed refresh
}

// jwksUnavailable keeps a relay from ever loading keys.
func jwksUnavailable(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "unavailable", http.StatusServiceUnavailable)
}

// fitClaims returns the claims of a valid FIT for the synthetic app,
// environment and site A (PLAN.md §4.4). Tests change single claims.
func fitClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss": "forge/invocation-token",
		"aud": testAppID,
		"exp": now.Add(4 * time.Minute).Unix(),
		"nbf": now.Add(-5 * time.Second).Unix(),
		"app": map[string]any{
			"id":             testAppID,
			"installationId": testInstallID,
			"environment":    map[string]any{"type": "DEVELOPMENT", "id": testEnvID},
		},
		"context": map[string]any{"cloudId": testSiteA, "moduleKey": "token-relay"},
	}
}

// signFIT returns claims as an RS256 compact JWS under testKID, signed with
// key.
func signFIT(t testing.TB, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	return signFITKID(t, key, testKID, claims)
}

// signFITKID is signFIT under the key ID kid.
func signFITKID(t testing.TB, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := b64([]byte(`{"alg":"RS256","kid":"`+kid+`","typ":"JWT"}`)) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func validFIT(t testing.TB) string { return signFIT(t, testKeys().published, fitClaims()) }

func bearer(token string) http.Header { return http.Header{"Authorization": {"Bearer " + token}} }

// environ returns the synthetic settings of a relay with overrides applied.
// Only the required settings, the credential and the test's own endpoints
// are given, so every other setting has its real default (PLAN.md §8).
func environ(upstreamURL, jwksURL string, overrides map[string]string) []string {
	settings := map[string]string{
		"RELAY_APP_ID":         testAppID,
		"RELAY_ENVIRONMENT_ID": testEnvID,
		"RELAY_CLOUD_IDS":      testSiteA + "," + testSiteB,
		"RELAY_UPSTREAM_URL":   upstreamURL,
		// The synthetic upstream is on loopback, not TARA (PLAN.md §8, SR-5).
		"RELAY_UPSTREAM_ANY_HOST": "true",
		"RELAY_UPSTREAM_AUTH":     "Authorization: " + testCredential,
		"RELAY_JWKS_URL":          jwksURL,
	}
	for k, v := range overrides {
		if v == unset {
			delete(settings, k)
		} else {
			settings[k] = v
		}
	}
	out := make([]string, 0, len(settings))
	for k, v := range settings {
		out = append(out, k+"="+v)
	}
	return out
}

// logSink collects a relay's JSON log lines. slog's JSON handler writes each
// record with one Write call, so every Write is one line.
type logSink struct {
	mu   sync.Mutex // guards text
	text bytes.Buffer
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.text.Write(p)
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.text.String()
}

// requests returns the per-request lines (PLAN.md §10) in the order they
// were written.
func (s *logSink) requests(t testing.TB) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(s.String()) {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		if m["msg"] == "request" {
			out = append(out, m)
		}
	}
	return out
}

// waitRequests waits for n request lines. The server writes a line after
// the handler returns, which can be after the client has its answer.
func (s *logSink) waitRequests(t testing.TB, n int) []map[string]any {
	t.Helper()
	var lines []map[string]any
	waitUntil(t, strconv.Itoa(n)+" request log lines", func() bool {
		lines = s.requests(t)
		return len(lines) >= n
	})
	return lines
}

// field returns a log value as text; JSON numbers print without a fraction.
func field(line map[string]any, key string) string {
	v, ok := line[key]
	if !ok {
		return "<absent>"
	}
	return fmt.Sprint(v)
}

func keys(line map[string]any) []string {
	out := make([]string, 0, len(line))
	for k := range line {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// waitUntil polls cond until it holds. The state it waits for changes in
// goroutines that cross real sockets, which a testing/synctest bubble cannot
// observe, so it polls on the real clock.
func waitUntil(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.NewTimer(waitTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(pollInterval)
	defer tick.Stop()
	for !cond() {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// gate is an upstream that holds every call until the test opens it, so a
// test can keep forwarding slots busy. Tests defer release, which runs
// before the servers' cleanups.
type gate struct {
	entered chan struct{}
	open    chan struct{}
	once    sync.Once
}

func newGate() *gate {
	return &gate{entered: make(chan struct{}, 64), open: make(chan struct{})}
}

func (g *gate) release() { g.once.Do(func() { close(g.open) }) }

// handler reads the request first, so net/http watches the connection and
// cancels the request's context when the relay gives up the call.
func (g *gate) handler(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body) // a failed read only ends the call sooner
	g.entered <- struct{}{}
	select {
	case <-g.open:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, upstreamBody) // the relay reports a lost answer itself
	case <-r.Context().Done():
		// Returning would send an empty 200 that can still reach the relay
		// after it gave up, since Go's transport keeps a response that races
		// its cancellation; the relay would then forward it instead of
		// failing the call.
		panic(http.ErrAbortHandler)
	}
}

func (g *gate) waitEntered(t testing.TB, n int) {
	t.Helper()
	deadline := time.NewTimer(waitTimeout)
	defer deadline.Stop()
	for range n {
		select {
		case <-g.entered:
		case <-deadline.C:
			t.Fatalf("timed out waiting for %d held calls", n)
		}
	}
}

// answerOK is the default upstream: a token answer.
func answerOK(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, upstreamBody)
}

func counted(n *atomic.Int64, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		h(w, r)
	})
}

// newTLSServer starts a loopback HTTPS server. Closing the client
// connections first ends handlers that wait for their request's context, so
// cleanup cannot hang on a held call.
func newTLSServer(t testing.TB, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	// TLS failures some tests cause on purpose would otherwise be printed.
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(func() {
		s.CloseClientConnections()
		s.Close()
	})
	return s
}

// closedPortURL returns an https URL on a loopback port nothing listens on.
func closedPortURL(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return "https://" + addr
}

type relayOptions struct {
	env               map[string]string // setting overrides; unset removes one
	upstream          http.HandlerFunc  // nil: answerOK
	jwks              http.HandlerFunc  // nil: serveJWKS
	upstreamURL       string            // replaces the synthetic upstream server
	untrustedUpstream bool              // the forwarder trusts no CA
	nilForwarder      bool              // Options.Forwarder is nil, so forwarding panics
	notReady          bool              // do not wait for the first key snapshot
	lookupNotReady    bool              // the Verifier's key lookups find no snapshot; the cache stays ready
	run               bool              // serve with Server.Run instead of httptest
}

// keySource is what fit.NewVerifier takes: the relay's *fit.Cache or a fake.
type keySource interface {
	Key(ctx context.Context, kid string) (*rsa.PublicKey, error)
}

// expiredKeys answers every lookup as the cache does once its snapshot has
// expired, which can happen between the server's readiness check and the
// Verifier's key lookup (PLAN.md §4.2 step 1).
type expiredKeys struct{}

func (expiredKeys) Key(context.Context, string) (*rsa.PublicKey, error) { return nil, fit.ErrNotReady }

// relay is one relay under test, built from real parts: config.Load on a
// synthetic environment, the fit cache fetching from a TLS JWKS server,
// fit.NewVerifier and forward.New in front of a TLS upstream.
type relay struct {
	cfg          *config.Config
	srv          *server.Server
	keys         *fit.Cache
	logs         *logSink
	url, addr    string // the relay's base URL and host:port
	upstreamURL  string // RELAY_UPSTREAM_URL
	client       *http.Client
	upstreamHits atomic.Int64
	jwksHits     atomic.Int64

	// Set with relayOptions.run.
	cancelRun context.CancelFunc
	runDone   chan struct{}
	runErr    error // written before runDone closes
}

func newRelay(t *testing.T, o relayOptions) *relay {
	t.Helper()
	r := &relay{logs: &logSink{}}
	logger := slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	jwksHandler := o.jwks
	if jwksHandler == nil {
		jwksHandler = serveJWKS
	}
	jwks := newTLSServer(t, counted(&r.jwksHits, jwksHandler))

	upstreamCAs := x509.NewCertPool()
	r.upstreamURL = o.upstreamURL
	if r.upstreamURL == "" {
		h := o.upstream
		if h == nil {
			h = answerOK
		}
		up := newTLSServer(t, counted(&r.upstreamHits, h))
		r.upstreamURL = up.URL
		if !o.untrustedUpstream {
			upstreamCAs.AddCert(up.Certificate())
		}
	}

	cfg, unknown, err := config.Load(environ(r.upstreamURL, jwks.URL+"/.well-known/jwks.json", o.env))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if len(unknown) != 0 {
		t.Fatalf("unknown settings %v", unknown)
	}
	r.cfg = cfg

	jwksClient := fit.JWKSClient()
	jwksCAs := x509.NewCertPool()
	jwksCAs.AddCert(jwks.Certificate())
	jwksClient.Transport.(*http.Transport).TLSClientConfig.RootCAs = jwksCAs
	r.keys = fit.NewCache(cfg.JWKSURL, jwksClient, cfg.JWKSRefresh, cfg.JWKSMaxAge, logger)
	keysCtx, stopKeys := context.WithCancel(context.Background())
	keysDone := make(chan struct{})
	go func() {
		defer close(keysDone)
		r.keys.Run(keysCtx)
	}()
	t.Cleanup(func() {
		stopKeys()
		<-keysDone
	})

	var verifierKeys keySource = r.keys
	if o.lookupNotReady {
		verifierKeys = expiredKeys{}
	}
	opts := server.Options{
		Config: cfg,
		Verifier: fit.NewVerifier(fit.Policy{
			AppID:           cfg.AppID,
			EnvironmentID:   cfg.EnvironmentID,
			CloudIDs:        cfg.CloudIDs,
			InstallationIDs: cfg.InstallationIDs,
			ClockSkew:       cfg.ClockSkew,
		}, verifierKeys),
		Keys:    r.keys,
		Logger:  logger,
		Version: testVersion,
	}
	if !o.nilForwarder {
		opts.Forwarder = forward.New(forward.Options{
			Upstream:   cfg.Upstream,
			Credential: cfg.Credential,
			RootCAs:    upstreamCAs,
			Timeout:    cfg.UpstreamTimeout,
		})
	}
	r.srv = server.New(opts)

	if o.run {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		r.cancelRun, r.runDone = cancel, make(chan struct{})
		go func() {
			defer close(r.runDone)
			r.runErr = r.srv.Run(ctx, ln)
		}()
		t.Cleanup(func() {
			cancel()
			<-r.runDone // Run bounds this by RELAY_SHUTDOWN_GRACE
		})
		r.addr = ln.Addr().String()
		r.url = "http://" + r.addr
	} else {
		ts := httptest.NewServer(r.srv)
		t.Cleanup(func() {
			ts.CloseClientConnections()
			ts.Close()
		})
		r.url, r.addr = ts.URL, ts.Listener.Addr().String()
	}

	r.client = &http.Client{Transport: &http.Transport{}, Timeout: waitTimeout}
	t.Cleanup(r.client.CloseIdleConnections)
	if !o.notReady {
		waitUntil(t, "the first key snapshot", r.keys.Ready)
	}
	return r
}

// stop cancels Run's context and returns Run's result.
func (r *relay) stop(t testing.TB) error {
	t.Helper()
	r.cancelRun()
	select {
	case <-r.runDone:
	case <-time.After(r.cfg.ShutdownGrace + waitTimeout):
		t.Fatal("Run did not return")
	}
	return r.runErr
}

// reply is a relay answer with its body read.
type reply struct {
	status int
	header http.Header
	body   string
}

// send makes one request with Go's client. It reports errors instead of
// failing the test, so goroutines may call it.
func (r *relay) send(ctx context.Context, method, target string, header http.Header, body io.Reader) (reply, error) {
	req, err := http.NewRequestWithContext(ctx, method, r.url+target, body)
	if err != nil {
		return reply{}, err
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer func() { _ = resp.Body.Close() }() // the body is read in full below
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return reply{}, err
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}, nil
}

func (r *relay) do(t testing.TB, method, target string, header http.Header, body io.Reader) reply {
	t.Helper()
	rep, err := r.send(context.Background(), method, target, header, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	return rep
}

// raw writes request to the relay exactly as given, so neither Go's client
// nor its URL parser can normalize the target, and reads one answer.
func (r *relay) raw(t testing.TB, method, request string) reply {
	t.Helper()
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }() // one exchange per connection
	if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("%q: %v", strings.SplitN(request, "\r\n", 2)[0], err)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return reply{status: resp.StatusCode, header: resp.Header, body: string(b)}
}

// requestText is a bodiless request with the given request line parts.
func requestText(method, target string, header http.Header) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: relay.example\r\nConnection: close\r\n", method, target)
	for k, vs := range header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	return b.String()
}

// expectErrorHeaders checks the headers of a relay-generated error (PLAN.md
// §4.3). Names and codes are literals, so renaming one breaks the contract
// tests (CONTRIBUTING.md, Tests).
func expectErrorHeaders(t testing.TB, got reply, status int, code string, versioned bool) {
	t.Helper()
	if got.status != status {
		t.Errorf("status = %d, want %d", got.status, status)
	}
	if v := got.header.Values("Relay-Error"); len(v) != 1 || v[0] != code {
		t.Errorf("Relay-Error = %q, want %q", v, code)
	}
	if v := got.header.Values("Content-Type"); len(v) != 1 || v[0] != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", v)
	}
	if v, ok := got.header["Relay-Upstream-Status"]; ok {
		t.Errorf("Relay-Upstream-Status = %q on a relay error", v)
	}
	expectProtocol(t, got)
	expectVersion(t, got, versioned)
	expectNoStore(t, got)
}

// expectRelayError also checks the exact body.
func expectRelayError(t testing.TB, got reply, status int, code string, versioned bool) {
	t.Helper()
	expectErrorHeaders(t, got, status, code, versioned)
	want := `{"error":"` + code + `"}`
	if got.body != want {
		t.Errorf("body = %q, want %q", got.body, want)
	}
	if v := got.header.Get("Content-Length"); v != strconv.Itoa(len(want)) {
		t.Errorf("Content-Length = %q, want %d", v, len(want))
	}
}

// expectNoStore checks the caching and sniffing headers every relay answer
// carries (PLAN.md §4.3, SR-8).
func expectNoStore(t testing.TB, got reply) {
	t.Helper()
	if v := got.header.Values("Cache-Control"); len(v) != 1 || v[0] != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", v)
	}
	if v := got.header.Values("X-Content-Type-Options"); len(v) != 1 || v[0] != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", v)
	}
}

func expectProtocol(t testing.TB, got reply) {
	t.Helper()
	if v := got.header.Values("Relay-Protocol"); len(v) != 1 || v[0] != "1" {
		t.Errorf("Relay-Protocol = %q, want 1", v)
	}
}

// expectVersion checks that Relay-Version appears exactly on responses to a
// valid FIT (PLAN.md §4.3).
func expectVersion(t testing.TB, got reply, want bool) {
	t.Helper()
	v, ok := got.header["Relay-Version"]
	switch {
	case want && (len(v) != 1 || v[0] != testVersion):
		t.Errorf("Relay-Version = %q, want %q", v, testVersion)
	case !want && ok:
		t.Errorf("Relay-Version = %q without a valid FIT", v)
	}
}

// expectHealthy checks a health answer (PLAN.md §4.1).
func expectHealthy(t testing.TB, got reply) {
	t.Helper()
	if got.status != http.StatusOK || got.body != `{"status":"ok"}` {
		t.Errorf("got %d %q, want 200 {\"status\":\"ok\"}", got.status, got.body)
	}
	if v := got.header.Get("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", v)
	}
	if v, ok := got.header["Relay-Error"]; ok {
		t.Errorf("Relay-Error = %q on a health answer", v)
	}
	expectProtocol(t, got)
	expectVersion(t, got, false)
	expectNoStore(t, got)
}
