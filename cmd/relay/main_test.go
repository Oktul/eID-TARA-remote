// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"eid-forge-remote/internal/fit"
)

// Synthetic identifiers; none belongs to a real app, environment or site.
const (
	appID   = "ari:cloud:ecosystem::app/00000000-0000-4000-8000-000000000001"
	envID   = "ari:cloud:ecosystem::environment/00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000002"
	cloudID = "00000000-0000-4000-8000-000000000003"
	// marker is planted in the credential, rejected values and unknown
	// settings. It must never appear in output (PLAN.md §10, §13).
	marker = "SECRETMARKER8c3a"
	// unreachableJWKS is an HTTPS URL on loopback where nothing listens, so
	// the key fetch fails without leaving the machine.
	unreachableJWKS = "https://127.0.0.1:1/jwks.json"
	// waitLimit bounds how long a failing test waits for the relay; a
	// passing test never waits for it.
	waitLimit = 30 * time.Second
)

// validEnv returns valid values for the four required settings, with the
// JWKS pointed at a dead loopback port.
func validEnv() map[string]string {
	return map[string]string{
		"RELAY_APP_ID":         appID,
		"RELAY_ENVIRONMENT_ID": envID,
		"RELAY_CLOUD_IDS":      cloudID,
		"RELAY_UPSTREAM_URL":   "https://provider.example",
		"RELAY_JWKS_URL":       unreachableJWKS,
	}
}

// with returns a copy of m with the name/value pairs kv set.
func with(m map[string]string, kv ...string) map[string]string {
	m = maps.Clone(m)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func environ(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

// logLines parses serve's output, which must be one JSON object per line
// (PLAN.md §7 Logging).
func logLines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var lines []map[string]any
	for _, l := range strings.Split(out, "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line is not a JSON object: %q", l)
		}
		lines = append(lines, m)
	}
	return lines
}

// find returns the first line whose message is msg, or nil.
func find(lines []map[string]any, msg string) map[string]any {
	for _, l := range lines {
		if l["msg"] == msg {
			return l
		}
	}
	return nil
}

// freePort returns a loopback port that was free a moment ago. If another
// process takes it first, the test fails rather than passes.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestRunVersionPrintsVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if got := stdout.String(); got != version+"\n" {
		t.Errorf("stdout = %q, want %q", got, version+"\n")
	}
	if stderr.Len() != 0 {
		t.Errorf("stderr = %q, want empty", stderr.String())
	}
}

// TestRunUsageErrorExits2 checks that anything but the three subcommands is
// refused with the usage text and exit code 2, and that serve does not start
// with an argument it would ignore.
func TestRunUsageErrorExits2(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown_subcommand", []string{"start"}},
		{"flag_instead_of_subcommand", []string{"--version"}},
		{"serve_with_extra_argument", []string{"serve", "extra"}},
		{"version_with_extra_argument", []string{"version", "extra"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, nil, &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2", code)
			}
			if !strings.HasPrefix(stderr.String(), "usage: relay ") {
				t.Errorf("stderr = %q, want the usage text", stderr.String())
			}
			// Without settings, a serve that ran would log its error to
			// stdout and return at once instead of listening.
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

// TestServeInvalidSettingExits2 checks PLAN.md §6 R-13 and §8: a bad setting
// stops startup with exit code 2 and one JSON line that names the setting,
// never its value or the credential.
func TestServeInvalidSettingExits2(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		env     map[string]string
		setting string
		hidden  []string // must not appear in any output
	}{
		{
			"bad_port_with_secret_credential", []string{"serve"},
			with(validEnv(), "RELAY_PORT", "notaport", "RELAY_UPSTREAM_AUTH", "Authorization: Basic "+marker),
			"RELAY_PORT", []string{"notaport", marker},
		},
		{
			"serve_is_the_default_subcommand", nil,
			with(validEnv(), "RELAY_PORT", "notaport"),
			"RELAY_PORT", []string{"notaport"},
		},
		{
			"malformed_credential", []string{"serve"},
			with(validEnv(), "RELAY_UPSTREAM_AUTH", "Authorization Basic "+marker),
			"RELAY_UPSTREAM_AUTH", []string{marker},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tc.args, environ(tc.env), &stdout, &stderr); code != 2 {
				t.Fatalf("exit code = %d, want 2; stdout:\n%s", code, stdout.String())
			}
			for _, h := range tc.hidden {
				if strings.Contains(stdout.String()+stderr.String(), h) {
					t.Errorf("output contains %q:\n%s%s", h, stdout.String(), stderr.String())
				}
			}
			lines := logLines(t, stdout.String())
			if len(lines) != 1 {
				t.Fatalf("got %d log lines, want 1:\n%s", len(lines), stdout.String())
			}
			l := lines[0]
			if l["msg"] != "invalid configuration" || l["level"] != "ERROR" || l["setting"] != tc.setting {
				t.Errorf("log line = %v, want an ERROR \"invalid configuration\" naming %s", l, tc.setting)
			}
			if reason, _ := l["reason"].(string); reason == "" {
				t.Errorf("log line = %v, want a reason", l)
			}
		})
	}
}

// TestServeWarnsUnknownSettingsWhenLoadFails checks PLAN.md §8: unknown
// RELAY_* names are reported by name, without their values, even when
// startup fails, since a typo often explains the error that follows.
func TestServeWarnsUnknownSettingsWhenLoadFails(t *testing.T) {
	env := validEnv()
	delete(env, "RELAY_APP_ID")
	env["RELAY_APPID"] = marker
	env["RELAY_PORTS"] = marker

	var stdout, stderr bytes.Buffer
	if code := run(nil, environ(env), &stdout, &stderr); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if strings.Contains(stdout.String()+stderr.String(), marker) {
		t.Errorf("output contains an unknown setting's value:\n%s", stdout.String())
	}
	lines := logLines(t, stdout.String())
	if len(lines) != 3 {
		t.Fatalf("got %d log lines, want 3:\n%s", len(lines), stdout.String())
	}
	for i, name := range []string{"RELAY_APPID", "RELAY_PORTS"} {
		if l := lines[i]; l["msg"] != "unknown setting" || l["level"] != "WARN" || l["name"] != name {
			t.Errorf("line %d = %v, want a WARN \"unknown setting\" naming %s", i, l, name)
		}
	}
	if l := lines[2]; l["msg"] != "invalid configuration" || l["setting"] != "RELAY_APP_ID" {
		t.Errorf("line 2 = %v, want \"invalid configuration\" naming RELAY_APP_ID", l)
	}
}

// logSink collects serve's log output, which the key worker, the request
// handlers and serve itself write concurrently.
type logSink struct {
	mu  sync.Mutex // guards buf
	buf bytes.Buffer
	// wrote has capacity one, so a pending signal stands for every write
	// since the reader last looked.
	wrote chan struct{}
}

func (s *logSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf.Write(p)
	select {
	case s.wrote <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// relay is a serve call running in the background on a loopback port.
type relay struct {
	port   int
	log    *logSink
	cancel context.CancelFunc
	done   chan struct{} // closed when serve has returned
	code   int           // serve's exit code; read only after done
	// stopped records that the test called stop, so that cleanup does not
	// wait a second time for a serve that failed to return.
	stopped bool
}

// startRelay runs serve with env and jwksClient on a free port. The test's
// cleanup stops it.
func startRelay(t *testing.T, env map[string]string, jwksClient *http.Client) *relay {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &relay{port: freePort(t), log: &logSink{wrote: make(chan struct{}, 1)}, cancel: cancel, done: make(chan struct{})}
	env = with(env, "RELAY_PORT", strconv.Itoa(r.port))
	go func() {
		defer close(r.done)
		r.code = serve(ctx, "127.0.0.1", environ(env), r.log, jwksClient)
	}()
	t.Cleanup(func() {
		if !r.stopped {
			r.stop(t)
		}
	})
	return r
}

// stop cancels serve's context, as SIGTERM does, and returns its exit code.
func (r *relay) stop(t *testing.T) int {
	t.Helper()
	r.stopped = true
	r.cancel()
	select {
	case <-r.done:
		return r.code
	case <-time.After(waitLimit):
		t.Fatalf("serve did not return within %v of cancellation; log:\n%s", waitLimit, r.log)
		return 0
	}
}

// waitFor waits until serve has logged a line with message msg and returns
// it, failing at once if serve returns first.
func (r *relay) waitFor(t *testing.T, msg string) map[string]any {
	t.Helper()
	deadline := time.NewTimer(waitLimit)
	defer deadline.Stop()
	for {
		if l := find(logLines(t, r.log.String()), msg); l != nil {
			return l
		}
		select {
		case <-r.log.wrote:
		case <-r.done:
			if l := find(logLines(t, r.log.String()), msg); l != nil {
				return l
			}
			t.Fatalf("serve returned %d before logging %q; log:\n%s", r.code, msg, r.log)
		case <-deadline.C:
			t.Fatalf("no %q log line within %v; log:\n%s", msg, waitLimit, r.log)
		}
	}
}

// get requests path from the relay over loopback and returns the response
// with its body read and closed, so the connection is idle for shutdown.
func (r *relay) get(t *testing.T, client *http.Client, path string) (*http.Response, string) {
	t.Helper()
	resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(r.port) + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("GET %s: read body: %v", path, err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("GET %s: close body: %v", path, err)
	}
	return resp, string(body)
}

// TestServeStartsAndStops runs the relay with valid synthetic settings while
// the JWKS is unreachable. An unreachable JWKS never stops startup (PLAN.md
// §6 R-13), so it must be live but not ready (§4.5). The startup line carries
// the version and every setting but never the credential (§10 O-5, S-8), and
// cancelling the context, as SIGTERM does, makes serve return 0 (R-11).
func TestServeStartsAndStops(t *testing.T) {
	// The file name carries the marker too: the summary must not print the
	// path either.
	credentialFile := filepath.Join(t.TempDir(), "auth-"+marker)
	if err := os.WriteFile(credentialFile, []byte("Authorization: Basic "+marker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name       string
		env        map[string]string
		credential string
	}{
		{"credential_from_env_shows_set", with(validEnv(), "RELAY_UPSTREAM_AUTH", "Authorization: Basic "+marker), "set"},
		{"credential_from_file_shows_set_from_file", with(validEnv(), "RELAY_UPSTREAM_AUTH_FILE", credentialFile), "set (from file)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := startRelay(t, with(tc.env, "RELAY_UNKNOWN_SETTING", marker), fit.JWKSClient())
			// serve starts the key worker only after the listener is open,
			// so the worker's first failed fetch proves the port is up.
			r.waitFor(t, "jwks refresh failed")

			// A zero Transport uses no proxy.
			client := &http.Client{Transport: &http.Transport{}, Timeout: waitLimit}
			defer client.CloseIdleConnections()
			if resp, body := r.get(t, client, "/livez"); resp.StatusCode != 200 || body != `{"status":"ok"}` {
				t.Errorf("/livez = %d %s, want 200 {\"status\":\"ok\"}", resp.StatusCode, body)
			}
			if resp, body := r.get(t, client, "/readyz"); resp.StatusCode != 503 || resp.Header.Get("Relay-Error") != "not_ready" {
				t.Errorf("/readyz = %d %s, want 503 not_ready", resp.StatusCode, body)
			}

			if code := r.stop(t); code != 0 {
				t.Fatalf("exit code = %d, want 0; log:\n%s", code, r.log)
			}
			out := r.log.String()
			if strings.Contains(out, marker) {
				t.Errorf("log contains a secret marker:\n%s", out)
			}
			lines := logLines(t, out)

			startup := find(lines, "starting")
			if startup == nil {
				t.Fatalf("no startup line; log:\n%s", out)
			}
			want := []string{
				"time", "level", "msg", "version", "go", "upstream_proxy", "jwks_proxy",
				"RELAY_APP_ID", "RELAY_ENVIRONMENT_ID", "RELAY_CLOUD_IDS",
				"RELAY_UPSTREAM_URL", "RELAY_UPSTREAM_AUTH",
				"RELAY_UPSTREAM_CA_FILE", "RELAY_INSTALLATION_IDS",
				"RELAY_PORT", "RELAY_UPSTREAM_TIMEOUT",
				"RELAY_CLOCK_SKEW", "RELAY_JWKS_URL",
				"RELAY_JWKS_REFRESH", "RELAY_JWKS_MAX_AGE", "RELAY_SHUTDOWN_GRACE",
				"RELAY_LOG_LEVEL",
			}
			slices.Sort(want)
			// Exactly these keys: the settings are listed one by one, so
			// nothing that holds the credential is printed whole.
			if got := slices.Sorted(maps.Keys(startup)); !slices.Equal(got, want) {
				t.Errorf("startup keys = %v, want %v", got, want)
			}
			if startup["version"] != version || startup["go"] != runtime.Version() {
				t.Errorf("startup version, go = %v, %v; want %s, %s", startup["version"], startup["go"], version, runtime.Version())
			}
			for _, k := range []string{"upstream_proxy", "jwks_proxy"} {
				if _, ok := startup[k].(bool); !ok {
					t.Errorf("startup %s = %v, want a bool", k, startup[k])
				}
			}
			if startup["RELAY_UPSTREAM_AUTH"] != tc.credential {
				t.Errorf("startup RELAY_UPSTREAM_AUTH = %v, want %q", startup["RELAY_UPSTREAM_AUTH"], tc.credential)
			}
			if startup["RELAY_PORT"] != float64(r.port) {
				t.Errorf("startup RELAY_PORT = %v, want %d", startup["RELAY_PORT"], r.port)
			}

			if l := find(lines, "unknown setting"); l == nil || l["level"] != "WARN" || l["name"] != "RELAY_UNKNOWN_SETTING" {
				t.Errorf("unknown setting line = %v, want a WARN naming RELAY_UNKNOWN_SETTING", l)
			}
			stopped := find(lines, "stopped")
			if stopped == nil || stopped["level"] != "INFO" {
				t.Fatalf("stopped line = %v, want INFO; log:\n%s", stopped, out)
			}
			if _, ok := stopped["error"]; ok {
				t.Errorf("stopped line = %v, want no error", stopped)
			}
		})
	}
}

// jwksDocument publishes pub under kid (PLAN.md §4.5).
func jwksDocument(kid string, pub *rsa.PublicKey) string {
	b64 := base64.RawURLEncoding.EncodeToString
	return `{"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"` + kid +
		`","n":"` + b64(pub.N.Bytes()) + `","e":"` + b64(big.NewInt(int64(pub.E)).Bytes()) + `"}]}`
}

// signFIT returns a FIT that the synthetic settings accept (PLAN.md §4.4),
// signed with key under kid.
func signFIT(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"iss":     "forge/invocation-token",
		"aud":     appID,
		"exp":     now.Add(4 * time.Minute).Unix(),
		"nbf":     now.Add(-5 * time.Second).Unix(),
		"app":     map[string]any{"id": appID, "environment": map[string]any{"id": envID}},
		"context": map[string]any{"cloudId": cloudID},
	})
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	input := b64([]byte(`{"alg":"RS256","kid":"`+kid+`"}`)) + "." + b64(payload)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

// waitRefused waits until the relay's port refuses connections, which it
// does once shutdown has closed the listener (PLAN.md §6 R-11).
func (r *relay) waitRefused(t *testing.T) {
	t.Helper()
	deadline := time.NewTimer(waitLimit)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(r.port))
		if err != nil {
			return
		}
		_ = conn.Close() // a probe only; it sent nothing
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("the relay still accepted connections %v after cancellation", waitLimit)
		}
	}
}

// TestServeKeyLoopStopsAfterInFlightRequests checks the order of PLAN.md §6
// R-11: the key loop stops only after the in-flight requests. A request whose
// FIT names a key the snapshot lacks waits for the fetch it asked for
// (§4.5). That fetch is in flight when the signal arrives and is answered
// only once the listener is closed, so the request is served only if the key
// worker outlives the listener; otherwise it gets 401 invalid_token.
//
// The request waits for the fetch at most fit.FITKeyWait. A 401 that took
// that long proves nothing, because the relay may rightly have stopped
// waiting before a slow test released the fetch, so that attempt is
// repeated. A 401 sooner can only come from a stopped key worker, and any
// other failure has no timing excuse either.
func TestServeKeyLoopStopsAfterInFlightRequests(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 3
	for i := 1; ; i++ {
		a := keyLoopShutdownAttempt(t, key)
		waitExpired := a.err == nil && a.status == http.StatusUnauthorized &&
			a.relayError == "invalid_token" && a.took >= fit.FITKeyWait
		switch {
		case a.err == nil && a.status == http.StatusOK:
			return
		case !waitExpired || t.Failed():
			t.Fatalf("in-flight request = %d %q, %v after %v; want 200: a 401 sooner than FITKeyWait means the key worker stopped before the request finished", a.status, a.relayError, a.err, a.took)
		case i == attempts:
			t.Fatalf("all %d attempts answered 401 after at least FITKeyWait (%v), so none tested the order", attempts, fit.FITKeyWait)
		}
		t.Logf("attempt %d proves nothing: 401 after %v, at least FITKeyWait", i, a.took)
	}
}

// keyLoopAnswer is the in-flight request's answer in
// TestServeKeyLoopStopsAfterInFlightRequests, and how long it took.
type keyLoopAnswer struct {
	status     int
	relayError string
	err        error
	took       time.Duration
}

// keyLoopShutdownAttempt runs one attempt of
// TestServeKeyLoopStopsAfterInFlightRequests with a new relay and JWKS
// server, and returns the in-flight request's answer.
func keyLoopShutdownAttempt(t *testing.T, key *rsa.PrivateKey) keyLoopAnswer {
	t.Helper()
	// The startup fetch publishes the key under the old ID and every later
	// fetch under the new one, which the FIT names. The second fetch is held
	// until the test releases it.
	const oldKID, newKID = "synthetic-before-rotation", "synthetic-after-rotation"
	var fetches atomic.Int32
	held := make(chan struct{})
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kid := oldKID
		switch fetches.Add(1) {
		case 1:
		case 2:
			close(held)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			kid = newKID
		default:
			kid = newKID
		}
		_, _ = io.WriteString(w, jwksDocument(kid, &key.PublicKey)) // a lost answer fails the fetch, and the test with it
	}))
	t.Cleanup(jwks.Close)
	t.Cleanup(releaseOnce) // runs first, so a held fetch cannot block Close

	r := startRelay(t, with(validEnv(), "RELAY_JWKS_URL", jwks.URL+"/jwks.json"), jwks.Client())
	r.waitFor(t, "signing keys ready")

	token := signFIT(t, key, newKID)
	answered := make(chan keyLoopAnswer, 1)
	go func() {
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(r.port)+"/relay/v1/info", nil)
		if err != nil {
			answered <- keyLoopAnswer{err: err}
			return
		}
		req.Header.Set("Authorization", "Bearer "+token)
		// A zero Transport uses no proxy.
		client := &http.Client{Transport: &http.Transport{}, Timeout: waitLimit}
		defer client.CloseIdleConnections()
		// The relay's wait starts after the request is sent, so this
		// duration is never shorter than that wait.
		start := time.Now()
		resp, err := client.Do(req)
		took := time.Since(start)
		if err != nil {
			answered <- keyLoopAnswer{err: err, took: took}
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body) // only the status and Relay-Error are checked
		_ = resp.Body.Close()
		answered <- keyLoopAnswer{status: resp.StatusCode, relayError: resp.Header.Get("Relay-Error"), took: took}
	}()

	select {
	case <-held:
	case <-time.After(waitLimit):
		t.Fatalf("the unknown key ID started no fetch within %v; log:\n%s", waitLimit, r.log)
	}
	r.cancel() // as SIGTERM does
	r.waitRefused(t)
	releaseOnce()

	var a keyLoopAnswer
	select {
	case a = <-answered:
	case <-time.After(waitLimit):
		t.Fatalf("no answer within %v; log:\n%s", waitLimit, r.log)
	}
	if code := r.stop(t); code != 0 {
		t.Errorf("exit code = %d, want 0; log:\n%s", code, r.log)
	}
	if n := fetches.Load(); n != 2 {
		t.Errorf("%d JWKS fetches, want 2: one at startup, one for the unknown key ID", n)
	}
	return a
}

// probeServer stands in for the relay's health endpoints on 127.0.0.1. It
// answers each path with its status in statuses, or 404, and records the
// paths it was asked for. A 3xx answer points at /followed.
type probeServer struct {
	*httptest.Server
	mu    sync.Mutex // guards paths
	paths []string
}

func newProbeServer(t *testing.T, statuses map[string]int) *probeServer {
	t.Helper()
	p := &probeServer{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.paths = append(p.paths, r.URL.RequestURI())
		p.mu.Unlock()
		status, ok := statuses[r.URL.Path]
		if !ok {
			status = http.StatusNotFound
		}
		if status/100 == 3 {
			w.Header().Set("Location", "/followed")
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *probeServer) port(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(p.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Port()
}

func (p *probeServer) requested() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.paths)
}

// TestHealthcheck checks PLAN.md §7 O-3: exit 0 only when /livez, or /readyz
// with --ready, answers 200 on the relay's port. A redirect is an answer, not something to follow: a container
// runtime must not count a relay that redirects as healthy.
func TestHealthcheck(t *testing.T) {
	cases := []struct {
		name      string
		args      []string
		statuses  map[string]int
		want      int
		requested []string
	}{
		{"livez_200_exits_0", nil, map[string]int{"/livez": 200}, 0, []string{"/livez"}},
		{"ready_flag_checks_readyz", []string{"--ready"}, map[string]int{"/livez": 200, "/readyz": 200}, 0, []string{"/readyz"}},
		{"livez_503_exits_1", nil, map[string]int{"/livez": 503}, 1, []string{"/livez"}},
		{"readyz_503_exits_1_while_live", []string{"--ready"}, map[string]int{"/livez": 200, "/readyz": 503}, 1, []string{"/readyz"}},
		{"redirect_not_followed", nil, map[string]int{"/livez": 302, "/followed": 200}, 1, []string{"/livez"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newProbeServer(t, tc.statuses)
			var stdout, stderr bytes.Buffer
			args := append([]string{"healthcheck"}, tc.args...)
			if code := run(args, environ(map[string]string{"RELAY_PORT": p.port(t)}), &stdout, &stderr); code != tc.want {
				t.Errorf("exit code = %d, want %d; stderr: %s", code, tc.want, stderr.String())
			}
			if got := p.requested(); !slices.Equal(got, tc.requested) {
				t.Errorf("requested %v, want %v", got, tc.requested)
			}
		})
	}
}

func TestHealthcheckNoListenerExits1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := map[string]string{"RELAY_PORT": strconv.Itoa(freePort(t))}
	if code := run([]string{"healthcheck"}, environ(env), &stdout, &stderr); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// TestHealthcheckBadFlagsExit1 checks that a mistake in the probe's own
// command line sends nothing and exits 1, not 2, which Docker reserves for
// health checks (PLAN.md §7 O-3: exit 0 or 1).
func TestHealthcheckBadFlagsExit1(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"unknown_flag", []string{"--bogus"}},
		{"positional_argument", []string{"extra"}},
		{"argument_after_ready", []string{"--ready", "extra"}},
		{"ready_not_a_bool", []string{"--ready=maybe"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := newProbeServer(t, map[string]int{"/livez": 200, "/readyz": 200})
			var stdout, stderr bytes.Buffer
			args := append([]string{"healthcheck"}, tc.args...)
			if code := run(args, environ(map[string]string{"RELAY_PORT": p.port(t)}), &stdout, &stderr); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), "usage: relay healthcheck") {
				t.Errorf("stderr %q has no usage line", stderr.String())
			}
			if got := p.requested(); len(got) != 0 {
				t.Errorf("requested %v, want nothing", got)
			}
		})
	}
}

// TestHealthcheckBadPortExits1 checks that a broken RELAY_PORT fails the
// probe with the setting's name and without its value (PLAN.md §8).
func TestHealthcheckBadPortExits1(t *testing.T) {
	var stdout, stderr bytes.Buffer
	env := map[string]string{"RELAY_PORT": "port" + marker}
	if code := run([]string{"healthcheck"}, environ(env), &stdout, &stderr); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if got := stderr.String(); !strings.Contains(got, "RELAY_PORT") || strings.Contains(got, marker) {
		t.Errorf("stderr = %q, want it to name RELAY_PORT without its value", got)
	}
}

// TestHealthcheckIgnoresOtherSettings checks that the probe reads only the
// port (PLAN.md §7 O-3): broken or secret settings
// elsewhere neither fail it nor reach its output.
func TestHealthcheckIgnoresOtherSettings(t *testing.T) {
	p := newProbeServer(t, map[string]int{"/livez": 200})
	env := with(map[string]string{"RELAY_PORT": p.port(t)},
		"RELAY_APP_ID", marker,
		"RELAY_ENVIRONMENT_ID", marker,
		"RELAY_UPSTREAM_AUTH", "Authorization: Basic "+marker)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"healthcheck"}, environ(env), &stdout, &stderr); code != 0 {
		t.Errorf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), marker) {
		t.Errorf("output contains a setting's value: %s%s", stdout.String(), stderr.String())
	}
}

// TestHealthcheckIgnoresProxyEnvironment checks that the probe goes straight
// to loopback even when HTTPS_PROXY and HTTP_PROXY name a proxy, as they do
// in networks whose egress goes through one (PLAN.md §5). Go's environment
// proxy also skips loopback, so this pins the observable behaviour rather
// than one line of the transport.
func TestHealthcheckIgnoresProxyEnvironment(t *testing.T) {
	proxy := newProbeServer(t, nil)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	p := newProbeServer(t, map[string]int{"/livez": 200})
	var stdout, stderr bytes.Buffer
	if code := run([]string{"healthcheck"}, environ(map[string]string{"RELAY_PORT": p.port(t)}), &stdout, &stderr); code != 0 {
		t.Errorf("exit code = %d, want 0; stderr: %s", code, stderr.String())
	}
	if got := proxy.requested(); len(got) != 0 {
		t.Errorf("proxy received %v, want nothing", got)
	}
}
