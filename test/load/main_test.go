// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

// testKey is generated once per package run; no key is ever committed
// (CONTRIBUTING.md, Tests).
var testKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, rsaKeyBits)
})

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := testKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// testUnix is a fixed time for tests that compare minted claims.
const testUnix = 1_800_000_000

// decodePart decodes one compact-JWS part with the strictness the relay
// applies (PLAN.md §4.4), so a fixture the relay would refuse fails here.
func decodePart(t *testing.T, part string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(part)
	if err != nil {
		t.Fatalf("part is not strict base64url: %v", err)
	}
	if base64.RawURLEncoding.EncodeToString(b) != part {
		t.Fatal("part is not canonical base64url")
	}
	return b
}

func splitFIT(t *testing.T, token string) (header, payload, sig string) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts, want 3", len(parts))
	}
	return parts[0], parts[1], parts[2]
}

func verifies(k *rsa.PrivateKey, header, payload, sig []byte) bool {
	digest := sha256.Sum256([]byte(base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)))
	return rsa.VerifyPKCS1v15(&k.PublicKey, crypto.SHA256, digest[:], sig) == nil
}

// The claim names and values below are spelled as literals: they are what
// the relay's settings printed by this tool must match (PLAN.md §4.4, §8).
func TestMintedFITPassesEveryRelayCheck(t *testing.T) {
	k := key(t)
	s, err := mint(k, time.Unix(testUnix, 0))
	if err != nil {
		t.Fatal(err)
	}
	h, p, sig := splitFIT(t, s.valid)
	var header map[string]any
	if err := json.Unmarshal(decodePart(t, h), &header); err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "RS256" || header["kid"] != "load-test-key" {
		t.Errorf("header = %v, want alg RS256 and kid load-test-key", header)
	}
	for _, forbidden := range []string{"crit", "jku", "jwk", "x5u", "x5c", "zip", "b64"} {
		if _, ok := header[forbidden]; ok {
			t.Errorf("header carries %s, which the relay refuses", forbidden)
		}
	}
	if !verifies(k, decodePart(t, h), decodePart(t, p), decodePart(t, sig)) {
		t.Fatal("signature does not verify over the parts as encoded")
	}
	var claims struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Nbf int64  `json:"nbf"`
		Exp int64  `json:"exp"`
		App struct {
			InstallationID string `json:"installationId"`
			Environment    struct {
				ID string `json:"id"`
			} `json:"environment"`
		} `json:"app"`
		Context struct {
			CloudID string `json:"cloudId"`
		} `json:"context"`
		IcLabel *string `json:"icLabel"`
	}
	if err := json.Unmarshal(decodePart(t, p), &claims); err != nil {
		t.Fatal(err)
	}
	want := []struct{ name, got, want string }{
		{"iss", claims.Iss, "forge/invocation-token"},
		{"aud", claims.Aud, "ari:cloud:ecosystem::app/11111111-1111-4111-8111-111111111111"},
		{"app.environment.id", claims.App.Environment.ID, "ari:cloud:ecosystem::environment/11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222"},
		{"context.cloudId", claims.Context.CloudID, "33333333-3333-4333-8333-333333333333"},
	}
	for _, w := range want {
		if w.got != w.want {
			t.Errorf("%s = %q, want %q", w.name, w.got, w.want)
		}
	}
	if claims.App.InstallationID == "" {
		t.Error("app.installationId is empty; the relay rejects an empty supplied pin")
	}
	if claims.IcLabel != nil {
		t.Error("icLabel present; the relay refuses Isolated Cloud tokens")
	}
	if claims.Nbf != testUnix || claims.Exp != testUnix+25 {
		t.Errorf("nbf, exp = %d, %d; want now and now + 25 s", claims.Nbf, claims.Exp)
	}
}

func TestBadSignatureFITFailsOnlyTheSignature(t *testing.T) {
	k := key(t)
	s, err := mint(k, time.Unix(testUnix, 0))
	if err != nil {
		t.Fatal(err)
	}
	vh, vp, _ := splitFIT(t, s.valid)
	h, p, sig := splitFIT(t, s.badSignature)
	if h != vh || p != vp {
		t.Error("header or payload differ from the valid token")
	}
	if verifies(k, decodePart(t, h), decodePart(t, p), decodePart(t, sig)) {
		t.Error("bad signature verifies")
	}
}

func TestUnknownKeyFITNamesTheGivenKid(t *testing.T) {
	s, err := mint(key(t), time.Unix(testUnix, 0))
	if err != nil {
		t.Fatal(err)
	}
	token, err := unknownKeyFIT(s, "unknown-7-42")
	if err != nil {
		t.Fatal(err)
	}
	h, p, sig := splitFIT(t, token)
	var header map[string]any
	if err := json.Unmarshal(decodePart(t, h), &header); err != nil {
		t.Fatal(err)
	}
	if header["kid"] != "unknown-7-42" || header["alg"] != "RS256" {
		t.Errorf("header = %v", header)
	}
	if p != s.payload || sig != s.signature {
		t.Error("payload or signature differ from the valid token")
	}
}

func TestMinterReusesTokensUntilRemint(t *testing.T) {
	start := time.Unix(testUnix, 0)
	now := start
	m := newMinter(key(t), func() time.Time { return now })
	first, err := m.get()
	if err != nil {
		t.Fatal(err)
	}
	now = start.Add(fitRemint - time.Nanosecond)
	if s, err := m.get(); err != nil || s.valid != first.valid {
		t.Errorf("re-minted before fitRemint (error %v)", err)
	}
	now = start.Add(fitRemint)
	if s, err := m.get(); err != nil || s.valid == first.valid {
		t.Errorf("token still reused at fitRemint (error %v)", err)
	}
}

func TestJWKSDocumentPublishesTheKey(t *testing.T) {
	k := key(t)
	doc, err := jwksDocument(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(doc, &set); err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("%d keys, want 1", len(set.Keys))
	}
	j := set.Keys[0]
	if j["kty"] != "RSA" || j["use"] != "sig" || j["alg"] != "RS256" || j["kid"] != "load-test-key" {
		t.Errorf("key members = %v", j)
	}
	n := new(big.Int).SetBytes(decodePart(t, j["n"]))
	e := new(big.Int).SetBytes(decodePart(t, j["e"]))
	if n.Cmp(k.N) != 0 || !e.IsInt64() || e.Int64() != int64(k.E) {
		t.Error("n or e do not match the signing key")
	}
	if n.BitLen() < 2048 {
		t.Errorf("modulus has %d bits; the relay skips keys under 2048", n.BitLen())
	}
}

func TestCertificatesChainToTheWrittenCA(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "relay-fixture.test"} {
		t.Run(host, func(t *testing.T) {
			caPEM, cert, err := newCertificates(host, time.Unix(testUnix, 0))
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(caPEM) {
				t.Fatal("CA PEM does not parse")
			}
			leaf, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if leaf.IsCA {
				t.Error("server certificate is a CA")
			}
			opts := x509.VerifyOptions{Roots: roots, DNSName: host, CurrentTime: time.Unix(testUnix, 0)}
			if _, err := leaf.Verify(opts); err != nil {
				t.Errorf("server certificate does not verify: %v", err)
			}
			opts.DNSName = "other.test"
			if _, err := leaf.Verify(opts); err == nil {
				t.Error("server certificate verifies for another host")
			}
		})
	}
}

// newTestFixture serves f with the production server settings on loopback
// and returns its URL and a client that trusts only the generated CA.
func newTestFixture(t *testing.T, f *fixture) (string, *http.Client) {
	t.Helper()
	caPEM, cert, err := newCertificates("127.0.0.1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := newFixtureServer(f, cert, io.Discard)
	served := make(chan error, 1)
	go func() { served <- srv.ServeTLS(ln, "", "") }()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(func() {
		tr.CloseIdleConnections()
		_ = srv.Close() // the test is over; only the listener's close error is lost
		<-served
	})
	return "https://" + ln.Addr().String(), &http.Client{Transport: tr, Timeout: requestTimeout}
}

func TestFixtureAnswersOnlyTheJWKSAndTheTokenRoute(t *testing.T) {
	f := &fixture{
		jwks:         []byte(`{"keys":[]}`),
		requestBody:  fill(100, "request-body-"),
		responseBody: fill(200, "response-body-"),
	}
	base, c := newTestFixture(t, f)
	cases := []struct {
		name, method, path string
		body               []byte
		status             int
		answer             []byte
	}{
		{"jwks_get_served", http.MethodGet, jwksPath, nil, http.StatusOK, f.jwks},
		{"unchanged_body_gets_full_answer", http.MethodPost, tokenPath, f.requestBody, http.StatusOK, f.responseBody},
		{"changed_body_answers_400", http.MethodPost, tokenPath, fill(100, "changed-"), http.StatusBadRequest, nil},
		{"short_body_answers_400", http.MethodPost, tokenPath, f.requestBody[:99], http.StatusBadRequest, nil},
		{"get_on_token_route_not_found", http.MethodGet, tokenPath, nil, http.StatusNotFound, nil},
		{"other_path_not_found", http.MethodPost, "/oidc/token/", f.requestBody, http.StatusNotFound, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(tc.method, base+tc.path, bytes.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			// Read to the end below; a close error cannot change the result.
			defer func() { _ = resp.Body.Close() }()
			got, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.status)
			}
			if tc.answer != nil && !bytes.Equal(got, tc.answer) {
				t.Error("answer body differs")
			}
		})
	}
	if n := f.jwksFetches.Load(); n != 1 {
		t.Errorf("jwks fetches = %d, want 1", n)
	}
	if n := f.upstreamCalls.Load(); n != 3 {
		t.Errorf("upstream calls = %d, want 3", n)
	}
}

func TestOutcomeKey(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header http.Header
		want   string
	}{
		{"relay_error", 503, http.Header{"Relay-Error": {"too_busy"}}, "503 too_busy"},
		{"forwarded", 200, http.Header{"Relay-Upstream-Status": {"401"}}, "200 upstream 401"},
		{"relay_error_wins_over_upstream_status", 502, http.Header{"Relay-Error": {"upstream_too_large"}, "Relay-Upstream-Status": {"200"}}, "502 upstream_too_large"},
		{"no_relay_headers", 429, http.Header{}, "429"},
		{"uppercase_code_malformed", 401, http.Header{"Relay-Error": {"Invalid_Token"}}, "401 malformed"},
		{"repeated_code_malformed", 401, http.Header{"Relay-Error": {"invalid_token", "invalid_token"}}, "401 malformed"},
		{"long_code_malformed", 401, http.Header{"Relay-Error": {strings.Repeat("a", 33)}}, "401 malformed"},
		{"text_code_malformed", 401, http.Header{"Relay-Error": {"secret marker"}}, "401 malformed"},
		{"empty_code_malformed", 401, http.Header{"Relay-Error": {""}}, "401 malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := outcomeKey(&http.Response{StatusCode: tc.status, Header: tc.header}); got != tc.want {
				t.Errorf("outcomeKey = %q, want %q", got, tc.want)
			}
		})
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestErrorClassIsFixed(t *testing.T) {
	cases := map[string]error{
		"response_too_large": errTooLarge,
		"timeout":            &net.OpError{Op: "read", Err: timeoutError{}},
		"connection":         errors.New("secret marker"),
	}
	for want, err := range cases {
		if got := errorClass(err); got != want {
			t.Errorf("errorClass(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestHistogramBucketsBoundTheirValues(t *testing.T) {
	last := -1
	for us := uint64(0); us < 1<<32; us = us*9/8 + 1 {
		i := histogramIndex(us)
		if i < last {
			t.Fatalf("index(%d) = %d is below the previous index %d", us, i, last)
		}
		last = i
		upper := uint64(histogramUpper(i) / time.Microsecond)
		if upper < us || upper-us > us/histogramSub {
			t.Fatalf("bucket %d upper bound %d µs does not bound %d µs within 1/%d", i, upper, us, histogramSub)
		}
	}
}

func TestHistogramPercentiles(t *testing.T) {
	h := newHistogram()
	if h.percentile(50) != 0 {
		t.Error("empty histogram has a percentile")
	}
	for ms := 1; ms <= 100; ms++ {
		h.record(time.Duration(ms) * time.Millisecond)
	}
	for _, p := range []int64{50, 95, 99} {
		want := time.Duration(p) * time.Millisecond
		if got := h.percentile(p); got < want || got > want+want/histogramSub {
			t.Errorf("p%d = %s, want %s to %s", p, got, want, want+want/histogramSub)
		}
	}
	h.record(100 * time.Hour)
	if got := h.percentile(100); got < histogramMax || got > histogramMax+histogramMax/histogramSub {
		t.Errorf("a duration above histogramMax recorded as %s", got)
	}
}

func scenarioNamed(t *testing.T, name string) scenario {
	t.Helper()
	for _, s := range allScenarios() {
		if s.name == name {
			return s
		}
	}
	t.Fatalf("no scenario %q", name)
	return scenario{}
}

func TestVerdictChecks(t *testing.T) {
	passing := func(outcomes map[string]int64) result {
		return result{elapsed: 30 * time.Second, outcomes: outcomes, errors: map[string]int64{}, probe: probeTally{failures: map[string]int64{}}}
	}
	cases := []struct {
		name     string
		scenario string
		edit     func(*result)
		fails    bool
	}{
		{"full_with_forwarded_and_too_busy_passes", "full", func(*result) {}, false},
		{"full_without_overload_fails", "full", func(r *result) { delete(r.outcomes, outcomeTooBusy) }, true},
		{"full_upstream_calls_allowed", "full", func(r *result) { r.upstreamCalls = 10 }, false},
		{"unexpected_outcome_fails", "full", func(r *result) { r.outcomes["401 invalid_token"] = 1 }, true},
		{"missing_required_outcome_fails", "full", func(r *result) { delete(r.outcomes, outcomeForwarded) }, true},
		{"transport_error_fails", "full", func(r *result) { r.errors["connection"] = 1 }, true},
		{"body_mismatch_fails", "full", func(r *result) { r.errors["body_mismatch"] = 1 }, true},
		{"failed_health_probe_fails", "full", func(r *result) { r.probe.failures["/livez timeout"] = 1 }, true},
		{"invalid_reaching_upstream_fails", "invalid", func(r *result) { r.upstreamCalls = 1 }, true},
		{"invalid_forwarded_fails", "invalid", func(r *result) { r.outcomes[outcomeForwarded] = 1 }, true},
		{"invalid_too_busy_fails", "invalid", func(r *result) { r.outcomes[outcomeTooBusy] = 1 }, true},
		{"unknown_kid_too_busy_fails", "unknown-kid", func(r *result) { r.outcomes[outcomeTooBusy] = 1 }, true},
		{"unknown_kid_reaching_upstream_fails", "unknown-kid", func(r *result) { r.upstreamCalls = 1 }, true},
		{"unknown_kid_one_fetch_per_interval_passes", "unknown-kid", func(r *result) { r.jwksFetches = 1 }, false},
		{"unknown_kid_fetches_over_limit_fail", "unknown-kid", func(r *result) { r.jwksFetches = 2 }, true},
		{"unknown_kid_limit_grows_with_elapsed", "unknown-kid", func(r *result) { r.elapsed = 2 * time.Minute; r.jwksFetches = 3 }, false},
		{"slow_headers_closed_passes", "slow-headers", func(r *result) { r.outcomes = map[string]int64{outcomeClosed: 3, "answered 408": 1} }, false},
		{"slow_headers_open_at_end_fails", "slow-headers", func(r *result) { r.outcomes = map[string]int64{outcomeOpen: 1} }, true},
		{"slow_headers_reaching_upstream_fails", "slow-headers", func(r *result) { r.outcomes = map[string]int64{outcomeClosed: 1}; r.upstreamCalls = 1 }, true},
		{"idle_open_at_end_passes", "idle", func(r *result) { r.outcomes = map[string]int64{outcomeOpen: 2, outcomeClosed: 1} }, false},
		{"idle_failed_first_request_fails", "idle", func(r *result) { r.outcomes = map[string]int64{"first request 503 not_ready": 1} }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := scenarioNamed(t, tc.scenario)
			r := passing(map[string]int64{s.required: 5})
			if s.name == "full" {
				r.outcomes[outcomeTooBusy] = 5
			}
			tc.edit(&r)
			if got := verdict(s, r); (len(got) > 0) != tc.fails {
				t.Errorf("verdict = %q, want failing %v", got, tc.fails)
			}
		})
	}
}

func TestParseOptionsDefaults(t *testing.T) {
	o, err := parseOptions(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range o.scenarios {
		names = append(names, s.name)
	}
	if want := []string{"full", "invalid", "unknown-kid", "slow-headers", "idle"}; !slices.Equal(names, want) {
		t.Errorf("scenarios = %v, want %v", names, want)
	}
	if o.relay.base != "http://127.0.0.1:8080" || o.probeBase != o.relay.base || o.relay.addr != "127.0.0.1:8080" {
		t.Errorf("relay = %+v, probe %q", o.relay, o.probeBase)
	}
	if o.host != "127.0.0.1" || o.workers != 100 || o.conns != 200 || o.bodyBytes != 65536 || o.responseBytes != 65536 {
		t.Errorf("options = %+v", o)
	}
	if o.duration != 30*time.Second || o.upstreamDelay != 100*time.Millisecond || o.slowInterval != time.Second {
		t.Errorf("durations = %s, %s, %s", o.duration, o.upstreamDelay, o.slowInterval)
	}
}

func TestParseOptionsSelectsScenariosInOrder(t *testing.T) {
	o, err := parseOptions([]string{"-scenario", "idle,full", "-relay", "https://relay.test", "-probe", "http://127.0.0.1:8080"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.scenarios) != 2 || o.scenarios[0].name != "idle" || o.scenarios[1].name != "full" {
		t.Errorf("scenarios = %v", o.scenarios)
	}
	if !o.relay.tls || o.relay.addr != "relay.test:443" || o.relay.serverName != "relay.test" || o.probeBase != "http://127.0.0.1:8080" {
		t.Errorf("relay = %+v, probe %q", o.relay, o.probeBase)
	}
}

func TestParseOptionsRejects(t *testing.T) {
	cases := map[string][]string{
		"unknown_scenario":          {"-scenario", "full,nope"},
		"duplicate_scenario":        {"-scenario", "full,full"},
		"empty_scenario_item":       {"-scenario", "full,"},
		"zero_workers":              {"-c", "0"},
		"too_many_workers":          {"-c", "10001"},
		"zero_conns":                {"-conns", "0"},
		"negative_body":             {"-body-bytes", "-1"},
		"oversized_response":        {"-response-bytes", "16777217"},
		"zero_duration":             {"-duration", "0s"},
		"duration_over_soak":        {"-duration", "73h"},
		"negative_upstream_delay":   {"-upstream-delay", "-1s"},
		"zero_slow_interval":        {"-slow-interval", "0s"},
		"zero_ready_timeout":        {"-ready-timeout", "0s"},
		"relay_with_path":           {"-relay", "http://127.0.0.1:8080/relay"},
		"relay_with_query":          {"-relay", "http://127.0.0.1:8080?x=1"},
		"relay_with_empty_query":    {"-relay", "http://127.0.0.1:8080/?"},
		"relay_with_userinfo":       {"-relay", "http://user@127.0.0.1:8080"},
		"relay_not_http":            {"-relay", "ftp://127.0.0.1"},
		"relay_without_host":        {"-relay", "http://"},
		"probe_with_path":           {"-probe", "http://127.0.0.1:8080/livez"},
		"wildcard_listen_no_host":   {"-listen", "0.0.0.0:9443"},
		"empty_listen_host_no_host": {"-listen", ":9443"},
		"listen_without_port":       {"-listen", "127.0.0.1"},
		"host_not_a_name":           {"-host", "relay host"},
		"empty_ca_out":              {"-ca-out", ""},
		"extra_argument":            {"full"},
		"unknown_flag":              {"-nope"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseOptions(args, io.Discard); err == nil {
				t.Error("accepted")
			}
		})
	}
}

// pipeDialer hands each connection's far end to serve, which plays the relay.
// The far end closes when serve returns; serve's reads fail once the near end
// closes, so every goroutine exits.
func pipeDialer(serve func(net.Conn)) dialFunc {
	return func(context.Context) (net.Conn, error) {
		near, far := net.Pipe()
		go func() {
			defer func() { _ = far.Close() }() // a net.Pipe end closes without error
			serve(far)
		}()
		return near, nil
	}
}

func TestSlowHeadersEndWhenThePeerTimesOut(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const headerTimeout = 5 * time.Second
		var mu sync.Mutex
		var received []string
		e := &env{relay: target{host: "relay.test"}, conns: 3, slowInterval: time.Second}
		e.dial = pipeDialer(func(c net.Conn) {
			var got []byte
			deadline := time.Now().Add(headerTimeout)
			b := make([]byte, 1)
			for time.Now().Before(deadline) {
				if _, err := c.Read(b); err != nil {
					return
				}
				got = append(got, b[0])
			}
			mu.Lock()
			received = append(received, string(got))
			mu.Unlock()
		})
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		tl := newTally()
		slowHeaders(ctx, ctx, e, tl)
		r := tl.result()
		if !maps.Equal(r.outcomes, map[string]int64{outcomeClosed: 3}) || len(r.errors) > 0 {
			t.Errorf("outcomes = %v, errors = %v", r.outcomes, r.errors)
		}
		if r.p99 < headerTimeout || r.p99 > headerTimeout+headerTimeout/histogramSub {
			t.Errorf("time to close p99 = %s, want about %s", r.p99, headerTimeout)
		}
		// One byte per interval, starting at once: six bytes in five seconds.
		for _, got := range received {
			if got != "POST /" {
				t.Errorf("peer received %q, want the request's first six bytes", got)
			}
		}
	})
}

func TestSlowHeadersStillOpenAtEndAreCounted(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := &env{relay: target{host: "relay.test"}, conns: 2, slowInterval: time.Second}
		e.dial = pipeDialer(func(c net.Conn) {
			_, _ = io.Copy(io.Discard, c) // reads until the generator closes
		})
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		tl := newTally()
		slowHeaders(ctx, ctx, e, tl)
		if r := tl.result(); !maps.Equal(r.outcomes, map[string]int64{outcomeOpen: 2}) {
			t.Errorf("outcomes = %v", r.outcomes)
		}
	})
}

func TestSlowHeadersAnsweredByThePeer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := &env{relay: target{host: "relay.test"}, conns: 1, slowInterval: time.Second}
		e.dial = pipeDialer(func(c net.Conn) {
			if _, err := io.ReadFull(c, make([]byte, 3)); err != nil {
				return
			}
			// The write ends early when the generator closes after reading
			// the status; that is all it needs.
			_, _ = io.WriteString(c, "HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n")
		})
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		defer cancel()
		tl := newTally()
		slowHeaders(ctx, ctx, e, tl)
		if r := tl.result(); !maps.Equal(r.outcomes, map[string]int64{"answered 408": 1}) {
			t.Errorf("outcomes = %v", r.outcomes)
		}
	})
}

// serveOneHealthAnswer reads one request and answers it with answer.
func serveOneHealthAnswer(t *testing.T, c net.Conn, answer string) bool {
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil {
		t.Errorf("read request: %v", err)
		return false
	}
	if req.Method != http.MethodGet || req.RequestURI != "/livez" || req.Host != "relay.test" {
		t.Errorf("request = %s %s for %s, want GET /livez for relay.test", req.Method, req.RequestURI, req.Host)
	}
	if _, err := io.WriteString(c, answer); err != nil {
		t.Errorf("write answer: %v", err)
		return false
	}
	return true
}

const livezOK = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nRelay-Protocol: 1\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}"

func TestIdleConnectionsEndAtThePeersIdleTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const idleTimeout = 60 * time.Second
		e := &env{relay: target{host: "relay.test"}, conns: 2}
		e.dial = pipeDialer(func(c net.Conn) {
			if serveOneHealthAnswer(t, c, livezOK) {
				<-time.After(idleTimeout) // fake time inside the bubble
			}
		})
		ctx, cancel := context.WithTimeout(t.Context(), 2*idleTimeout)
		defer cancel()
		tl := newTally()
		idle(ctx, ctx, e, tl)
		r := tl.result()
		if !maps.Equal(r.outcomes, map[string]int64{outcomeClosed: 2}) || len(r.errors) > 0 {
			t.Errorf("outcomes = %v, errors = %v", r.outcomes, r.errors)
		}
		if r.p50 < idleTimeout || r.p50 > idleTimeout+idleTimeout/histogramSub {
			t.Errorf("time to close p50 = %s, want about %s", r.p50, idleTimeout)
		}
	})
}

func TestIdleConnectionsOpenAtEndAndFailedFirstRequests(t *testing.T) {
	cases := []struct {
		name   string
		answer string
		want   string
	}{
		{"kept_alive_until_end", livezOK, outcomeOpen},
		{"first_request_refused", "HTTP/1.1 503 Service Unavailable\r\nRelay-Error: not_ready\r\nContent-Length: 0\r\n\r\n", "first request 503 not_ready"},
		{"first_request_not_kept_alive", "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", "first request not kept alive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				e := &env{relay: target{host: "relay.test"}, conns: 1}
				e.dial = pipeDialer(func(c net.Conn) {
					if serveOneHealthAnswer(t, c, tc.answer) {
						_, _ = io.Copy(io.Discard, c) // stays open until the generator closes
					}
				})
				ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
				defer cancel()
				tl := newTally()
				idle(ctx, ctx, e, tl)
				if r := tl.result(); !maps.Equal(r.outcomes, map[string]int64{tc.want: 1}) {
					t.Errorf("outcomes = %v, want %s", r.outcomes, tc.want)
				}
			})
		})
	}
}

// TestRequestsRecordRelayAnswers drives the request workers against a fake
// relay that stops the scenario itself after enough requests, so no test
// waits for a duration.
func TestRequestsRecordRelayAnswers(t *testing.T) {
	const stopAfter = 20
	cases := []struct {
		name       string
		run        func(ctx, abort context.Context, e *env, t *tally)
		answer     func(w http.ResponseWriter, f *fixture)
		wantKey    string
		wantErrors map[string]int64
	}{
		{"forwarded_unchanged", full, func(w http.ResponseWriter, f *fixture) {
			w.Header().Set("Relay-Upstream-Status", "200")
			_, _ = w.Write(f.responseBody) // a failed write fails the client, which the test checks
		}, outcomeForwarded, map[string]int64{}},
		{"forwarded_changed_body_flagged", full, func(w http.ResponseWriter, f *fixture) {
			w.Header().Set("Relay-Upstream-Status", "200")
			_, _ = w.Write(f.responseBody[1:]) // a failed write fails the client, which the test checks
		}, outcomeForwarded, nil},
		{"invalid_rejected", invalidSignatures, func(w http.ResponseWriter, _ *fixture) {
			w.Header().Set("Relay-Error", "invalid_token")
			w.WriteHeader(http.StatusUnauthorized)
		}, outcomeInvalid, map[string]int64{}},
		{"unknown_kid_rejected", unknownKeys, func(w http.ResponseWriter, _ *fixture) {
			w.Header().Set("Relay-Error", "invalid_token")
			w.WriteHeader(http.StatusUnauthorized)
		}, outcomeInvalid, map[string]int64{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixture{requestBody: fill(1000, "request-body-"), responseBody: fill(2000, "response-body-")}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var served atomic.Int64
			var mu sync.Mutex
			kids := map[string]bool{}
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if served.Add(1) >= stopAfter {
					cancel()
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
				if r.Method != http.MethodPost || r.RequestURI != tokenPath || !ok || strings.Count(token, ".") != 2 {
					t.Errorf("request = %s %s with a malformed Authorization field", r.Method, r.RequestURI)
				}
				header, _, _ := strings.Cut(token, ".")
				mu.Lock()
				kids[header] = true
				mu.Unlock()
				if tc.name != "invalid_rejected" && tc.name != "unknown_kid_rejected" && !bytes.Equal(body, f.requestBody) {
					t.Error("request body differs")
				}
				tc.answer(w, f)
			}))
			defer relay.Close()
			target, err := parseTarget(relay.URL)
			if err != nil {
				t.Fatal(err)
			}
			e := &env{relay: target, fits: newMinter(key(t), time.Now), fixture: f, workers: 4}
			tl := newTally()
			tc.run(ctx, t.Context(), e, tl)
			r := tl.result()
			if r.count < stopAfter || r.outcomes[tc.wantKey] != r.count {
				t.Errorf("count %d, outcomes %v; want %d or more, all %s", r.count, r.outcomes, stopAfter, tc.wantKey)
			}
			switch {
			case tc.wantErrors != nil && !maps.Equal(r.errors, tc.wantErrors):
				t.Errorf("errors = %v, want %v", r.errors, tc.wantErrors)
			case tc.wantErrors == nil && r.errors["body_mismatch"] != r.count:
				t.Errorf("errors = %v, want body_mismatch for every answer", r.errors)
			}
			if tc.name == "unknown_kid_rejected" && int64(len(kids)) != served.Load() {
				t.Errorf("%d distinct key IDs in %d requests", len(kids), served.Load())
			}
		})
	}
}

func TestPreflightNeedsOneUnchangedForwardedAnswer(t *testing.T) {
	cases := []struct {
		name    string
		answer  func(w http.ResponseWriter, f *fixture)
		wantErr string
	}{
		{"forwarded_unchanged_passes", func(w http.ResponseWriter, f *fixture) {
			w.Header().Set("Relay-Upstream-Status", "200")
			_, _ = w.Write(f.responseBody) // a failed write fails the client, which the test checks
		}, ""},
		{"stale_relay_rejecting_the_key_stops", func(w http.ResponseWriter, _ *fixture) {
			w.Header().Set("Relay-Error", "invalid_token")
			w.WriteHeader(http.StatusUnauthorized)
		}, "401 invalid_token"},
		{"untrusted_upstream_stops", func(w http.ResponseWriter, _ *fixture) {
			w.Header().Set("Relay-Error", "upstream_unreachable")
			w.WriteHeader(http.StatusBadGateway)
		}, "502 upstream_unreachable"},
		{"changed_body_stops", func(w http.ResponseWriter, f *fixture) {
			w.Header().Set("Relay-Upstream-Status", "200")
			_, _ = w.Write(f.responseBody[1:]) // a failed write fails the client, which the test checks
		}, "body_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixture{requestBody: fill(10, "request-body-"), responseBody: fill(20, "response-body-")}
			relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { tc.answer(w, f) }))
			defer relay.Close()
			target, err := parseTarget(relay.URL)
			if err != nil {
				t.Fatal(err)
			}
			err = preflight(t.Context(), &env{relay: target, fits: newMinter(key(t), time.Now), fixture: f})
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("preflight: %v", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("preflight error = %v, want it to name %s", err, tc.wantErr)
			}
		})
	}
}

func TestProbeRecordsFailedHealthAnswers(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/livez":
		case "/readyz":
			cancel() // the round in progress still completes
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			t.Errorf("probe requested %s", r.URL.Path)
		}
	}))
	defer relay.Close()
	p := probe(ctx, probeClient(), relay.URL)
	if p.sent < 2 || p.sent%2 != 0 || !maps.Equal(p.failures, map[string]int64{"/readyz status 503": p.sent / 2}) {
		t.Errorf("sent %d, failures %v", p.sent, p.failures)
	}
}

// roundTripFunc answers a client's requests in memory.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWaitReadyNeedsA200(t *testing.T) {
	t.Run("ready_on_200", func(t *testing.T) {
		ready := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		defer ready.Close()
		if err := waitReady(t.Context(), probeClient(), ready.URL); err != nil {
			t.Errorf("ready relay: %v", err)
		}
	})
	t.Run("not_ready_until_cancelled", func(t *testing.T) {
		// The bubble's fake clock runs the poll interval without a sleep.
		synctest.Test(t, func(t *testing.T) {
			const polls = 3
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var calls int
			c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if calls++; calls == polls {
					cancel() // this answer still arrives; waitReady must then stop
				}
				return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: http.NoBody, Request: r}, nil
			})}
			if err := waitReady(ctx, c, "http://relay.test"); !errors.Is(err, context.Canceled) {
				t.Errorf("waitReady = %v, want context.Canceled", err)
			}
			if calls != polls {
				t.Errorf("%d polls, want %d", calls, polls)
			}
		})
	})
}

// TestPrintSettingsNamesEveryRequiredSetting spells the setting names as
// literals: they are the relay's contract (PLAN.md §8).
func TestPrintSettingsNamesEveryRequiredSetting(t *testing.T) {
	var b strings.Builder
	printSettings(&b, "https://127.0.0.1:9443", "/tmp/load-ca.pem")
	for _, line := range []string{
		"RELAY_APP_ID=ari:cloud:ecosystem::app/11111111-1111-4111-8111-111111111111\n",
		"RELAY_ENVIRONMENT_ID=ari:cloud:ecosystem::environment/11111111-1111-4111-8111-111111111111/22222222-2222-4222-8222-222222222222\n",
		"RELAY_CLOUD_IDS=33333333-3333-4333-8333-333333333333\n",
		"RELAY_UPSTREAM_URL=https://127.0.0.1:9443\n",
		"RELAY_JWKS_URL=https://127.0.0.1:9443/.well-known/jwks.json\n",
		"RELAY_UPSTREAM_CA_FILE=/tmp/load-ca.pem\n",
		"SSL_CERT_FILE=/tmp/load-ca.pem\n",
	} {
		if !strings.Contains(b.String(), "\n"+line) {
			t.Errorf("settings lack %q", line)
		}
	}
	for _, name := range []string{"RELAY_ROUTES", "RELAY_RESPONSE_HEADERS"} {
		if strings.Contains(b.String(), name) {
			t.Errorf("settings contain removed setting %s", name)
		}
	}
}
