// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// keysSecretMarker stands for attacker-chosen or secret text. Tests put it
// into key IDs, URLs and error strings and check that no log line or
// returned error repeats it (PLAN.md §10).
const keysSecretMarker = "SECRET-MARKER-5e0c"

// testPublicKeys returns the public halves of the package's test signers,
// which are generated once per run (verify_test.go).
func testPublicKeys() [2]*rsa.PublicKey {
	s := signers()
	return [2]*rsa.PublicKey{&s.primary.PublicKey, &s.other.PublicKey}
}

// oddModulus returns an odd number of exactly bits bits. The parser checks
// only the size and parity of a modulus, so size boundaries need no real
// key of that size.
func oddModulus(bits int) *big.Int {
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	return n.SetBit(n, 0, 1)
}

// testJWK returns the JWKS entry for pub in the form Atlassian publishes.
func testJWK(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": kid,
		"n":   segment(string(pub.N.Bytes())),
		"e":   segment(string(big.NewInt(int64(pub.E)).Bytes())),
	}
}

func jwkWith(jwk map[string]any, name string, v any) map[string]any {
	c := maps.Clone(jwk)
	c[name] = v
	return c
}

func jwkWithout(jwk map[string]any, name string) map[string]any {
	c := maps.Clone(jwk)
	delete(c, name)
	return c
}

// testJWKS encodes keys as a JWKS document.
func testJWKS(t testing.TB, keys ...map[string]any) []byte {
	t.Helper()
	if keys == nil {
		keys = []map[string]any{}
	}
	raw, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return raw
}

// keysLog captures JSON log records. The cache worker writes from its own
// goroutine, hence the mutex.
type keysLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *keysLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *keysLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *keysLog) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(l, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// count returns how many records have message msg and, unless reason is
// empty, that reason.
func (l *keysLog) count(t *testing.T, msg, reason string) int {
	t.Helper()
	n := 0
	for line := range strings.Lines(l.String()) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v", err)
		}
		if rec["msg"] == msg && (reason == "" || rec["reason"] == reason) {
			n++
		}
	}
	return n
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestKeyLimitsMatchPlan(t *testing.T) {
	// The values are spelled out so that changing a PLAN.md §4.5 limit
	// breaks this test rather than passing silently.
	tests := []struct {
		name string
		got  any
		want any
	}{
		{"retry_initial_1s", JWKSRetryInitial, time.Second},
		{"retry_max_1m", JWKSRetryMax, time.Minute},
		{"unknown_refresh_interval_1m", JWKSUnknownRefreshInterval, time.Minute},
		{"fit_key_wait_1s", FITKeyWait, time.Second},
		{"jwks_body_64KiB", MaxJWKSBytes, 65536},
		{"jwks_fetch_timeout_10s", JWKSFetchTimeout, 10 * time.Second},
		{"jwks_max_keys_20", MaxJWKSKeys, 20},
		{"rsa_min_bits_2048", MinRSAModulusBits, 2048},
		{"rsa_max_bits_8192", MaxRSAModulusBits, 8192},
	}
	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestParseJWKSFailsWholeDocument(t *testing.T) {
	pub := testPublicKeys()[0]
	good := testJWK("k1", pub)
	n := good["n"].(string)
	even := new(big.Int).SetBit(oddModulus(MinRSAModulusBits), 0, 0)
	undersized := testJWK("k2", &rsa.PublicKey{N: oddModulus(1024), E: 65537})
	tooMany := make([]map[string]any, MaxJWKSKeys+1)
	for i := range tooMany {
		tooMany[i] = testJWK("k"+strconv.Itoa(i), pub)
	}
	// json.Marshal never writes the escape, so it is spliced in afterwards.
	escapedKID := bytes.Replace(
		testJWKS(t, good, testJWK("placeholder", pub)), []byte(`"placeholder"`), []byte(esc(`"~u006b1"`)), 1)

	tests := []struct {
		name string
		doc  []byte
		want jwksError
	}{
		{"not_json", []byte(`keys`), jwksMalformed},
		{"not_an_object", []byte(`[]`), jwksMalformed},
		{"trailing_json", append(testJWKS(t, good), `{}`...), jwksMalformed},
		{"duplicate_member_name", []byte(`{"keys":[],"keys":[]}`), jwksMalformed},
		{"duplicate_member_name_in_key", []byte(`{"keys":[{"kty":"EC","kty":"EC"}]}`), jwksMalformed},
		{"invalid_utf8", []byte("{\"keys\":[],\"x\":\"\xff\"}"), jwksMalformed},
		{"lone_surrogate_escape", []byte(`{"keys":[],"x":"\udc00"}`), jwksMalformed},
		{"keys_missing", []byte(`{}`), jwksMalformed},
		{"keys_case_variant", []byte(`{"Keys":[]}`), jwksMalformed},
		{"keys_null", []byte(`{"keys":null}`), jwksMalformed},
		{"keys_not_array", []byte(`{"keys":{}}`), jwksMalformed},
		{"key_not_object", []byte(`{"keys":["k1"]}`), jwksMalformed},
		{"key_null", []byte(`{"keys":[null]}`), jwksMalformed},
		{"kty_missing", testJWKS(t, jwkWithout(good, "kty")), jwksBadKey},
		{"kty_null", testJWKS(t, jwkWith(good, "kty", nil)), jwksBadKey},
		{"kty_not_string", testJWKS(t, jwkWith(good, "kty", 1)), jwksBadKey},
		{"use_null", testJWKS(t, jwkWith(good, "use", nil)), jwksBadKey},
		{"use_not_string", testJWKS(t, jwkWith(good, "use", []string{"sig"})), jwksBadKey},
		{"alg_null", testJWKS(t, jwkWith(good, "alg", nil)), jwksBadKey},
		{"alg_not_string", testJWKS(t, jwkWith(good, "alg", 256)), jwksBadKey},
		{"kid_missing", testJWKS(t, jwkWithout(good, "kid")), jwksBadKey},
		{"kid_empty", testJWKS(t, jwkWith(good, "kid", "")), jwksBadKey},
		{"kid_not_string", testJWKS(t, jwkWith(good, "kid", 1)), jwksBadKey},
		{"n_missing", testJWKS(t, jwkWithout(good, "n")), jwksBadKey},
		{"n_null", testJWKS(t, jwkWith(good, "n", nil)), jwksBadKey},
		{"n_not_string", testJWKS(t, jwkWith(good, "n", 1)), jwksBadKey},
		{"n_empty", testJWKS(t, jwkWith(good, "n", "")), jwksBadKey},
		{"n_padded", testJWKS(t, jwkWith(good, "n", base64.URLEncoding.EncodeToString(pub.N.Bytes()))), jwksBadKey},
		{"n_standard_alphabet", testJWKS(t, jwkWith(good, "n", "+"+n[1:])), jwksBadKey},
		{"n_line_break", testJWKS(t, jwkWith(good, "n", n[:100]+"\r\n"+n[100:])), jwksBadKey},
		{"n_non_canonical", testJWKS(t, jwkWith(good, "n", nonCanonical(t, n))), jwksBadKey},
		{"n_leading_zero_octet", testJWKS(t, jwkWith(good, "n", segment("\x00"+string(pub.N.Bytes())))), jwksBadKey},
		{"modulus_even", testJWKS(t, jwkWith(good, "n", segment(string(even.Bytes())))), jwksBadKey},
		{"modulus_over_max_bits", testJWKS(t, jwkWith(good, "n", segment(string(oddModulus(MaxRSAModulusBits+1).Bytes())))), jwksBadKey},
		{"e_missing", testJWKS(t, jwkWithout(good, "e")), jwksBadKey},
		{"e_not_string", testJWKS(t, jwkWith(good, "e", 65537)), jwksBadKey},
		{"e_empty", testJWKS(t, jwkWith(good, "e", "")), jwksBadKey},
		{"e_padded", testJWKS(t, jwkWith(good, "e", "Aw==")), jwksBadKey},
		{"e_leading_zero_octet", testJWKS(t, jwkWith(good, "e", "AAEAAQ")), jwksBadKey},
		{"e_one", testJWKS(t, jwkWith(good, "e", "AQ")), jwksBadKey},
		{"e_even", testJWKS(t, jwkWith(good, "e", "AQAA")), jwksBadKey},
		{"e_above_int32", testJWKS(t, jwkWith(good, "e", "gAAAAQ")), jwksBadKey},
		// Five octets 01 00 01 00 01 would wrap to 65537 in 32 bits.
		{"e_five_octets", testJWKS(t, jwkWith(good, "e", "AQABAAE")), jwksBadKey},
		{"bad_key_after_good_key", testJWKS(t, good, jwkWith(testJWK("k2", pub), "e", "AQ")), jwksBadKey},
		// The size of a malformed n is unknown, so even a small one fails.
		{"malformed_n_on_undersized_key", testJWKS(t, good, jwkWith(undersized, "n", base64.URLEncoding.EncodeToString(oddModulus(1024).Bytes()))), jwksBadKey},
		{"leading_zero_n_on_undersized_key", testJWKS(t, good, jwkWith(undersized, "n", segment("\x00"+string(oddModulus(1024).Bytes())))), jwksBadKey},
		{"duplicate_kid", testJWKS(t, good, good), jwksDuplicateKID},
		{"duplicate_kid_escaped", escapedKID, jwksDuplicateKID},
		{"duplicate_kid_with_skipped_key", testJWKS(t, good, map[string]any{"kty": "EC", "kid": "k1"}), jwksDuplicateKID},
		{"more_than_max_keys", testJWKS(t, tooMany...), jwksTooManyKeys},
		{"empty_key_set", testJWKS(t), jwksNoUsableKeys},
		{"all_keys_skipped", testJWKS(t, map[string]any{"kty": "EC", "kid": "k1"}), jwksNoUsableKeys},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requireEscape(t, tt.name, string(tt.doc))
			keys, err := parseJWKS(tt.doc, discardLogger())
			if err != tt.want || keys != nil {
				t.Fatalf("parseJWKS = %d keys, %v; want no keys, %v", len(keys), err, tt.want)
			}
		})
	}
}

func TestParseJWKSSkipsKeysItDoesNotUse(t *testing.T) {
	pub := testPublicKeys()[0]
	good := testJWK("k1", pub)
	other := testJWK("k2", testPublicKeys()[1])
	undersized := testJWK("k2", &rsa.PublicKey{N: oddModulus(MinRSAModulusBits - 1), E: 65537})
	tests := []struct {
		name string
		jwk  map[string]any
		want jwkSkip
	}{
		// A key the relay does not use is skipped before its other members
		// are read, so its junk cannot fail the refresh.
		{"kty_ec", map[string]any{"kty": "EC", "kid": "k2", "crv": "P-256", "n": 1}, skipKeyType},
		{"kty_case_variant", jwkWith(other, "kty", "rsa"), skipKeyType},
		{"use_enc", jwkWith(other, "use", "enc"), skipUse},
		{"use_case_variant", jwkWith(other, "use", "SIG"), skipUse},
		{"alg_rs512", jwkWith(other, "alg", "RS512"), skipAlgorithm},
		{"alg_none", jwkWith(other, "alg", "none"), skipAlgorithm},
		{"alg_case_variant", jwkWith(other, "alg", "rs256"), skipAlgorithm},
		{"modulus_under_min_bits", undersized, skipUndersized},
		// An undersized key can never verify a FIT, so its e and the parity
		// of its modulus are not judged (PLAN.md §4.5).
		{"undersized_with_even_exponent", jwkWith(undersized, "e", "Ag"), skipUndersized},
		{"undersized_with_exponent_missing", jwkWithout(undersized, "e"), skipUndersized},
		{"undersized_with_even_modulus", jwkWith(undersized, "n", segment(string(new(big.Int).SetBit(oddModulus(MinRSAModulusBits-1), 0, 0).Bytes()))), skipUndersized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := new(keysLog)
			keys, err := parseJWKS(testJWKS(t, good, tt.jwk), log.logger())
			if err != nil {
				t.Fatalf("parseJWKS: %v", err)
			}
			if len(keys) != 1 || keys["k1"] == nil {
				t.Fatalf("parseJWKS kept %d keys, want only k1", len(keys))
			}
			if got := log.count(t, "jwks keys skipped", string(tt.want)); got != 1 {
				t.Fatalf("skip records with reason %q = %d, want 1; log:\n%s", tt.want, got, log)
			}
		})
	}
}

func TestParseJWKSAcceptsEligibleKeys(t *testing.T) {
	pub := testPublicKeys()[0]
	good := testJWK("k1", pub)
	maxKeys := make([]map[string]any, MaxJWKSKeys)
	for i := range maxKeys {
		maxKeys[i] = testJWK("k"+strconv.Itoa(i+1), pub)
	}
	withExtra := bytes.Replace(testJWKS(t, jwkWith(good, "x5t", "unused")), []byte(`{"keys"`), []byte(`{"extra":{"a":[1]},"keys"`), 1)
	tests := []struct {
		name  string
		doc   []byte
		count int
		want  *rsa.PublicKey // the key expected under "k1"
	}{
		{"atlassian_form", testJWKS(t, good), 1, pub},
		{"use_and_alg_absent", testJWKS(t, jwkWithout(jwkWithout(good, "use"), "alg")), 1, pub},
		{"unknown_members_ignored", withExtra, 1, pub},
		{"exponent_three", testJWKS(t, jwkWith(good, "e", "Aw")), 1, &rsa.PublicKey{N: pub.N, E: 3}},
		{"exponent_max", testJWKS(t, jwkWith(good, "e", "f____w")), 1, &rsa.PublicKey{N: pub.N, E: 1<<31 - 1}},
		{"modulus_max_bits", testJWKS(t, testJWK("k1", &rsa.PublicKey{N: oddModulus(MaxRSAModulusBits), E: 65537})), 1, &rsa.PublicKey{N: oddModulus(MaxRSAModulusBits), E: 65537}},
		{"exactly_max_keys", testJWKS(t, maxKeys...), MaxJWKSKeys, pub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, err := parseJWKS(tt.doc, discardLogger())
			if err != nil {
				t.Fatalf("parseJWKS: %v", err)
			}
			if len(keys) != tt.count {
				t.Fatalf("parseJWKS kept %d keys, want %d", len(keys), tt.count)
			}
			if got := keys["k1"]; got == nil || !got.Equal(tt.want) {
				t.Fatalf("key k1 does not match the published key")
			}
		})
	}
}

func TestParseJWKSLogsNoKeyMaterial(t *testing.T) {
	pub := testPublicKeys()[0]
	undersized := &rsa.PublicKey{N: oddModulus(1024), E: 65537}
	log := new(keysLog)
	doc := testJWKS(t,
		testJWK(keysSecretMarker+"-good", pub),
		testJWK(keysSecretMarker+"-small", undersized),
		map[string]any{"kty": "EC", "kid": keysSecretMarker + "-ec"},
	)
	if _, err := parseJWKS(doc, log.logger()); err != nil {
		t.Fatalf("parseJWKS: %v", err)
	}
	out := log.String()
	for _, secret := range []string{keysSecretMarker, segment(string(pub.N.Bytes())), segment(string(undersized.N.Bytes()))} {
		if strings.Contains(out, secret) {
			t.Fatalf("log contains a key ID or key material:\n%s", out)
		}
	}
}

// trustingJWKSClient returns JWKSClient with srv's certificate as its only
// root, so the tests exercise the production client settings.
func trustingJWKSClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	c := JWKSClient()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c.Transport.(*http.Transport).TLSClientConfig.RootCAs = pool
	return c
}

func TestFetchJWKS(t *testing.T) {
	doc := []byte(`{"keys":[]}`)
	var followed atomic.Int32
	// A failed write only means the client stopped reading, which is what
	// the client-side checks below are about.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwks":
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			_, _ = w.Write(doc)
		case "/redirect":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			followed.Add(1)
			_, _ = w.Write(doc)
		case "/error":
			http.Error(w, keysSecretMarker, http.StatusInternalServerError)
		case "/no-content":
			w.WriteHeader(http.StatusNoContent)
		case "/max":
			_, _ = w.Write(bytes.Repeat([]byte("a"), MaxJWKSBytes))
		case "/over-chunked":
			_, _ = w.Write(bytes.Repeat([]byte("a"), MaxJWKSBytes+1))
		case "/over-declared":
			// The body never comes: only a client that refuses on the
			// declared length alone returns before its timeout.
			w.Header().Set("Content-Length", strconv.Itoa(MaxJWKSBytes+1))
			w.WriteHeader(http.StatusOK)
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Errorf("flush headers: %v", err)
			}
			<-r.Context().Done()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	client := trustingJWKSClient(t, srv)

	tests := []struct {
		name string
		path string
		want []byte
		err  error
	}{
		{"success", "/jwks", doc, nil},
		{"exactly_max_bytes", "/max", bytes.Repeat([]byte("a"), MaxJWKSBytes), nil},
		{"status_not_200", "/error", nil, jwksBadStatus},
		{"no_content_is_not_200", "/no-content", nil, jwksBadStatus},
		{"redirect_not_followed", "/redirect", nil, jwksBadStatus},
		{"body_over_max_unknown_length", "/over-chunked", nil, jwksTooLarge},
		{"body_over_max_declared_length", "/over-declared", nil, jwksTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(srv.URL+tt.path+"?"+keysSecretMarker, client, time.Hour, 2*time.Hour, discardLogger())
			got, err := c.fetch(t.Context())
			if err != tt.err || !bytes.Equal(got, tt.want) {
				t.Fatalf("fetch = %d bytes, %v; want %d bytes, %v", len(got), err, len(tt.want), tt.err)
			}
			if err != nil && strings.Contains(err.Error(), keysSecretMarker) {
				t.Fatalf("fetch error repeats the URL or the answer: %v", err)
			}
		})
	}
	if n := followed.Load(); n != 0 {
		t.Fatalf("redirect target fetched %d times, want 0", n)
	}
}

func TestFetchJWKSFailsWithoutNetworkDetail(t *testing.T) {
	trusted := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	// The refused handshake below is expected; keep it out of the test output.
	trusted.Config.ErrorLog = log.New(io.Discard, "", 0)
	trusted.StartTLS()
	defer trusted.Close()
	closed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closed.URL
	closed.Close()

	tests := []struct {
		name   string
		url    string
		client *http.Client
	}{
		{"connection_refused", closedURL, trustingJWKSClient(t, trusted)},
		// The production client trusts only the system roots, never the
		// test certificate.
		{"untrusted_certificate", trusted.URL, JWKSClient()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCache(tt.url+"/"+keysSecretMarker, tt.client, time.Hour, 2*time.Hour, discardLogger())
			got, err := c.fetch(t.Context())
			if err != jwksFetchFailed || got != nil {
				t.Fatalf("fetch = %d bytes, %v; want %v", len(got), err, jwksFetchFailed)
			}
			if strings.Contains(err.Error(), keysSecretMarker) {
				t.Fatalf("fetch error repeats the URL: %v", err)
			}
		})
	}
}

func TestJWKSClientSettings(t *testing.T) {
	c, dialer := jwksClient()
	if c.Timeout != JWKSFetchTimeout {
		t.Errorf("Timeout = %v, want JWKSFetchTimeout", c.Timeout)
	}
	if c.CheckRedirect == nil || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Errorf("CheckRedirect does not stop at the first response")
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport is %T, want *http.Transport", c.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("TLS minimum version is not 1.2")
	}
	if tr.Protocols == nil || !tr.Protocols.HTTP1() || tr.Protocols.HTTP2() || tr.Protocols.UnencryptedHTTP2() {
		t.Errorf("Protocols = %v, want HTTP/1.1 only", tr.Protocols)
	}
	if tr.Proxy == nil {
		t.Errorf("Proxy is nil, want HTTPS_PROXY and NO_PROXY honoured")
	}
	if !tr.DisableCompression {
		t.Errorf("DisableCompression is off")
	}
	if !tr.DisableKeepAlives {
		t.Errorf("DisableKeepAlives is off")
	}
	if tr.MaxResponseHeaderBytes != maxJWKSHeaderBytes {
		t.Errorf("MaxResponseHeaderBytes = %d, want %d", tr.MaxResponseHeaderBytes, maxJWKSHeaderBytes)
	}
	// Literals, so that dropping or changing a timeout fails here.
	if tr.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("TLSHandshakeTimeout = %v, want 10s", tr.TLSHandshakeTimeout)
	}
	if dialer.Timeout != 30*time.Second {
		t.Errorf("dial timeout = %v, want 30s", dialer.Timeout)
	}
	// The dial timeout check proves something only if the transport dials
	// with that dialer. Its Control hook runs before the connect, so nothing
	// is sent.
	errHook := errors.New("control hook ran")
	dialer.Control = func(string, string, syscall.RawConn) error { return errHook }
	if _, err := tr.DialContext(t.Context(), "tcp", "127.0.0.1:1"); !errors.Is(err, errHook) {
		t.Errorf("the transport dials with another dialer (%v)", err)
	}
}

// TestJWKSClientClosesSilentHandshake covers a JWKS host, or a box on the
// way to it, that accepts the connection and never answers the ClientHello.
// Go dials on a context detached from the fetch, so the fetch's end leaves
// the handshake running, and only the handshake timeout closes the socket.
// The peer is an in-memory pipe, so the bubble's fake clock runs both
// timeouts.
func TestJWKSClientClosesSilentHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		client := JWKSClient()
		tr := client.Transport.(*http.Transport)
		// The pipe stands for the JWKS host, whatever proxy the test
		// environment sets.
		tr.Proxy = nil
		closedAfter := make(chan time.Duration, 1)
		tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
			conn, peer := net.Pipe()
			dialed := time.Now()
			go func() {
				// Reads the ClientHello, answers nothing and returns when
				// the client closes its end.
				_, _ = io.Copy(io.Discard, peer)
				closedAfter <- time.Since(dialed)
			}()
			return conn, nil
		}
		// If the handshake timeout is missing, only this ends the handshake,
		// so the bubble can finish after the failure is reported.
		t.Cleanup(tr.CloseIdleConnections)

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		if _, err := fetchJWKS("https://keys.example/jwks.json", client)(ctx); err != jwksFetchFailed {
			t.Fatalf("fetch = %v, want %v", err, jwksFetchFailed)
		}
		select {
		case d := <-closedAfter:
			if d != tlsHandshakeTimeout {
				t.Errorf("connection closed %v after the dial, want %v", d, tlsHandshakeTimeout)
			}
		case <-time.After(time.Hour):
			t.Error("connection still open an hour after the fetch ended")
		}
	})
}

func TestJWKSErrorsAreFixedClasses(t *testing.T) {
	// Each value is a log reason; spelling them out keeps a rename visible.
	want := map[jwksError]string{
		jwksFetchFailed:  "fetch",
		jwksBadStatus:    "status",
		jwksTooLarge:     "too_large",
		jwksMalformed:    "malformed",
		jwksBadKey:       "key_parameters",
		jwksDuplicateKID: "duplicate_kid",
		jwksTooManyKeys:  "too_many_keys",
		jwksNoUsableKeys: "no_usable_keys",
		jwksPanic:        "panic",
	}
	for err, reason := range want {
		if got := failureReason(err); got != reason {
			t.Errorf("failureReason(%v) = %q, want %q", err, got, reason)
		}
	}
	if got := failureReason(fmt.Errorf("dial %s: refused", keysSecretMarker)); got != "fetch" {
		t.Errorf("failureReason(foreign error) = %q, want fetch", got)
	}
}
