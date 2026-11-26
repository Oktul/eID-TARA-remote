// SPDX-License-Identifier: EUPL-1.2

package server_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"eid-tara-remote/internal/server"
)

// TestCheckOrder proves the order of PLAN.md §4.2 on a ready relay: the FIT
// before the route, so a caller without a token learns nothing about the
// routes, and the route before the body. No rejected request reaches the
// upstream.
func TestCheckOrder(t *testing.T) {
	r := newRelay(t, relayOptions{})
	fit := validFIT(t)
	otherKey := signFIT(t, testKeys().other, fitClaims())
	big := strings.Repeat("a", server.MaxRequestBytes+1)
	cases := []struct {
		name      string
		method    string
		target    string
		header    http.Header
		body      string
		status    int
		code      string
		versioned bool
	}{
		{"invalid_token_before_route_not_allowed", "POST", "/oidc/other", nil, "", 401, "invalid_token", false},
		{"bad_signature_before_route_not_allowed", "POST", "/oidc/other", bearer(otherKey), "", 401, "invalid_token", false},
		{"invalid_token_before_body_too_large", "POST", "/oidc/token", nil, big, 401, "invalid_token", false},
		{"invalid_token_before_info", "GET", "/relay/v1/info", nil, "", 401, "invalid_token", false},
		{"route_not_allowed_before_body_too_large", "POST", "/oidc/other", bearer(fit), big, 404, "route_not_allowed", true},
		{"body_too_large_before_forward", "POST", "/oidc/token", bearer(fit), big, 413, "body_too_large", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := r.do(t, c.method, c.target, c.header, strings.NewReader(c.body))
			expectRelayError(t, got, c.status, c.code, c.versioned)
		})
	}
	if n := r.upstreamHits.Load(); n != 0 {
		t.Errorf("%d rejected requests reached the upstream", n)
	}

	t.Run("not_ready_before_invalid_token", func(t *testing.T) {
		r := newRelay(t, relayOptions{jwks: jwksUnavailable, notReady: true})
		for _, h := range []http.Header{nil, bearer("not-a-jws"), bearer(otherKey), bearer(fit)} {
			expectRelayError(t, r.do(t, "POST", "/oidc/token", h, nil), 503, "not_ready", false)
		}
		expectRelayError(t, r.do(t, "GET", "/relay/v1/info", bearer(fit), nil), 503, "not_ready", false)
		if n := r.upstreamHits.Load(); n != 0 {
			t.Errorf("%d requests reached the upstream without keys", n)
		}
	})
}

// TestHealthBypassesConcurrencyCap proves PLAN.md §4.2 and §6: with every
// forwarding slot held by a slow upstream call, health checks and info still
// answer locally, without touching the upstream or the JWKS, and a caller
// without a FIT is refused as on an idle relay. Only a token POST that
// passed every earlier check gets 503 too_busy (owner, 2026-10-20).
func TestHealthBypassesConcurrencyCap(t *testing.T) {
	g := newGate()
	defer g.release()
	r := newRelay(t, relayOptions{upstream: g.handler})
	fit := validFIT(t)
	held := make(chan error, server.MaxConcurrent)
	for range server.MaxConcurrent {
		go func() {
			got, err := r.send(context.Background(), "POST", "/oidc/token", bearer(fit), nil)
			if err == nil && got.status != http.StatusOK {
				err = fmt.Errorf("status %d", got.status)
			}
			held <- err
		}()
	}
	g.waitEntered(t, server.MaxConcurrent)

	// A health check that needed a slot would wait for the gate and time out.
	expectHealthy(t, r.do(t, "GET", "/livez", nil, nil))
	expectHealthy(t, r.do(t, "GET", "/readyz", nil, nil))
	expectRelayError(t, r.do(t, "POST", "/oidc/token", bearer(fit), nil), 503, "too_busy", true)
	// The slot comes before the body, so an oversized token POST is busy too.
	big := strings.NewReader(strings.Repeat("a", server.MaxRequestBytes+1))
	expectRelayError(t, r.do(t, "POST", "/oidc/token", bearer(fit), big), 503, "too_busy", true)
	expectRelayError(t, r.do(t, "POST", "/oidc/token", nil, nil), 401, "invalid_token", false)
	expectRelayError(t, r.do(t, "POST", "/oidc/other", bearer(fit), nil), 404, "route_not_allowed", true)
	if got := r.do(t, "GET", "/relay/v1/info", bearer(fit), nil); got.status != http.StatusOK {
		t.Errorf("info on a full relay: status %d, want 200", got.status)
	}
	if n := r.upstreamHits.Load(); n != server.MaxConcurrent {
		t.Errorf("upstream calls = %d, want only the %d held ones", n, server.MaxConcurrent)
	}
	if n := r.jwksHits.Load(); n != 1 {
		t.Errorf("JWKS fetches = %d, want only the startup fetch", n)
	}

	g.release()
	for range server.MaxConcurrent {
		if err := <-held; err != nil {
			t.Errorf("held request: %v", err)
		}
	}
	// A slot is freed before its request's log line is written.
	busy := 0
	for _, line := range r.logs.waitRequests(t, server.MaxConcurrent+7) {
		if field(line, "error") != "too_busy" {
			continue
		}
		busy++
		// Only verified data: the matched route and the signed site.
		if field(line, "route") != "POST /oidc/token" || field(line, "cloud_id") != testSiteA {
			t.Errorf("too_busy log: route %q, cloud_id %q", field(line, "route"), field(line, "cloud_id"))
		}
	}
	if busy != 2 {
		t.Errorf("too_busy log lines = %d, want 2", busy)
	}
	if got := r.do(t, "POST", "/oidc/token", bearer(fit), nil); got.status != http.StatusOK {
		t.Errorf("after release: status %d, want 200", got.status)
	}
}

// notHealth lists requests that resemble a health check but are not the
// exact GET /livez or GET /readyz that PLAN.md §4.2 exempts. They take the
// FIT path like any other request.
var notHealth = []struct{ name, method, target string }{
	{"head_livez", "HEAD", "/livez"},
	{"livez_query", "GET", "/livez?x"},
	{"livez_empty_query", "GET", "/livez?"},
	{"post_livez", "POST", "/livez"},
	{"double_slash_livez", "GET", "//livez"},
	{"trailing_slash_livez", "GET", "/livez/"},
	{"upper_case_livez", "GET", "/LIVEZ"},
	{"encoded_livez", "GET", "/live%7a"},
	{"absolute_form_livez", "GET", "http://relay.example/livez"},
	{"head_readyz", "HEAD", "/readyz"},
	{"readyz_query", "GET", "/readyz?x"},
	{"post_readyz", "POST", "/readyz"},
	{"double_slash_readyz", "GET", "//readyz"},
	{"trailing_slash_readyz", "GET", "/readyz/"},
}

// TestHealthExemptionsAreExact proves that only the exact health requests
// skip the FIT: anything else answers 401 on a ready relay and 503 not_ready
// on one without keys, and is logged at info with the unmatched route.
func TestHealthExemptionsAreExact(t *testing.T) {
	cases := []struct {
		name   string
		opts   relayOptions
		status int
		code   string
	}{
		{"ready", relayOptions{}, 401, "invalid_token"},
		{"not_ready", relayOptions{jwks: jwksUnavailable, notReady: true}, 503, "not_ready"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRelay(t, c.opts)
			for i, n := range notHealth {
				got := r.raw(t, n.method, requestText(n.method, n.target, nil))
				if n.method == "HEAD" {
					expectErrorHeaders(t, got, c.status, c.code, false)
				} else {
					expectRelayError(t, got, c.status, c.code, false)
				}
				line := r.logs.waitRequests(t, i+1)[i]
				if field(line, "level") != "INFO" || field(line, "route") != "unmatched" {
					t.Errorf("%s: logged level %s route %s, want INFO unmatched", n.name,
						field(line, "level"), field(line, "route"))
				}
			}
			// The exact request is still a health check.
			if got := r.do(t, "GET", "/livez", nil, nil); got.status != http.StatusOK {
				t.Errorf("GET /livez = %d, want 200", got.status)
			}
		})
	}
}

// TestNotReadyUntilFirstKeySnapshot proves PLAN.md §4.5: until the first
// JWKS fetch succeeds, /readyz and every protected endpoint answer 503
// not_ready, while /livez stays 200; the first snapshot makes the relay
// ready.
func TestNotReadyUntilFirstKeySnapshot(t *testing.T) {
	g := newGate()
	defer g.release()
	r := newRelay(t, relayOptions{notReady: true, jwks: func(w http.ResponseWriter, req *http.Request) {
		g.entered <- struct{}{}
		select {
		case <-g.open:
			serveJWKS(w, req)
		case <-req.Context().Done():
		}
	}})
	g.waitEntered(t, 1) // the first fetch is in flight, so no snapshot exists
	fit := validFIT(t)
	expectRelayError(t, r.do(t, "GET", "/readyz", nil, nil), 503, "not_ready", false)
	expectHealthy(t, r.do(t, "GET", "/livez", nil, nil))
	expectRelayError(t, r.do(t, "POST", "/oidc/token", bearer(fit), nil), 503, "not_ready", false)
	expectRelayError(t, r.do(t, "GET", "/relay/v1/info", bearer(fit), nil), 503, "not_ready", false)

	g.release()
	waitUntil(t, "the first key snapshot", r.keys.Ready)
	expectHealthy(t, r.do(t, "GET", "/readyz", nil, nil))
	if got := r.do(t, "POST", "/oidc/token", bearer(fit), nil); got.status != http.StatusOK {
		t.Errorf("after the first snapshot: status %d, want 200", got.status)
	}
}

// TestKeyWaitHoldsNoSlot proves the SR-2 fix of PLAN.md §16: requests with
// an unknown kid wait for a JWKS refresh without holding a forwarding slot,
// so more of them than MaxConcurrent neither answer too_busy nor keep a
// valid token exchange out (§4.2 step 3, owner 2026-10-20). The refresh is
// held open until the valid exchange has its answer.
func TestKeyWaitHoldsNoSlot(t *testing.T) {
	refreshing := make(chan struct{}, 1)
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var fetches atomic.Int64
	jwks := func(w http.ResponseWriter, req *http.Request) {
		if fetches.Add(1) > 1 {
			select {
			case refreshing <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-req.Context().Done():
			}
		}
		serveJWKS(w, req)
	}
	r := newRelay(t, relayOptions{jwks: jwks})
	unknown := signFITKID(t, testKeys().published, "unknown-kid", fitClaims())

	// Waiters report through done, never through t: after a t.Fatal below
	// they may still be running, and logging then would panic.
	type result struct {
		got reply
		err error
	}
	const waiters = server.MaxConcurrent + 10
	done := make(chan result, waiters)
	for range waiters {
		go func() {
			got, err := r.send(context.Background(), "POST", "/oidc/token", bearer(unknown), nil)
			done <- result{got, err}
		}()
	}
	select {
	case <-refreshing:
	case <-time.After(waitTimeout):
		t.Fatal("timed out waiting for the unknown-kid refresh")
	}

	if got := r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil); got.status != http.StatusOK {
		t.Errorf("valid exchange during the key wait: status %d, want 200", got.status)
	}
	once.Do(func() { close(release) })
	for range waiters {
		res := <-done
		if res.err != nil {
			t.Error(res.err)
			continue
		}
		expectRelayError(t, res.got, 401, "invalid_token", false)
	}
	if n := r.upstreamHits.Load(); n != 1 {
		t.Errorf("upstream calls = %d, want only the valid one", n)
	}
}

// TestReadinessFollowsKeyAge proves PLAN.md §4.5 and the first check of
// §4.2. Once the last good snapshot reaches RELAY_JWKS_MAX_AGE the relay is
// not ready and answers not_ready before it judges any token, whether or not
// every slot is taken. A request admitted earlier still gets its upstream
// answer.
//
// The snapshot age is measured on the real clock and the fetches cross real
// sockets, so a testing/synctest bubble cannot fake it: this test waits
// about RELAY_JWKS_MAX_AGE, 400 ms.
func TestReadinessFollowsKeyAge(t *testing.T) {
	g := newGate()
	defer g.release()
	var failing atomic.Bool
	jwks := func(w http.ResponseWriter, req *http.Request) {
		if failing.Load() {
			jwksUnavailable(w, req)
			return
		}
		serveJWKS(w, req)
	}
	r := newRelay(t, relayOptions{
		env: map[string]string{
			"RELAY_JWKS_REFRESH": "40ms",
			"RELAY_JWKS_MAX_AGE": "400ms",
		},
		upstream: g.handler,
		jwks:     jwks,
	})
	fit := validFIT(t)
	held := make(chan error, server.MaxConcurrent)
	for range server.MaxConcurrent {
		go func() {
			got, err := r.send(context.Background(), "POST", "/oidc/token", bearer(fit), nil)
			if err == nil && got.status != http.StatusOK {
				err = fmt.Errorf("status %d", got.status)
			}
			held <- err
		}()
	}
	g.waitEntered(t, server.MaxConcurrent)
	failing.Store(true)
	waitUntil(t, "the key snapshot to expire", func() bool { return !r.keys.Ready() })

	expectRelayError(t, r.do(t, "POST", "/oidc/token", bearer(fit), nil), 503, "not_ready", false)
	expectRelayError(t, r.do(t, "GET", "/readyz", nil, nil), 503, "not_ready", false)
	expectHealthy(t, r.do(t, "GET", "/livez", nil, nil))

	g.release()
	for range server.MaxConcurrent {
		if err := <-held; err != nil {
			t.Errorf("request admitted before expiry: %v", err)
		}
	}
	r.logs.waitRequests(t, server.MaxConcurrent+3) // every earlier request has finished
	for _, h := range []http.Header{bearer(fit), nil, bearer("not-a-jws")} {
		expectRelayError(t, r.do(t, "POST", "/oidc/token", h, nil), 503, "not_ready", false)
	}
	if n := r.upstreamHits.Load(); n != server.MaxConcurrent {
		t.Errorf("upstream calls = %d, want only the %d admitted before expiry", n, server.MaxConcurrent)
	}
}

// TestRequestTargetsRefusedAfterFIT proves PLAN.md §4.2 step 2 and §5: the
// relay compares the raw request target byte for byte, so queries,
// absolute-form and asterisk targets, percent-encoding, dot segments and
// method variants never match a route, even with a valid FIT. Raw TCP keeps
// Go's client from normalizing the targets; Server.Run is used because only
// its http.Server passes "OPTIONS *" to the relay (DisableGeneralOptionsHandler).
func TestRequestTargetsRefusedAfterFIT(t *testing.T) {
	r := newRelay(t, relayOptions{run: true})
	fit := validFIT(t)
	cases := []struct{ name, method, target string }{
		{"query_string", "POST", "/oidc/token?x=1"},
		{"empty_query", "POST", "/oidc/token?"},
		{"absolute_form", "POST", "http://relay.example/oidc/token"},
		{"absolute_form_https", "POST", "https://relay.example/oidc/token"},
		{"options_asterisk", "OPTIONS", "*"},
		{"encoded_slash", "POST", "/oidc%2Ftoken"},
		{"encoded_letter", "POST", "/oidc/%74oken"},
		{"encoded_dot_segments", "POST", "/x/%2e%2e/oidc/token"},
		{"dot_segment", "POST", "/oidc/./token"},
		{"dot_dot_segment", "POST", "/x/../oidc/token"},
		{"double_slash", "POST", "//oidc/token"},
		{"trailing_slash", "POST", "/oidc/token/"},
		{"path_case", "POST", "/OIDC/token"},
		{"method_case", "post", "/oidc/token"},
		{"get_token", "GET", "/oidc/token"},
		{"head_token", "HEAD", "/oidc/token"},
		{"put_token", "PUT", "/oidc/token"},
		{"patch_token", "PATCH", "/oidc/token"},
		{"delete_token", "DELETE", "/oidc/token"},
		{"options_token", "OPTIONS", "/oidc/token"},
		{"trace_token", "TRACE", "/oidc/token"},
		{"connect_token", "CONNECT", "/oidc/token"},
		{"other_method", "PROPFIND", "/oidc/token"},
		{"other_path", "POST", "/oidc/keys"},
		{"info_query", "GET", "/relay/v1/info?x"},
		{"info_head", "HEAD", "/relay/v1/info"},
		{"info_post", "POST", "/relay/v1/info"},
		{"reserved_prefix", "GET", "/relay/v1/other"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := r.raw(t, c.method, requestText(c.method, c.target, bearer(fit)))
			if c.method == "HEAD" {
				expectErrorHeaders(t, got, 404, "route_not_allowed", true)
			} else {
				expectRelayError(t, got, 404, "route_not_allowed", true)
			}
			line := r.logs.waitRequests(t, i+1)[i]
			if field(line, "route") != "unmatched" || field(line, "cloud_id") != testSiteA {
				t.Errorf("logged route %s cloud_id %s, want unmatched %s",
					field(line, "route"), field(line, "cloud_id"), testSiteA)
			}
		})
	}
	if n := r.upstreamHits.Load(); n != 0 {
		t.Errorf("%d refused targets reached the upstream", n)
	}

	t.Run("options_asterisk_without_fit", func(t *testing.T) {
		// 401 rather than net/http's own 200 shows that the relay judged it.
		expectRelayError(t, r.raw(t, "OPTIONS", requestText("OPTIONS", "*", nil)), 401, "invalid_token", false)
	})
	t.Run("exact_route_control", func(t *testing.T) {
		got := r.raw(t, "POST", requestText("POST", "/oidc/token", bearer(fit)))
		if got.status != http.StatusOK || got.body != upstreamBody {
			t.Errorf("got %d %q, want the upstream answer", got.status, got.body)
		}
	})
}

// opaqueReader hides the body's length from Go's client, which then sends
// it chunked.
type opaqueReader struct{ io.Reader }

// TestRequestBodyLimit proves PLAN.md §4.2 step 4 for declared and chunked
// bodies, at and over the request limit. An oversized body never
// reaches the upstream.
func TestRequestBodyLimit(t *testing.T) {
	var mu sync.Mutex
	var received []int
	r := newRelay(t, relayOptions{
		upstream: func(w http.ResponseWriter, req *http.Request) {
			b, _ := io.ReadAll(req.Body) // the length is what the test checks
			mu.Lock()
			received = append(received, len(b))
			mu.Unlock()
			answerOK(w, req)
		},
	})
	fit := validFIT(t)
	cases := []struct {
		name   string
		body   io.Reader
		tooBig bool
	}{
		{"content_length_at_limit", strings.NewReader(strings.Repeat("a", server.MaxRequestBytes)), false},
		{"content_length_over_limit", strings.NewReader(strings.Repeat("a", server.MaxRequestBytes+1)), true},
		{"chunked_at_limit", opaqueReader{strings.NewReader(strings.Repeat("a", server.MaxRequestBytes))}, false},
		{"chunked_over_limit", opaqueReader{strings.NewReader(strings.Repeat("a", server.MaxRequestBytes+1))}, true},
		{"chunked_far_over_limit", opaqueReader{strings.NewReader(strings.Repeat("a", 2*server.MaxRequestBytes))}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := r.do(t, "POST", "/oidc/token", bearer(fit), c.body)
			if c.tooBig {
				expectRelayError(t, got, 413, "body_too_large", true)
			} else if got.status != http.StatusOK {
				t.Errorf("status = %d, want 200", got.status)
			}
		})
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(received, []int{server.MaxRequestBytes, server.MaxRequestBytes}) {
		t.Errorf("upstream received bodies of %v bytes, want only the two at the limit", received)
	}
}

// TestOversizedChunkedBodyClosesConnection proves that an oversized chunked
// body gets its 413 with Connection: close and that the relay then ends the
// connection instead of keeping it for another request (PLAN.md §6, R-4).
// The request asks for keep-alive, so the close is the relay's own.
func TestOversizedChunkedBodyClosesConnection(t *testing.T) {
	r := newRelay(t, relayOptions{})
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("a", server.MaxRequestBytes+1)
	// A keep-alive request: nothing but the relay asks for the close.
	if _, err := fmt.Fprintf(conn, "POST /oidc/token HTTP/1.1\r\nHost: relay.example\r\nAuthorization: Bearer %s\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", validFIT(t), len(body), body); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if !resp.Close {
		t.Fatal("413 does not announce Connection: close")
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Errorf("after the 413 the connection gave %v, want EOF", err)
	}
}

// TestOversizedBodyAnswerSurvivesPipelinedRequest proves that a client still
// sending when the relay refuses its body gets the 413 and a clean close,
// not a reset connection (PLAN.md §4.3, R-4). A pipelined request with a
// large body follows the oversized one. Closing the socket with those bytes
// unread sends a reset, which on Windows destroys the 413 in the client's
// receive buffer and on Linux takes the place of the EOF after it. net/http
// half-closes and waits first only when http.MaxBytesReader reaches its own
// ResponseWriter (readBody).
func TestOversizedBodyAnswerSurvivesPipelinedRequest(t *testing.T) {
	r := newRelay(t, relayOptions{})
	fit := validFIT(t)
	body, next := strings.Repeat("a", server.MaxRequestBytes+1), strings.Repeat("b", 1<<20)
	request := fmt.Sprintf("POST /oidc/token HTTP/1.1\r\nHost: relay.example\r\nAuthorization: Bearer %s\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", fit, len(body), body) +
		fmt.Sprintf("POST /oidc/token HTTP/1.1\r\nHost: relay.example\r\nAuthorization: Bearer %s\r\n"+
			"Content-Length: %d\r\n\r\n%s", fit, len(next), next)
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	// The relay reads no further than the first request, so this write
	// blocks once the socket buffers are full; it ends with the connection.
	written := make(chan struct{})
	go func() {
		defer close(written)
		_, _ = io.WriteString(conn, request) // fails once the connection closes
	}()
	defer func() {
		_ = conn.Close()
		<-written
	}()
	if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	// Reading only after the relay has logged the request gives a reset time
	// to arrive first, as it would for a client slower to read.
	r.logs.waitRequests(t, 1)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("the 413 was lost: %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
	if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
		t.Errorf("after the 413 the connection gave %v, want EOF", err)
	}
}

// TestKeyLookupNotReadyAnswersNotReady proves PLAN.md §4.2 step 1 for a key
// snapshot that expires between the readiness check and the key lookup: the
// token was never judged, so the answer is 503 not_ready, not 401. The
// Verifier's key source reports fit.ErrNotReady while the cache the server
// checks first is ready.
func TestKeyLookupNotReadyAnswersNotReady(t *testing.T) {
	r := newRelay(t, relayOptions{lookupNotReady: true})
	expectRelayError(t, r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil), 503, "not_ready", false)
	line := r.logs.waitRequests(t, 1)[0]
	if field(line, "error") != "not_ready" {
		t.Errorf("logged error %s, want not_ready", field(line, "error"))
	}
	if v, ok := line["auth_reason"]; ok {
		t.Errorf("auth_reason = %v for a token that was never judged", v)
	}
	if n := r.upstreamHits.Load(); n != 0 {
		t.Errorf("%d requests reached the upstream", n)
	}
}

// TestUnreadableBodyClosesConnectionWithoutAnswer proves PLAN.md §4.3: a
// body that cannot be read for a reason other than its size (broken
// chunked framing, a client that leaves mid-body) gets the connection
// closed without any answer, and the log records request_read.
func TestUnreadableBodyClosesConnectionWithoutAnswer(t *testing.T) {
	r := newRelay(t, relayOptions{})
	fit := validFIT(t)
	head := "POST /oidc/token HTTP/1.1\r\nHost: relay.example\r\nAuthorization: Bearer " + fit + "\r\n"
	cases := []struct {
		name      string
		request   string
		closeSend bool // the client stops sending after request
	}{
		{"malformed_chunk_size", head + "Transfer-Encoding: chunked\r\n\r\nzz\r\n", false},
		{"chunked_body_cut_off", head + "Transfer-Encoding: chunked\r\n\r\n10\r\n0123", true},
		{"content_length_body_cut_off", head + "Content-Length: 100\r\n\r\n0123456789", true},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", r.addr)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.WriteString(conn, c.request); err != nil {
				t.Fatal(err)
			}
			if c.closeSend {
				if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			got, err := io.ReadAll(conn)
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				t.Fatal("the relay kept the connection open")
			}
			if len(got) != 0 {
				t.Errorf("the relay answered %q, want no answer", got)
			}
			line := r.logs.waitRequests(t, i+1)[i]
			if field(line, "error") != "request_read" || field(line, "route") != "POST /oidc/token" {
				t.Errorf("logged error %s route %s, want request_read POST /oidc/token",
					field(line, "error"), field(line, "route"))
			}
		})
	}
	if n := r.upstreamHits.Load(); n != 0 {
		t.Errorf("%d unreadable requests reached the upstream", n)
	}
}

// TestUpstreamTimeout proves PLAN.md R-2: an upstream slower than
// RELAY_UPSTREAM_TIMEOUT gets 504 upstream_timeout. The test waits the
// 100 ms timeout on the real clock, since the call crosses real sockets.
func TestUpstreamTimeout(t *testing.T) {
	g := newGate()
	defer g.release()
	r := newRelay(t, relayOptions{env: map[string]string{"RELAY_UPSTREAM_TIMEOUT": "100ms"}, upstream: g.handler})
	expectRelayError(t, r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil), 504, "upstream_timeout", true)
	line := r.logs.waitRequests(t, 1)[0]
	if field(line, "error") != "upstream_timeout" || field(line, "status") != "504" {
		t.Errorf("logged error %s status %s, want upstream_timeout 504", field(line, "error"), field(line, "status"))
	}
	if _, ok := line["upstream_status"]; ok {
		t.Error("upstream_status logged without an upstream answer")
	}
}

// hijackedUpstream answers with a broken HTTP response that carries the
// secret marker, so the transport's error text holds it.
func hijackedUpstream(w http.ResponseWriter, r *http.Request) {
	_, _ = io.Copy(io.Discard, r.Body)
	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Length: " + secretMarker + "\r\n\r\n")
	_ = buf.Flush()
}

// TestUpstreamFailures proves the 502 codes of PLAN.md §4.3 and that the
// transport's error text, which names addresses, certificates and upstream
// bytes, never reaches the log (§10).
func TestUpstreamFailures(t *testing.T) {
	over := strings.Repeat("a", 65537)
	cases := []struct {
		name string
		opts relayOptions
		code string
	}{
		{"closed_port", relayOptions{upstreamURL: closedPortURL(t)}, "upstream_unreachable"},
		{"untrusted_certificate", relayOptions{untrustedUpstream: true}, "upstream_unreachable"},
		{"malformed_response", relayOptions{upstream: hijackedUpstream}, "upstream_unreachable"},
		{"content_length_over_limit", relayOptions{upstream: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "65537")
			_, _ = io.WriteString(w, over)
		}}, "upstream_too_large"},
		{"chunked_over_limit", relayOptions{upstream: func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, over[:512])
			_ = http.NewResponseController(w).Flush() // no Content-Length from here on
			_, _ = io.WriteString(w, over[512:])
		}}, "upstream_too_large"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRelay(t, c.opts)
			expectRelayError(t, r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil), 502, c.code, true)
			line := r.logs.waitRequests(t, 1)[0]
			if field(line, "error") != c.code {
				t.Errorf("logged error %s, want %s", field(line, "error"), c.code)
			}
			u, err := url.Parse(r.upstreamURL)
			if err != nil {
				t.Fatal(err)
			}
			logs := r.logs.String()
			for _, leak := range []string{secretMarker, u.Host, "x509", "certificate", "refused", "malformed", "tls:"} {
				if strings.Contains(logs, leak) {
					t.Errorf("log contains %q", leak)
				}
			}
		})
	}
	t.Run("at_limit", func(t *testing.T) {
		at := over[:65536]
		r := newRelay(t, relayOptions{
			upstream: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, at) },
		})
		if got := r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil); got.status != http.StatusOK || got.body != at {
			t.Errorf("got %d with %d bytes, want 200 with 65536", got.status, len(got.body))
		}
	})
}

// TestCallerDisconnectCancelsUpstreamCall proves PLAN.md R-3: when the
// caller goes away, the upstream call is canceled, and the log records
// client_canceled.
func TestCallerDisconnectCancelsUpstreamCall(t *testing.T) {
	entered := make(chan struct{}, 1)
	canceled := make(chan struct{})
	var once sync.Once
	r := newRelay(t, relayOptions{upstream: func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		entered <- struct{}{}
		<-req.Context().Done()
		once.Do(func() { close(canceled) })
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.send(ctx, "POST", "/oidc/token", bearer(validFIT(t)), strings.NewReader("code=synthetic"))
		done <- err
	}()
	deadline := time.NewTimer(waitTimeout)
	defer deadline.Stop()
	select {
	case <-entered:
	case <-deadline.C:
		t.Fatal("the request never reached the upstream")
	}
	cancel()
	select {
	case <-canceled:
	case <-deadline.C:
		t.Fatal("the upstream call outlived the caller")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("client error = %v, want context.Canceled", err)
	}
	line := r.logs.waitRequests(t, 1)[0]
	if field(line, "error") != "client_canceled" {
		t.Errorf("logged error %s, want client_canceled", field(line, "error"))
	}
}

// TestPanicBecomesInternalError proves PLAN.md R-6: a panic below the
// handler becomes 500 internal_error, the log names only the class, and the
// server keeps serving. A nil Forwarder panics in Forward.
func TestPanicBecomesInternalError(t *testing.T) {
	r := newRelay(t, relayOptions{nilForwarder: true})
	fit := validFIT(t)
	expectRelayError(t, r.do(t, "POST", "/oidc/token", bearer(fit), strings.NewReader("code=synthetic")), 500, "internal_error", true)
	if got := r.do(t, "GET", "/relay/v1/info", bearer(fit), nil); got.status != http.StatusOK {
		t.Errorf("after the panic: info status %d, want 200", got.status)
	}
	expectRelayError(t, r.do(t, "POST", "/oidc/token", bearer(fit), nil), 500, "internal_error", true)
	expectHealthy(t, r.do(t, "GET", "/livez", nil, nil))
	lines := r.logs.waitRequests(t, 4)
	if field(lines[0], "error") != "panic" || field(lines[0], "status") != "500" {
		t.Errorf("logged error %s status %s, want panic 500", field(lines[0], "error"), field(lines[0], "status"))
	}
	logs := r.logs.String()
	for _, leak := range []string{"runtime error", "nil pointer", "goroutine", "server.go"} {
		if strings.Contains(logs, leak) {
			t.Errorf("log contains panic detail %q", leak)
		}
	}
}

// TestForwardedRequestCarriesOnlyAllowedParts follows one request to the
// upstream (PLAN.md §5): the target stays /oidc/token, the credential replaces
// the caller's Authorization, so the FIT never leaves the relay, and only
// allowlisted headers and the unchanged body pass.
func TestForwardedRequestCarriesOnlyAllowedParts(t *testing.T) {
	type seen struct {
		method, target, host, body string
		header                     http.Header
	}
	got := make(chan seen, 1)
	r := newRelay(t, relayOptions{upstream: func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body) // compared below
		got <- seen{req.Method, req.RequestURI, req.Host, string(b), req.Header.Clone()}
		answerOK(w, req)
	}})
	fit := validFIT(t)
	h := bearer(fit)
	h.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Set("Accept", "application/json")
	h.Set("X-B3-Traceid", "463ac35c9f6413ad48485a3953bb6124")
	h.Set("X-Forge-Oauth-System", "synthetic-oauth-token")
	h.Set("X-Forwarded-For", "192.0.2.1")
	h.Set("X-Custom", "synthetic")
	h.Set("Cookie", "session=synthetic")
	const body = "grant_type=authorization_code&code=synthetic-code"
	if rep := r.do(t, "POST", "/oidc/token", h, strings.NewReader(body)); rep.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", rep.status)
	}
	s := <-got
	u, err := url.Parse(r.upstreamURL)
	if err != nil {
		t.Fatal(err)
	}
	if s.method != "POST" || s.target != "/oidc/token" || s.host != u.Host || s.body != body {
		t.Errorf("upstream got %s %s Host %s body %q", s.method, s.target, s.host, s.body)
	}
	if v := s.header.Values("Authorization"); len(v) != 1 || v[0] != testCredential {
		t.Error("the credential did not replace the caller's Authorization")
	}
	wantNames := []string{"Accept", "Authorization", "Content-Length", "Content-Type", "User-Agent"}
	if names := headerNames(s.header); !slices.Equal(names, wantNames) {
		t.Errorf("upstream header names = %q, want %q", names, wantNames)
	}
	for name, vs := range s.header {
		for _, v := range vs {
			if strings.Contains(v, fit) {
				t.Errorf("the FIT reached the upstream in %s", name)
			}
		}
	}
}

// TestLogLineFields proves PLAN.md §10: one JSON line per request with the
// fixed keys; health probes at debug.
func TestLogLineFields(t *testing.T) {
	r := newRelay(t, relayOptions{upstream: func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"invalid_client"}`)
	}})
	r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil)
	r.do(t, "POST", "/oidc/token", nil, nil)
	r.do(t, "GET", "/livez", nil, nil)
	lines := r.logs.waitRequests(t, 3)
	if len(lines) != 3 {
		t.Fatalf("%d request lines, want one per request", len(lines))
	}
	cases := []struct {
		name string
		keys []string
		want map[string]string
	}{
		{"forwarded",
			[]string{"cloud_id", "duration_ms", "level", "method", "msg", "request_id", "route", "status", "time", "upstream_status"},
			map[string]string{"level": "INFO", "method": "POST", "route": "POST /oidc/token", "status": "200",
				"upstream_status": "401", "cloud_id": testSiteA}},
		{"rejected",
			[]string{"auth_reason", "duration_ms", "error", "level", "method", "msg", "request_id", "route", "status", "time"},
			map[string]string{"level": "INFO", "method": "POST", "route": "unmatched", "status": "401",
				"error": "invalid_token", "auth_reason": "authorization"}},
		{"health",
			[]string{"duration_ms", "level", "method", "msg", "request_id", "route", "status", "time"},
			map[string]string{"level": "DEBUG", "method": "GET", "route": "GET /livez", "status": "200"}},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			line := lines[i]
			if got := keys(line); !slices.Equal(got, c.keys) {
				t.Errorf("keys = %q, want %q", got, c.keys)
			}
			for k, want := range c.want {
				if got := field(line, k); got != want {
					t.Errorf("%s = %s, want %s", k, got, want)
				}
			}
			if _, ok := line["duration_ms"].(float64); !ok {
				t.Errorf("duration_ms = %v, want a number", line["duration_ms"])
			}
		})
	}
}

// TestLogsNeverContainSecrets proves PLAN.md §10 (S-7): secret markers in
// rejected paths, queries, methods, trace and other headers, Authorization
// values, bodies in both directions, unverified site IDs and the configured
// credential never reach the log, and neither does a valid FIT.
func TestLogsNeverContainSecrets(t *testing.T) {
	r := newRelay(t, relayOptions{upstream: func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream", secretMarker+"-response-header")
		_, _ = io.WriteString(w, `{"access_token":"`+secretMarker+`-response-body"}`)
	}})
	fit := validFIT(t)
	badSite := fitClaims()
	badSite["context"] = map[string]any{"cloudId": secretMarker + "-disallowed-site"}
	badSiteFIT := signFIT(t, testKeys().published, badSite)
	unsigned := fitClaims()
	unsigned["context"] = map[string]any{"cloudId": secretMarker + "-unverified-site"}
	unsignedFIT := signFIT(t, testKeys().other, unsigned)

	requests := []string{
		requestText("POST", "/"+secretMarker+"-path", bearer(fit)),
		requestText("GET", "/"+secretMarker+"-path-without-fit", nil),
		requestText("POST", "/oidc/token?code="+secretMarker+"-query", bearer(fit)),
		requestText("GET", "/livez?"+secretMarker+"-health-query", nil),
		requestText(secretMarker+"METHOD", "/oidc/token", bearer(fit)),
		requestText("GET", "/livez", http.Header{
			"X-B3-Traceid": {secretMarker + "-trace"},
			"X-B3-Spanid":  {secretMarker + "-span"},
			"X-Custom":     {secretMarker + "-header"},
			"User-Agent":   {secretMarker + "-agent"},
		}),
		requestText("POST", "/oidc/token", http.Header{"Authorization": {"Bearer " + secretMarker + "-token"}}),
		requestText("POST", "/oidc/token", http.Header{"Authorization": {"Basic " + secretMarker + "-basic"}}),
		requestText("POST", "/oidc/token", bearer(badSiteFIT)),
		requestText("POST", "/oidc/token", bearer(unsignedFIT)),
	}
	for _, req := range requests {
		method, _, _ := strings.Cut(req, " ")
		r.raw(t, method, req)
	}
	// Bodies both ways, and the credential the relay adds upstream.
	got := r.do(t, "POST", "/oidc/token", bearer(fit), strings.NewReader("code="+secretMarker+"-request-body"))
	if !strings.Contains(got.body, secretMarker) {
		t.Fatal("the upstream body did not come back, so the test proves nothing")
	}
	lines := r.logs.waitRequests(t, len(requests)+1)
	if len(lines) != len(requests)+1 {
		t.Errorf("%d request lines, want %d", len(lines), len(requests)+1)
	}
	logs := r.logs.String()
	for _, leak := range []string{secretMarker, strings.ToLower(secretMarker), fit, badSiteFIT, unsignedFIT, testCredential} {
		if strings.Contains(logs, leak) {
			t.Errorf("log contains %.40q...", leak)
		}
	}
	if strings.Contains(logs, strings.Split(fit, ".")[2]) {
		t.Error("log contains the FIT signature")
	}
}

// TestTraceIDBecomesRequestID proves the one header-derived log value of
// PLAN.md §10: exactly one x-b3-traceid of 16 or 32 hex digits, not all
// zero, is logged in lowercase; anything else is replaced by a random
// 32-digit ID and never logged.
func TestTraceIDBecomesRequestID(t *testing.T) {
	r := newRelay(t, relayOptions{})
	cases := []struct {
		name   string
		header http.Header // sent as written: names are not canonicalized
		want   string      // "" means a random ID
	}{
		{"lowercase_32", http.Header{"X-B3-Traceid": {"463ac35c9f6413ad48485a3953bb6124"}}, "463ac35c9f6413ad48485a3953bb6124"},
		{"uppercase_16", http.Header{"X-B3-Traceid": {"463AC35C9F6413AE"}}, "463ac35c9f6413ae"},
		{"mixed_case_32", http.Header{"X-B3-Traceid": {"5F3aC35c9F6413aD48485A3953Bb6124"}}, "5f3ac35c9f6413ad48485a3953bb6124"},
		{"lowercase_name", http.Header{"x-b3-traceid": {"6a3ac35c9f6413ad"}}, "6a3ac35c9f6413ad"},
		{"leading_zeros", http.Header{"X-B3-Traceid": {"0000000000000001"}}, "0000000000000001"},
		{"repeated", http.Header{"X-B3-Traceid": {"b1b2c3d4e5f60718", "b1b2c3d4e5f60718"}}, ""},
		{"repeated_distinct", http.Header{"X-B3-Traceid": {"c1b2c3d4e5f60718", "d1b2c3d4e5f60718"}}, ""},
		{"repeated_spellings", http.Header{"x-b3-traceid": {"e1b2c3d4e5f60718"}, "X-B3-TraceId": {"f1b2c3d4e5f60718"}}, ""},
		{"all_zero_16", http.Header{"X-B3-Traceid": {"0000000000000000"}}, ""},
		{"all_zero_32", http.Header{"X-B3-Traceid": {strings.Repeat("0", 32)}}, ""},
		{"length_15", http.Header{"X-B3-Traceid": {"a2b2c3d4e5f6071"}}, ""},
		{"length_17", http.Header{"X-B3-Traceid": {"a3b2c3d4e5f607181"}}, ""},
		{"length_31", http.Header{"X-B3-Traceid": {"a4b2c3d4e5f60718a4b2c3d4e5f6071"}}, ""},
		{"length_33", http.Header{"X-B3-Traceid": {"a5b2c3d4e5f60718a5b2c3d4e5f607181"}}, ""},
		{"non_hex", http.Header{"X-B3-Traceid": {"a6b2c3d4e5f6071g"}}, ""},
		{"inner_space", http.Header{"X-B3-Traceid": {"a7b2c3d4 5f60718"}}, ""},
		{"comma_joined", http.Header{"X-B3-Traceid": {"a8b2c3d4e5f60718,a8b2c3d4e5f60718"}}, ""},
		{"empty", http.Header{"X-B3-Traceid": {""}}, ""},
		{"missing", nil, ""},
	}
	random := regexp.MustCompile(`^[0-9a-f]{32}$`)
	seen := map[string]bool{}
	var rejected []string
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r.raw(t, "GET", requestText("GET", "/livez", c.header))
			id := field(r.logs.waitRequests(t, i+1)[i], "request_id")
			if c.want != "" {
				if id != c.want {
					t.Errorf("request_id = %s, want %s", id, c.want)
				}
				return
			}
			if !random.MatchString(id) || seen[id] {
				t.Errorf("request_id = %s, want a fresh random 32-digit ID", id)
			}
			seen[id] = true
			for _, vs := range c.header {
				for _, v := range vs {
					if v != "" {
						rejected = append(rejected, v, strings.ToLower(v))
					}
				}
			}
		})
	}
	logs := r.logs.String()
	for _, v := range rejected {
		if strings.Contains(logs, v) {
			t.Errorf("log contains the rejected trace ID %q", v)
		}
	}
}

// TestCloudIDOnlyAfterVerifiedFIT proves PLAN.md §10: cloud_id is logged
// only from a verified FIT, whatever the outcome after verification, and
// never from a token that failed.
func TestCloudIDOnlyAfterVerifiedFIT(t *testing.T) {
	r := newRelay(t, relayOptions{})
	siteB := fitClaims()
	siteB["context"] = map[string]any{"cloudId": testSiteB}
	expired := fitClaims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	expired["nbf"] = time.Now().Add(-time.Hour - 25*time.Second).Unix()
	cases := []struct {
		name, target string
		header       http.Header
		cloudID      string // "" means absent
		authReason   string
	}{
		{"verified", "/oidc/token", bearer(validFIT(t)), testSiteA, ""},
		{"verified_other_site", "/oidc/token", bearer(signFIT(t, testKeys().published, siteB)), testSiteB, ""},
		{"verified_then_route_refused", "/oidc/other", bearer(validFIT(t)), testSiteA, ""},
		{"bad_signature", "/oidc/token", bearer(signFIT(t, testKeys().other, fitClaims())), "", "signature"},
		{"expired", "/oidc/token", bearer(signFIT(t, testKeys().published, expired)), "", "expired"},
		{"no_token", "/oidc/token", nil, "", "authorization"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r.do(t, "POST", c.target, c.header, nil)
			line := r.logs.waitRequests(t, i+1)[i]
			if c.cloudID == "" {
				if v, ok := line["cloud_id"]; ok {
					t.Errorf("cloud_id = %v from an unverified token", v)
				}
			} else if got := field(line, "cloud_id"); got != c.cloudID {
				t.Errorf("cloud_id = %s, want %s", got, c.cloudID)
			}
			if c.authReason != "" && field(line, "auth_reason") != c.authReason {
				t.Errorf("auth_reason = %s, want %s", field(line, "auth_reason"), c.authReason)
			}
		})
	}
}

// TestLogMethods proves PLAN.md §10: methods outside the fixed log allowlist are
// logged as "other", never as sent.
func TestLogMethods(t *testing.T) {
	r := newRelay(t, relayOptions{})
	cases := []struct{ method, want string }{
		{"GET", "GET"}, {"POST", "POST"}, {"PUT", "PUT"}, {"PATCH", "PATCH"}, {"DELETE", "DELETE"},
		{"HEAD", "other"}, {"OPTIONS", "other"}, {"TRACE", "other"}, {"PROPFIND", "other"}, {"get", "other"},
	}
	for i, c := range cases {
		t.Run(c.method, func(t *testing.T) {
			r.raw(t, c.method, requestText(c.method, "/livez", nil))
			if got := field(r.logs.waitRequests(t, i+1)[i], "method"); got != c.want {
				t.Errorf("method = %s, want %s", got, c.want)
			}
		})
	}
}

// TestRouteLoggedOnlyWhenMatched proves PLAN.md §10: route is the fixed
// "unmatched" marker until the token route or a relay endpoint matches.
func TestRouteLoggedOnlyWhenMatched(t *testing.T) {
	r := newRelay(t, relayOptions{})
	fit := validFIT(t)
	cases := []struct {
		name, method, target string
		header               http.Header
		body                 string
		want                 string
	}{
		{"invalid_token", "POST", "/oidc/token", nil, "", "unmatched"},
		{"route_not_allowed", "POST", "/oidc/other", bearer(fit), "", "unmatched"},
		{"body_too_large", "POST", "/oidc/token", bearer(fit), strings.Repeat("a", server.MaxRequestBytes+1), "POST /oidc/token"},
		{"forwarded", "POST", "/oidc/token", bearer(fit), "", "POST /oidc/token"},
		{"info", "GET", "/relay/v1/info", bearer(fit), "", "GET /relay/v1/info"},
		{"readyz", "GET", "/readyz", nil, "", "GET /readyz"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r.do(t, c.method, c.target, c.header, strings.NewReader(c.body))
			if got := field(r.logs.waitRequests(t, i+1)[i], "route"); got != c.want {
				t.Errorf("route = %s, want %s", got, c.want)
			}
		})
	}
}

// TestRunGracefulShutdown proves PLAN.md R-11: after the context ends,
// /readyz turns false while an in-flight request finishes within
// RELAY_SHUTDOWN_GRACE, and Run then returns nil. A second front end on the
// same Server shows /readyz, since Run's own listener is already closed.
func TestRunGracefulShutdown(t *testing.T) {
	g := newGate()
	defer g.release()
	r := newRelay(t, relayOptions{run: true, upstream: g.handler, env: map[string]string{"RELAY_SHUTDOWN_GRACE": "5s"}})
	ts := httptest.NewServer(r.srv)
	defer ts.Close()
	probe := &relay{url: ts.URL, client: r.client}
	expectHealthy(t, probe.do(t, "GET", "/readyz", nil, nil))

	inflight := make(chan reply, 1)
	go func() {
		got, err := r.send(context.Background(), "POST", "/oidc/token", bearer(validFIT(t)), nil)
		if err != nil {
			got = reply{status: -1, body: err.Error()}
		}
		inflight <- got
	}()
	g.waitEntered(t, 1)
	r.cancelRun()
	waitUntil(t, "/readyz to report the shutdown", func() bool {
		got, err := probe.send(context.Background(), "GET", "/readyz", nil, nil)
		return err == nil && got.status == http.StatusServiceUnavailable
	})
	expectRelayError(t, probe.do(t, "GET", "/readyz", nil, nil), 503, "not_ready", false)
	select {
	case <-r.runDone:
		t.Fatal("Run returned before the in-flight request finished")
	default:
	}

	g.release()
	if got := <-inflight; got.status != http.StatusOK || got.body != upstreamBody {
		t.Errorf("in-flight request got %d %q, want the upstream answer", got.status, got.body)
	}
	if err := r.stop(t); err != nil {
		t.Errorf("Run = %v, want nil", err)
	}
}

// TestRunShutdownGraceExceeded proves PLAN.md R-11's bound: a request still
// running when RELAY_SHUTDOWN_GRACE ends has its connection closed, and Run
// reports ErrShutdownTimeout. The test waits the 100 ms grace.
func TestRunShutdownGraceExceeded(t *testing.T) {
	g := newGate()
	defer g.release()
	r := newRelay(t, relayOptions{run: true, upstream: g.handler, env: map[string]string{"RELAY_SHUTDOWN_GRACE": "100ms"}})
	inflight := make(chan error, 1)
	go func() {
		_, err := r.send(context.Background(), "POST", "/oidc/token", bearer(validFIT(t)), nil)
		inflight <- err
	}()
	g.waitEntered(t, 1)
	if err := r.stop(t); !errors.Is(err, server.ErrShutdownTimeout) {
		t.Errorf("Run = %v, want ErrShutdownTimeout", err)
	}
	if err := <-inflight; err == nil {
		t.Error("the request outlived the grace period with an answer")
	}
}

// TestRunReturnsAfterCancel proves that Run serves until its context ends
// and then returns nil without in-flight work to wait for.
func TestRunReturnsAfterCancel(t *testing.T) {
	r := newRelay(t, relayOptions{run: true})
	expectHealthy(t, r.do(t, "GET", "/livez", nil, nil))
	if err := r.stop(t); err != nil {
		t.Errorf("Run = %v, want nil", err)
	}
	if _, err := r.send(context.Background(), "GET", "/livez", nil, nil); err == nil {
		t.Error("the relay still answered after Run returned")
	}
}
