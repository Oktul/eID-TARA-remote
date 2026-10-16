// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"maps"
	"math/bits"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client bounds. requestTimeout is longer than the relay's default
// WriteTimeout (upstream timeout + 5 s, PLAN.md §6 R-1), so a timeout here
// means the relay or its proxy missed its own bound.
const (
	requestTimeout    = 30 * time.Second
	dialTimeout       = 5 * time.Second
	clientIdleTimeout = 90 * time.Second
	writeTimeout      = 5 * time.Second // one byte of a slow request
	// probeTimeout is the Kubernetes default probe timeout: a slower answer
	// is what would restart the relay.
	probeTimeout  = time.Second
	probeInterval = 500 * time.Millisecond
	// maxSmallBody bounds relay error and health bodies, which are a few
	// bytes (PLAN.md §4.3).
	maxSmallBody = 4 << 10
	maxCodeBytes = 32
	// relayUnknownRefresh is the relay's JWKSUnknownRefreshInterval: unknown
	// key IDs start at most one JWKS fetch per interval (PLAN.md §4.5).
	relayUnknownRefresh = time.Minute
)

// Outcomes the checks refer to. The relay's are protocol literals (PLAN.md
// §4.3); the connection outcomes describe how a raw connection ended.
const (
	outcomeForwarded = "200 upstream 200"
	outcomeTooBusy   = "503 too_busy"
	outcomeInvalid   = "401 invalid_token"
	outcomeClosed    = "closed by peer"
	outcomeOpen      = "open at end"
	outcomeAnswered  = "answered"
	outcomeMalformed = "malformed"
)

var errTooLarge = errors.New("response over the read limit")

// scenario is one load pattern from PLAN.md §13 and the outcomes that pass it.
type scenario struct {
	name   string
	unit   string // what the count means
	timing string // what the percentiles measure
	// run drives the load until ctx ends; abort also cancels work in flight.
	run       func(ctx, abort context.Context, e *env, t *tally)
	ok        func(outcome string) bool
	required  string // an outcome that must occur at least once, if set
	upstream  bool   // requests may reach the upstream
	overCap   bool   // the load must exceed the relay's concurrency cap
	jwksLimit bool   // JWKS fetches must respect the unknown-key limit
}

func allScenarios() []scenario {
	return []scenario{
		{
			name: "full", unit: "requests", timing: "latency", run: full,
			ok:       oneOf(outcomeForwarded, outcomeTooBusy),
			required: outcomeForwarded, upstream: true, overCap: true,
		},
		{
			name: "invalid", unit: "requests", timing: "latency", run: invalidSignatures,
			// The concurrency slot is taken before the FIT check (PLAN.md
			// §4.2), so a flood may also see too_busy.
			ok:       oneOf(outcomeInvalid, outcomeTooBusy),
			required: outcomeInvalid,
		},
		{
			name: "unknown-kid", unit: "requests", timing: "latency", run: unknownKeys,
			ok:       oneOf(outcomeInvalid, outcomeTooBusy),
			required: outcomeInvalid, jwksLimit: true,
		},
		{
			name: "slow-headers", unit: "connections", timing: "time to close", run: slowHeaders,
			ok: func(o string) bool { return o != outcomeOpen },
		},
		{
			// The relay's IdleTimeout (60 s, PLAN.md §6 R-1) may outlast
			// -duration, so a connection still open at the end passes.
			name: "idle", unit: "connections", timing: "time to close", run: idle,
			ok: oneOf(outcomeClosed, outcomeOpen),
		},
	}
}

func oneOf(outcomes ...string) func(string) bool {
	return func(o string) bool { return slices.Contains(outcomes, o) }
}

// target is the relay, or the reverse proxy in front of it.
type target struct {
	base       string // scheme://host[:port], for net/http
	host       string // the Host header value
	addr       string // host:port, for raw connections
	tls        bool
	serverName string
}

// dialFunc opens one raw connection to the relay; tests replace it with
// net.Pipe.
type dialFunc func(ctx context.Context) (net.Conn, error)

// env is what the scenarios share.
type env struct {
	relay        target
	dial         dialFunc
	probe        *http.Client
	probeBase    string
	fits         *minter
	fixture      *fixture
	workers      int
	conns        int
	slowInterval time.Duration
}

// result is one scenario's report.
type result struct {
	name, unit, timing string
	elapsed            time.Duration
	count              int64
	outcomes, errors   map[string]int64
	timed              int64 // how many durations the percentiles cover
	p50, p95, p99      time.Duration
	probe              probeTally
	upstreamCalls      int64
	jwksFetches        int64
	failures           []string
}

// runScenario runs s for d while probing the relay's health. The probe
// goroutine it starts exits when the scenario has finished.
func runScenario(ctx context.Context, e *env, s scenario, d time.Duration) result {
	upstream0, jwks0 := e.fixture.upstreamCalls.Load(), e.fixture.jwksFetches.Load()
	probeCtx, stopProbe := context.WithCancel(ctx)
	probed := make(chan probeTally, 1)
	go func() { probed <- probe(probeCtx, e.probe, e.probeBase) }()

	runCtx, cancel := context.WithTimeout(ctx, d)
	t := newTally()
	start := time.Now()
	s.run(runCtx, ctx, e, t)
	elapsed := time.Since(start)
	cancel()
	stopProbe()

	r := t.result()
	r.name, r.unit, r.timing, r.elapsed = s.name, s.unit, s.timing, elapsed
	r.probe = <-probed
	r.upstreamCalls = e.fixture.upstreamCalls.Load() - upstream0
	r.jwksFetches = e.fixture.jwksFetches.Load() - jwks0
	r.failures = verdict(s, r)
	return r
}

// verdict lists the checks a scenario failed. They are the acceptance
// properties of PLAN.md §13: overload never fails a health probe (§6), every
// answer is one the protocol allows (§4.3), a rejected request never reaches
// the upstream (§4.2) and unknown key IDs start at most one JWKS fetch per
// interval (§4.5).
func verdict(s scenario, r result) []string {
	var f []string
	var unexpected int64
	for o, n := range r.outcomes {
		if !s.ok(o) {
			unexpected += n
		}
	}
	if unexpected > 0 {
		f = append(f, fmt.Sprintf("%d unexpected outcomes", unexpected))
	}
	if s.required != "" && r.outcomes[s.required] == 0 {
		f = append(f, "no "+s.required+" answer")
	}
	if s.overCap && r.outcomes[outcomeTooBusy] == 0 {
		f = append(f, "the concurrency cap was never reached; raise -c or -upstream-delay")
	}
	if n := sum(r.errors); n > 0 {
		f = append(f, fmt.Sprintf("%d errors", n))
	}
	if n := sum(r.probe.failures); n > 0 {
		f = append(f, fmt.Sprintf("%d failed health probes", n))
	}
	if !s.upstream && r.upstreamCalls > 0 {
		f = append(f, fmt.Sprintf("%d requests reached the upstream", r.upstreamCalls))
	}
	if limit := int64(r.elapsed/relayUnknownRefresh) + 1; s.jwksLimit && r.jwksFetches > limit {
		f = append(f, fmt.Sprintf("%d JWKS fetches, more than %d", r.jwksFetches, limit))
	}
	return f
}

func sum(m map[string]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}

func full(ctx, abort context.Context, e *env, t *tally) {
	requests(ctx, abort, e, t, e.fixture.requestBody, func(int, int) (string, error) {
		s, err := e.fits.get()
		return s.valid, err
	})
}

func invalidSignatures(ctx, abort context.Context, e *env, t *tally) {
	requests(ctx, abort, e, t, nil, func(int, int) (string, error) {
		s, err := e.fits.get()
		return s.badSignature, err
	})
}

func unknownKeys(ctx, abort context.Context, e *env, t *tally) {
	requests(ctx, abort, e, t, nil, func(worker, seq int) (string, error) {
		s, err := e.fits.get()
		if err != nil {
			return "", err
		}
		return unknownKeyFIT(s, "unknown-"+strconv.Itoa(worker)+"-"+strconv.Itoa(seq))
	})
}

// requests runs e.workers workers that send token requests back to back
// until ctx ends. A request in flight at that moment still completes, bounded
// by requestTimeout, so the last answers count instead of showing up as
// errors; abort cancels them.
func requests(ctx, abort context.Context, e *env, t *tally, body []byte, token func(worker, seq int) (string, error)) {
	c := loadClient(e.workers)
	defer c.CloseIdleConnections()
	limit := readLimit(e.fixture)
	var wg sync.WaitGroup
	for w := range e.workers {
		wg.Go(func() {
			for seq := 0; ctx.Err() == nil; seq++ {
				tok, err := token(w, seq)
				if err != nil {
					t.fail("mint")
					return
				}
				send(abort, c, e, t, tok, body, limit)
			}
		})
	}
	wg.Wait()
}

// preflight sends one valid request before any load. The key and CA are new
// for every run, so a relay left running from an earlier run, or started
// with other settings, would fail every scenario for that reason alone.
func preflight(ctx context.Context, e *env) error {
	s, err := e.fits.get()
	if err != nil {
		return err
	}
	c := loadClient(1)
	defer c.CloseIdleConnections()
	t := newTally()
	send(ctx, c, e, t, s.valid, e.fixture.requestBody, readLimit(e.fixture))
	r := t.result()
	switch {
	case ctx.Err() != nil:
		return errInterrupted
	case r.outcomes[outcomeForwarded] == 1 && len(r.errors) == 0:
		return nil
	}
	got := slices.Sorted(maps.Keys(r.outcomes))
	got = append(got, slices.Sorted(maps.Keys(r.errors))...)
	return fmt.Errorf("a valid request got %s, not %s; restart the relay with the settings above",
		strings.Join(got, ", "), outcomeForwarded)
}

// readLimit bounds an answer: the fake upstream's body, or a relay error.
func readLimit(f *fixture) int64 { return int64(max(len(f.responseBody), maxSmallBody)) }

// send makes one request and records its outcome. Only a forwarded answer
// carries the upstream body, which must arrive unchanged (PLAN.md D7).
func send(ctx context.Context, c *http.Client, e *env, t *tally, token string, body []byte, limit int64) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.relay.base+tokenPath, bytes.NewReader(body))
	if err != nil {
		t.fail("request")
		return
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	start := time.Now()
	outcome, got, err := exchange(c, req, limit)
	elapsed := time.Since(start)
	switch {
	case err != nil && ctx.Err() != nil:
		// Interrupted by the operator; not something the relay did.
	case err != nil:
		t.fail(errorClass(err))
	default:
		t.addTimed(outcome, elapsed)
		if outcome == outcomeForwarded && !bytes.Equal(got, e.fixture.responseBody) {
			t.flag("body_mismatch")
		}
	}
}

// exchange sends req and reads its answer up to limit bytes.
func exchange(c *http.Client, req *http.Request, limit int64) (outcome string, body []byte, err error) {
	resp, err := c.Do(req)
	if err != nil {
		return "", nil, err
	}
	// The outcome comes from the read below; a close error cannot change it.
	defer func() { _ = resp.Body.Close() }()
	body, err = io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", nil, err
	}
	if int64(len(body)) > limit {
		return "", nil, errTooLarge
	}
	return outcomeKey(resp), body, nil
}

// outcomeKey classifies an answer by its status and the relay's own headers
// (PLAN.md §4.3).
func outcomeKey(resp *http.Response) string {
	status := strconv.Itoa(resp.StatusCode)
	if v := resp.Header.Values("Relay-Error"); len(v) > 0 {
		return status + " " + code(v)
	}
	if v := resp.Header.Values("Relay-Upstream-Status"); len(v) > 0 {
		return status + " upstream " + code(v)
	}
	return status
}

// code reduces a relay header to the alphabet of its fixed codes, so a proxy
// or a broken relay cannot put arbitrary text into the report.
func code(v []string) string {
	if len(v) != 1 || v[0] == "" || len(v[0]) > maxCodeBytes {
		return outcomeMalformed
	}
	for _, c := range []byte(v[0]) {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return outcomeMalformed
		}
	}
	return v[0]
}

// errorClass reduces a transport error to a fixed class for the report.
func errorClass(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, errTooLarge):
		return "response_too_large"
	case errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	default:
		return "connection"
	}
}

// loadClient keeps one connection per worker alive between requests, like a
// busy reverse proxy in front of the relay, and sends exactly what a scenario
// builds: no compression (the forwarded body is compared byte for byte,
// PLAN.md D7), no redirects (the relay must not send one, §4.2), no proxy
// from the environment, and HTTP/1.1 only like the relay's server (§7).
func loadClient(conns int) *http.Client {
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: dialTimeout}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: dialTimeout,
		DisableCompression:  true,
		MaxIdleConns:        conns,
		MaxIdleConnsPerHost: conns,
		IdleConnTimeout:     clientIdleTimeout,
		Protocols:           http1(),
	}
	return &http.Client{Transport: tr, Timeout: requestTimeout, CheckRedirect: noRedirect}
}

// probeClient opens a fresh connection for every probe, as kubelet and a
// health-check process do, so a probe also shows that the relay still
// accepts connections under load.
func probeClient() *http.Client {
	tr := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: probeTimeout}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: probeTimeout,
		DisableKeepAlives:   true,
		Protocols:           http1(),
	}
	return &http.Client{Transport: tr, Timeout: probeTimeout, CheckRedirect: noRedirect}
}

func http1() *http.Protocols {
	p := new(http.Protocols)
	p.SetHTTP1(true)
	return p
}

func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// probeTally is what the health probe saw during one scenario.
type probeTally struct {
	sent     int64
	failures map[string]int64
	slowest  time.Duration
}

// probe checks /livez and /readyz every probeInterval until ctx ends. Overload
// must fail neither: a failed liveness probe restarts the relay (PLAN.md §6,
// §13). A round that has started completes, bounded by probeTimeout, so a
// failure at the very end of a scenario still counts.
func probe(ctx context.Context, c *http.Client, base string) probeTally {
	p := probeTally{failures: map[string]int64{}}
	tick := time.NewTicker(probeInterval)
	defer tick.Stop()
	for {
		for _, path := range []string{"/livez", "/readyz"} {
			start := time.Now()
			class := healthCheck(context.WithoutCancel(ctx), c, base+path)
			p.sent++
			p.slowest = max(p.slowest, time.Since(start))
			if class != "" {
				p.failures[path+" "+class]++
			}
		}
		select {
		case <-ctx.Done():
			return p
		case <-tick.C:
		}
	}
}

// waitReady polls /readyz until it answers 200. Until the relay has loaded
// the fixture's JWKS, every protected request answers 503 not_ready
// (PLAN.md §4.5), so no scenario would mean anything.
func waitReady(ctx context.Context, c *http.Client, base string) error {
	tick := time.NewTicker(probeInterval)
	defer tick.Stop()
	for {
		if healthCheck(ctx, c, base+"/readyz") == "" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// healthCheck returns "" when url answers 200, and a fixed failure class
// otherwise.
func healthCheck(ctx context.Context, c *http.Client, url string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "request"
	}
	resp, err := c.Do(req)
	if err != nil {
		return errorClass(err)
	}
	// The class comes from the read below; a close error cannot change it.
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxSmallBody)); err != nil {
		return errorClass(err)
	}
	if resp.StatusCode != http.StatusOK {
		return "status " + strconv.Itoa(resp.StatusCode)
	}
	return ""
}

// relayDialer dials the relay directly, with TLS when its URL is https.
func relayDialer(relay target) dialFunc {
	d := &net.Dialer{Timeout: dialTimeout}
	return func(ctx context.Context) (net.Conn, error) {
		conn, err := d.DialContext(ctx, "tcp", relay.addr)
		if err != nil || !relay.tls {
			return conn, err
		}
		tc := tls.Client(conn, &tls.Config{
			ServerName: relay.serverName,
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"http/1.1"},
		})
		hctx, cancel := context.WithTimeout(ctx, dialTimeout)
		defer cancel()
		if err := tc.HandshakeContext(hctx); err != nil {
			_ = conn.Close() // the handshake error is the one to report
			return nil, err
		}
		return tc, nil
	}
}

func slowHeaders(ctx, _ context.Context, e *env, t *tally) {
	connections(ctx, e, t, func(conn net.Conn) { slowConn(ctx, conn, e.relay.host, e.slowInterval, t) })
}

func idle(ctx, _ context.Context, e *env, t *tally) {
	connections(ctx, e, t, func(conn net.Conn) { idleConn(ctx, conn, e.relay.host, t) })
}

// connections opens e.conns connections at once and runs one on each. one
// returns before ctx has ended only when its connection has.
func connections(ctx context.Context, e *env, t *tally, one func(net.Conn)) {
	var wg sync.WaitGroup
	for range e.conns {
		wg.Go(func() {
			conn, err := e.dial(ctx)
			if err != nil {
				if ctx.Err() == nil {
					t.fail(errorClass(err))
				}
				return
			}
			// one records the outcome and may have closed conn already.
			defer func() { _ = conn.Close() }()
			one(conn)
		})
	}
	wg.Wait()
}

// slowConn writes a request one byte per interval and never finishes its
// headers, so only the peer's header timeout can end it: the relay's
// ReadHeaderTimeout or the proxy's ProxyReadHeaderTimeout (PLAN.md §6).
func slowConn(ctx context.Context, conn net.Conn, host string, interval time.Duration, t *tally) {
	start := time.Now()
	peer := watchPeer(conn)
	defer func() {
		_ = conn.Close() // ends watchPeer's read; the outcome is recorded
		<-peer
	}()
	request := "POST " + tokenPath + " HTTP/1.1\r\nHost: " + host + "\r\nX-Load-Slow: "
	tick := time.NewTicker(interval)
	defer tick.Stop()
	ticks := tick.C
	for i := 0; ; i++ {
		if ticks != nil && writeSlowByte(conn, request, i) != nil {
			ticks = nil // the peer stopped reading; wait for it to finish closing
		}
		select {
		case o := <-peer:
			t.addTimed(o, time.Since(start))
			return
		case <-ctx.Done():
			t.add(outcomeOpen)
			return
		case <-ticks:
		}
	}
}

// writeSlowByte writes byte i of request, and after it a header value that
// grows until the peer gives up.
func writeSlowByte(conn net.Conn, request string, i int) error {
	b := byte('a')
	if i < len(request) {
		b = request[i]
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	_, err := conn.Write([]byte{b})
	return err
}

// idleConn sends one complete health request and then leaves the connection
// idle in keep-alive, so only the peer's idle timeout ends it (the relay's
// IdleTimeout, PLAN.md §6 R-1). A health request needs no token and never
// reaches the upstream (§4.2), so the scenario measures connections alone.
func idleConn(ctx context.Context, conn net.Conn, host string, t *tally) {
	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		t.fail(errorClass(err))
		return
	}
	if _, err := io.WriteString(conn, "GET /livez HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.fail(errorClass(err))
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.fail(errorClass(err))
		return
	}
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxSmallBody))
	// Close reads what is left of the body, so its error also means the
	// connection cannot go on to idle.
	if cerr := resp.Body.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		t.fail(errorClass(err))
		return
	case outcomeKey(resp) != "200":
		t.add("first request " + outcomeKey(resp))
		return
	case resp.Close:
		t.add("first request not kept alive")
		return
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.fail(errorClass(err))
		return
	}
	idleSince := time.Now()
	peer := watchPeer(conn)
	defer func() {
		_ = conn.Close() // ends watchPeer's read; the outcome is recorded
		<-peer
	}()
	select {
	case o := <-peer:
		t.addTimed(o, time.Since(idleSince))
	case <-ctx.Done():
		t.add(outcomeOpen)
	}
}

// watchPeer reports how the peer ended conn. Its goroutine exits once conn
// is closed by either side; the channel then yields one outcome and closes,
// so a second receive never blocks.
func watchPeer(conn net.Conn) <-chan string {
	ch := make(chan string, 1)
	go func() {
		defer close(ch)
		ch <- readOutcome(conn)
	}()
	return ch
}

// statusPrefix is "HTTP/1.1 200": enough of an answer to read its status.
const statusPrefix = len("HTTP/1.1 200")

// readOutcome blocks until the peer answers or the connection ends.
func readOutcome(conn net.Conn) string {
	var buf [statusPrefix]byte
	// Every error means the connection ended; n tells whether the peer
	// answered first.
	n, _ := io.ReadFull(conn, buf[:])
	switch {
	case n == 0:
		return outcomeClosed
	case n < statusPrefix || !bytes.HasPrefix(buf[:], []byte("HTTP/1.")) || buf[8] != ' ':
		return outcomeAnswered + " " + outcomeMalformed
	}
	status := buf[9:]
	for _, c := range status {
		if c < '0' || c > '9' {
			return outcomeAnswered + " " + outcomeMalformed
		}
	}
	return outcomeAnswered + " " + string(status)
}

// tally collects one scenario's results. Workers share it under mu; each
// request or connection records once, so the lock is not what limits the rate.
type tally struct {
	mu       sync.Mutex // guards every field below
	count    int64
	outcomes map[string]int64
	errors   map[string]int64
	latency  *histogram
}

func newTally() *tally {
	return &tally{outcomes: map[string]int64{}, errors: map[string]int64{}, latency: newHistogram()}
}

// add counts an outcome without a duration.
func (t *tally) add(outcome string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count++
	t.outcomes[outcome]++
}

// addTimed counts an outcome and its duration.
func (t *tally) addTimed(outcome string, d time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count++
	t.outcomes[outcome]++
	t.latency.record(d)
}

// fail counts an attempt that ended in an error instead of an outcome.
func (t *tally) fail(class string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count++
	t.errors[class]++
}

// flag adds an error to an attempt already counted.
func (t *tally) flag(class string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.errors[class]++
}

func (t *tally) result() result {
	t.mu.Lock()
	defer t.mu.Unlock()
	return result{
		count:    t.count,
		outcomes: maps.Clone(t.outcomes),
		errors:   maps.Clone(t.errors),
		timed:    t.latency.total,
		p50:      t.latency.percentile(50),
		p95:      t.latency.percentile(95),
		p99:      t.latency.percentile(99),
	}
}

// histogram is a log-linear latency histogram: its memory is fixed for any
// -duration, and each bucket spans at most 1/histogramSub of its values,
// which is precise enough for p50, p95 and p99.
type histogram struct {
	counts []int64
	total  int64
}

const (
	histogramSub = 16
	histogramMax = time.Hour // longer durations are recorded as this
)

func newHistogram() *histogram {
	return &histogram{counts: make([]int64, histogramIndex(uint64(histogramMax/time.Microsecond))+1)}
}

func (h *histogram) record(d time.Duration) {
	d = min(max(d, 0), histogramMax)
	h.counts[histogramIndex(uint64(d/time.Microsecond))]++
	h.total++
}

// percentile returns the upper bound of the bucket holding the p-th
// percentile, or 0 when nothing was recorded.
func (h *histogram) percentile(p int64) time.Duration {
	if h.total == 0 {
		return 0
	}
	rank := max((h.total*p+99)/100, 1)
	var seen int64
	for i, n := range h.counts {
		seen += n
		if seen >= rank {
			return histogramUpper(i)
		}
	}
	return histogramMax
}

// histogramIndex maps microseconds to a bucket: exact below histogramSub,
// then histogramSub buckets per power of two.
func histogramIndex(us uint64) int {
	if us < histogramSub {
		return int(us)
	}
	shift := bits.Len64(us) - bits.Len64(histogramSub)
	return histogramSub*shift + int(us>>shift)
}

// histogramUpper returns the largest duration in bucket i.
func histogramUpper(i int) time.Duration {
	if i < histogramSub {
		return time.Duration(i) * time.Microsecond
	}
	shift := i/histogramSub - 1
	m := uint64(i%histogramSub + histogramSub)
	return time.Duration((m+1)<<shift-1) * time.Microsecond
}
