// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Signing-key schedule and limits (PLAN.md §4.5).
const (
	// JWKSRetryInitial is the delay after a failed fetch. Each further
	// failure doubles it, up to JWKSRetryMax.
	JWKSRetryInitial = time.Second
	// JWKSRetryMax caps the delay between failed fetches.
	JWKSRetryMax = time.Minute
	// JWKSUnknownRefreshInterval is the least time between two fetches
	// started by unknown key IDs, whichever IDs callers send, so made-up IDs
	// cannot turn the relay into a load generator against the JWKS host.
	JWKSUnknownRefreshInterval = time.Minute
	// FITKeyWait bounds how long a request with an unknown key ID waits for
	// the shared fetch.
	FITKeyWait = time.Second
	// MaxJWKSBytes caps the JWKS response body.
	MaxJWKSBytes = 64 << 10
	// JWKSFetchTimeout bounds one whole fetch, reading the body included.
	JWKSFetchTimeout = 10 * time.Second
	// MaxJWKSKeys is the most usable keys a snapshot holds. A larger set
	// fails the refresh instead of being truncated.
	MaxJWKSKeys = 20
	// MinRSAModulusBits is the smallest modulus trusted; smaller keys are
	// skipped.
	MinRSAModulusBits = 2048
	// MaxRSAModulusBits bounds the cost of one signature check. A larger
	// modulus counts as invalid RSA parameters and fails the refresh.
	MaxRSAModulusBits = 8192
)

const (
	// maxJWKSHeaderBytes bounds the JWKS response headers, which Go's
	// transport would otherwise accept up to 10 MiB.
	maxJWKSHeaderBytes = 32 << 10
	// The upstream client's dial and handshake timeouts (PLAN.md §5,
	// 2026-10-16): Go dials on a context detached from the fetch, so
	// JWKSFetchTimeout alone would not end a stalled connect or handshake.
	dialTimeout         = 30 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
	// crypto/rsa refuses to verify with an even e or one outside these
	// bounds, and with an even modulus. Checking them here makes such a key
	// fail the refresh loudly instead of failing every FIT later.
	minRSAExponent       = 3
	maxRSAExponent       = 1<<31 - 1
	maxRSAExponentOctets = 4
)

// jwksError is the fixed class of a failed refresh, logged as its reason.
// The fetcher and the parser return nothing else, so a failure log line
// never carries a URL, a network error or document content (PLAN.md §4.5,
// §10).
type jwksError string

func (e jwksError) Error() string { return "jwks: " + string(e) }

const (
	jwksFetchFailed  jwksError = "fetch"          // DNS, connection, TLS, timeout or read failure
	jwksBadStatus    jwksError = "status"         // any answer but 200, a redirect included
	jwksTooLarge     jwksError = "too_large"      // body over MaxJWKSBytes
	jwksMalformed    jwksError = "malformed"      // not a strict JSON object with an array of objects in keys
	jwksBadKey       jwksError = "key_parameters" // an RSA signing key with a malformed member or invalid parameters
	jwksDuplicateKID jwksError = "duplicate_kid"
	jwksTooManyKeys  jwksError = "too_many_keys"
	jwksNoUsableKeys jwksError = "no_usable_keys"
	jwksPanic        jwksError = "panic" // recovered in fetch or parse (PLAN.md §6, R-7)
)

// jwkSkip is the fixed log reason for a key the relay does not use.
type jwkSkip string

const (
	skipKeyType    jwkSkip = "kty"        // not an RSA key
	skipUse        jwkSkip = "use"        // not a signing key
	skipAlgorithm  jwkSkip = "alg"        // not for RS256
	skipUndersized jwkSkip = "undersized" // modulus under MinRSAModulusBits
)

// snapshot is one fully parsed JWKS. It is never modified once stored, so
// requests read it without a lock.
type snapshot struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

// Cache holds the current signing-key snapshot and the one worker, Run, that
// refreshes it (PLAN.md §4.5). Only Run fetches, so at most one fetch is in
// flight, and requests never start goroutines or queue key IDs.
type Cache struct {
	fetch   func(context.Context) ([]byte, error)
	refresh time.Duration
	maxAge  time.Duration
	logger  *slog.Logger

	snap    atomic.Pointer[snapshot]
	running atomic.Bool
	// wake asks Run for a fetch on behalf of unknown key IDs. With capacity
	// one, a pending request stands for every caller that wants it.
	wake chan struct{}

	mu sync.Mutex // guards inflight and lastUnknown
	// inflight is non-nil while a fetch runs or unknown key IDs have asked
	// for one, and is closed when that fetch ends; waiting callers share it.
	inflight chan struct{}
	// lastUnknown is when unknown key IDs last started a fetch.
	lastUnknown time.Time
}

// NewCache returns a cache that fetches the JWKS at jwksURL with client
// (normally JWKSClient), refreshes it every refresh interval and trusts a
// snapshot for less than maxAge after its last successful fetch
// (RELAY_JWKS_REFRESH and RELAY_JWKS_MAX_AGE, PLAN.md §8). It starts no
// goroutine; the caller runs Run.
func NewCache(jwksURL string, client *http.Client, refresh, maxAge time.Duration, logger *slog.Logger) *Cache {
	return newCache(fetchJWKS(jwksURL, client), refresh, maxAge, logger)
}

// newCache takes the fetcher as a function so tests can run the worker under
// testing/synctest, with fake time and no network (PLAN.md §13).
// refresh and maxAge are validated settings: 0 < refresh < max age
// (PLAN.md §4.5).
func newCache(fetch func(context.Context) ([]byte, error), refresh, maxAge time.Duration, logger *slog.Logger) *Cache {
	return &Cache{
		fetch:   fetch,
		refresh: refresh,
		maxAge:  maxAge,
		logger:  logger,
		wake:    make(chan struct{}, 1),
	}
}

// JWKSClient returns the HTTP client for fetching signing keys: TLS 1.2 or
// later, HTTP/1.1 only, HTTPS_PROXY and NO_PROXY honoured, the whole fetch
// bounded by JWKSFetchTimeout and its dial and TLS handshake by their own
// timeouts (PLAN.md §4.5, §5, §7). It does not follow redirects, so keys
// only ever come from the configured URL.
func JWKSClient() *http.Client {
	client, _ := jwksClient()
	return client
}

// jwksClient is JWKSClient and the dialer its transport dials with, so that
// a test can check the dial timeout, which DialContext hides.
func jwksClient() (*http.Client, *net.Dialer) {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	dialer := &net.Dialer{Timeout: dialTimeout}
	return &http.Client{
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         dialer.DialContext,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: tlsHandshakeTimeout,
			Protocols:           protocols,
			// A fetch every few hours gains nothing from an idle connection
			// held open in between.
			DisableKeepAlives: true,
			// Then the size cap applies to the bytes received, and no
			// decompressor reads the response.
			DisableCompression:     true,
			MaxResponseHeaderBytes: maxJWKSHeaderBytes,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Timeout:       JWKSFetchTimeout,
	}, dialer
}

// fetchJWKS returns the fetcher for the JWKS at jwksURL. It answers only
// with jwksError values (see there).
func fetchJWKS(jwksURL string, client *http.Client) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
		if err != nil {
			return nil, jwksFetchFailed
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, jwksFetchFailed
		}
		// The body is read in full or abandoned; a close error changes
		// neither outcome.
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			return nil, jwksBadStatus
		}
		if resp.ContentLength > MaxJWKSBytes {
			return nil, jwksTooLarge
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
		if err != nil {
			return nil, jwksFetchFailed
		}
		if len(body) > MaxJWKSBytes {
			return nil, jwksTooLarge
		}
		return body, nil
	}
}

// Run is the refresh worker and the cache's only goroutine. The caller starts
// it once at startup; it returns when ctx is done (PLAN.md §6, R-11). It
// fetches at once, retries failures with exponential backoff, refreshes a
// good snapshot every refresh interval and serves fetches that unknown key
// IDs ask for. Network failures never stop it.
func (c *Cache) Run(ctx context.Context) {
	if !c.running.CompareAndSwap(false, true) {
		panic("fit: Cache.Run called twice")
	}
	retry := JWKSRetryInitial
	next := time.NewTimer(0)
	defer next.Stop()
	// expiry fires when the last good snapshot reaches maxAge. It only logs
	// the transition: Ready and Key check the age themselves.
	expiry := time.NewTimer(c.maxAge)
	expiry.Stop()
	defer expiry.Stop()
	ready := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-expiry.C:
			ready = false
			c.logger.Warn("signing keys expired")
			continue
		case <-c.wake:
			if !c.requested() {
				continue // the fetch it asked for has already run
			}
		case <-next.C:
		}
		err := c.refreshOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.logger.Warn("jwks refresh failed", slog.String("reason", failureReason(err)))
			next.Reset(retry)
			retry = min(2*retry, JWKSRetryMax)
			continue
		}
		retry = JWKSRetryInitial
		next.Reset(c.refresh)
		// The snapshot may have reached its maximum age while this fetch ran.
		// Reset would discard that tick, so take it first and log both
		// transitions, since Ready was false in between.
		select {
		case <-expiry.C:
			ready = false
			c.logger.Warn("signing keys expired")
		default:
		}
		expiry.Reset(c.maxAge)
		if !ready {
			ready = true
			c.logger.Info("signing keys ready")
		}
	}
}

// requested reports whether unknown key IDs are waiting for a fetch. A wake
// left over from a fetch that has already served them finds none.
func (c *Cache) requested() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inflight != nil
}

// refreshOnce runs one fetch and, when it ends, releases every caller
// waiting on it.
func (c *Cache) refreshOnce(ctx context.Context) error {
	c.mu.Lock()
	if c.inflight == nil {
		c.inflight = make(chan struct{})
	}
	done := c.inflight
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.inflight = nil
		c.mu.Unlock()
		close(done)
	}()
	return c.load(ctx)
}

// load fetches and parses the JWKS and replaces the whole snapshot only if
// the document is usable, so removed keys stop being trusted and a bad
// document changes nothing (PLAN.md §4.5). A panic becomes an ordinary
// failure, so the worker keeps its backoff schedule (PLAN.md §6, R-7).
func (c *Cache) load(ctx context.Context) (err error) {
	defer func() {
		if recover() != nil {
			err = jwksPanic
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, JWKSFetchTimeout)
	defer cancel()
	raw, err := c.fetch(ctx)
	if err != nil {
		return err
	}
	keys, err := parseJWKS(raw, c.logger)
	if err != nil {
		return err
	}
	c.snap.Store(&snapshot{keys: keys, fetchedAt: time.Now()})
	c.logger.Debug("jwks refreshed", slog.Int("keys", len(keys)))
	return nil
}

// failureReason returns the fixed log value for a refresh error. An error
// of any other type, which only an injected fetcher can return, is logged
// as a fetch failure without its text.
func failureReason(err error) string {
	var je jwksError
	if errors.As(err, &je) {
		return string(je)
	}
	return string(jwksFetchFailed)
}

// Ready reports whether a usable snapshot is loaded: one exists and is
// younger than the maximum age (PLAN.md §4.1 /readyz, §4.5).
func (c *Cache) Ready() bool { return c.usable() != nil }

// Key returns the trusted key for kid. A known kid is answered from the
// current snapshot without waiting. An unknown kid waits, at most FITKeyWait
// or until ctx ends, for the fetch in flight or for one it asks Run to
// start; when no fetch is in flight and unknown IDs started one within
// JWKSUnknownRefreshInterval, it is refused at once (PLAN.md §4.5).
// ErrNotReady means no snapshot is usable.
func (c *Cache) Key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	key, err := c.lookup(kid)
	if !errors.Is(err, errKeyUnknown) {
		return key, err
	}
	done := c.awaitRefresh()
	if done == nil {
		return nil, errKeyUnknown
	}
	wait := time.NewTimer(FITKeyWait)
	defer wait.Stop()
	// The caller only stops waiting; the fetch belongs to Run and goes on.
	select {
	case <-done:
	case <-wait.C:
	case <-ctx.Done():
	}
	return c.lookup(kid)
}

// lookup finds kid in the current snapshot.
func (c *Cache) lookup(kid string) (*rsa.PublicKey, error) {
	s := c.usable()
	if s == nil {
		return nil, ErrNotReady
	}
	if key, ok := s.keys[kid]; ok {
		return key, nil
	}
	return nil, errKeyUnknown
}

// usable returns the current snapshot, or nil if there is none or it has
// reached the maximum age: an expired snapshot is never trusted
// (PLAN.md §4.5).
func (c *Cache) usable() *snapshot {
	s := c.snap.Load()
	if s == nil || time.Since(s.fetchedAt) >= c.maxAge {
		return nil
	}
	return s
}

// awaitRefresh returns a channel that is closed when the running or
// requested fetch ends, or nil during the unknown-key cooldown. Joining a
// fetch that is already running starts nothing, so it does not count against
// the cooldown.
func (c *Cache) awaitRefresh() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inflight != nil {
		return c.inflight
	}
	now := time.Now()
	if now.Sub(c.lastUnknown) < JWKSUnknownRefreshInterval {
		return nil
	}
	c.lastUnknown = now
	c.inflight = make(chan struct{})
	select {
	case c.wake <- struct{}{}:
	default: // a wake is pending already; Run finds this inflight when it takes it
	}
	return c.inflight
}

// parseJWKS returns the usable keys of a JWKS document. A key the relay does
// not use is skipped; every other rule failure fails the whole document, so
// a snapshot is never built from part of a set (PLAN.md §4.5).
func parseJWKS(raw []byte, logger *slog.Logger) (map[string]*rsa.PublicKey, error) {
	doc, err := parseObject(raw)
	if err != nil {
		return nil, jwksMalformed
	}
	elems, present, err := doc.arr("keys")
	if err != nil || !present {
		return nil, jwksMalformed
	}
	keys := make(map[string]*rsa.PublicKey)
	// kids holds every string kid, skipped keys included: if two entries
	// claim one kid, it is unclear which key the publisher meant.
	kids := make(map[string]bool)
	skipped := make(map[jwkSkip]int)
	for _, elem := range elems {
		jwk, err := asObject(elem)
		if err != nil {
			return nil, jwksMalformed
		}
		if id, ok, err := jwk.str("kid"); ok && err == nil {
			if kids[id] {
				return nil, jwksDuplicateKID
			}
			kids[id] = true
		}
		kid, key, skip, err := parseJWK(jwk)
		if err != nil {
			return nil, err
		}
		if skip != "" {
			skipped[skip]++
			continue
		}
		keys[kid] = key
		if len(keys) > MaxJWKSKeys {
			return nil, jwksTooManyKeys
		}
	}
	for _, r := range [...]jwkSkip{skipKeyType, skipUse, skipAlgorithm, skipUndersized} {
		if n := skipped[r]; n > 0 {
			logger.Info("jwks keys skipped", slog.String("reason", string(r)), slog.Int("count", n))
		}
	}
	if len(keys) == 0 {
		return nil, jwksNoUsableKeys
	}
	return keys, nil
}

// parseJWK reads one JWKS entry. It returns a skip reason for a key the
// relay does not use, undersized keys included, and an error for an RSA
// signing key with a malformed member or invalid parameters: such a key is
// meant for the relay, so it fails the refresh rather than silently
// disappearing (PLAN.md §4.5).
func parseJWK(jwk object) (kid string, key *rsa.PublicKey, skip jwkSkip, err error) {
	kty, present, err := jwk.str("kty")
	if err != nil || !present {
		return "", nil, "", jwksBadKey
	}
	if kty != "RSA" {
		return "", nil, skipKeyType, nil
	}
	use, present, err := jwk.str("use")
	if err != nil {
		return "", nil, "", jwksBadKey
	}
	if present && use != "sig" {
		return "", nil, skipUse, nil
	}
	alg, present, err := jwk.str("alg")
	if err != nil {
		return "", nil, "", jwksBadKey
	}
	if present && alg != "RS256" {
		return "", nil, skipAlgorithm, nil
	}
	kid, _, err = jwk.str("kid")
	if err != nil || kid == "" {
		return "", nil, "", jwksBadKey
	}
	nb, ok := jwkParam(jwk, "n")
	if !ok {
		return "", nil, "", jwksBadKey
	}
	n := new(big.Int).SetBytes(nb)
	// An undersized key can never verify a FIT, so it is skipped before e and
	// the modulus's parity and maximum are judged: only an otherwise eligible
	// key fails the refresh (PLAN.md §4.5). A malformed n fails, since its
	// size is unknown.
	if n.BitLen() < MinRSAModulusBits {
		return "", nil, skipUndersized, nil
	}
	eb, ok := jwkParam(jwk, "e")
	if !ok || len(eb) > maxRSAExponentOctets {
		return "", nil, "", jwksBadKey
	}
	var e uint32
	for _, b := range eb {
		e = e<<8 | uint32(b)
	}
	if e < minRSAExponent || e > maxRSAExponent || e%2 == 0 {
		return "", nil, "", jwksBadKey
	}
	if n.Bit(0) == 0 || n.BitLen() > MaxRSAModulusBits {
		return "", nil, "", jwksBadKey
	}
	return kid, &rsa.PublicKey{N: n, E: int(e)}, "", nil
}

// jwkParam decodes the RSA integer member name (RFC 7518 §6.3.1): strict
// base64url of an unsigned big-endian value without leading zero octets.
// RFC 7518 wants it unpadded, but Atlassian's live JWKS pads n with "="
// (Phase 0 dry run, 2026-10-16), so exactly the padding that completes the
// last quantum is also accepted; any other "=" fails (PLAN.md §4.5). FIT
// parts stay strictly unpadded. The text before the padding passes the same
// alphabet check as FIT parts, since Go's decoders skip CR and LF.
func jwkParam(jwk object, name string) ([]byte, bool) {
	s, _, err := jwk.str(name)
	if err != nil {
		return nil, false
	}
	data := strings.TrimRight(s, "=")
	if !base64URL(data) {
		return nil, false
	}
	var b []byte
	if data == s {
		b, err = decodePart(data)
	} else {
		// The padded decoder refuses a wrong "=" count, including one on
		// text that needs none, and in strict mode non-canonical bits.
		b, err = base64.URLEncoding.Strict().DecodeString(s)
	}
	if err != nil || len(b) == 0 || b[0] == 0 {
		return nil, false
	}
	return b, true
}
