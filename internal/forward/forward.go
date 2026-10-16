// SPDX-License-Identifier: EUPL-1.2

package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Forward returns one of these errors and never the transport's own: that
// text can carry upstream bytes, addresses or TLS detail, which must not
// reach a log line or a response (PLAN.md §10). The server maps each to its
// PLAN.md §4.3 code.
var (
	// ErrUnreachable is 502 upstream_unreachable: a DNS, connection, TLS or
	// proxy failure, a reset, an answer that is not valid HTTP/1.1, one with
	// a status below 200 or one whose header is over UpstreamMaxHeaderBytes.
	ErrUnreachable = errors.New("upstream unreachable")
	// ErrTooLarge is 502 upstream_too_large: the upstream body is over
	// Options.MaxResponseBytes.
	ErrTooLarge = errors.New("upstream response too large")
	// ErrTimeout is 504 upstream_timeout: Options.Timeout, or a deadline
	// on the caller's context, ran out before the answer was complete.
	ErrTimeout = errors.New("upstream timeout")
	// ErrCanceled reports that the caller went away (PLAN.md R-3). Nobody is
	// left to answer, so it is only a log class.
	ErrCanceled = errors.New("caller canceled")
)

const (
	// UpstreamMaxHeaderBytes bounds the upstream's response header, which is
	// read before Options.MaxResponseBytes applies. Go's default is 10 MiB,
	// far beyond a token response (PLAN.md R-4).
	UpstreamMaxHeaderBytes = 32 << 10
	// MaxIdleConnsPerHost is how many idle upstream connections are kept
	// for reuse (PLAN.md §5, R-9).
	MaxIdleConnsPerHost = 10

	// The plan sets no value for these; they are net/http.DefaultTransport's.
	idleConnTimeout = 90 * time.Second
	tcpKeepAlive    = 30 * time.Second

	// PLAN.md §5 sets these (2026-10-16). Go dials on a context detached
	// from the request, so Options.Timeout ends a call but not its dial or
	// TLS handshake. The dial timeout bounds a connect that never completes;
	// the handshake timeout closes a peer that accepts and stays silent,
	// which would otherwise hold the socket for as long as it stays open.
	dialTimeout         = 30 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
)

// Options configures a Forwarder from the validated settings (PLAN.md §8).
type Options struct {
	Upstream Upstream
	// Routes are the allowed routes. Forward refuses any other, so no
	// request reaches the upstream without one (PLAN.md §4.2).
	Routes []Route
	// Credential is set on every upstream request; nil sets none, as for
	// Authentigate, whose client assertion Forge signs (PLAN.md §5).
	Credential *Credential
	// RequestHeaders and ResponseHeaders are the allowlists from
	// ParseRequestHeaders and ParseResponseHeaders.
	RequestHeaders  []string
	ResponseHeaders []string
	// RootCAs are the only CAs trusted for the upstream; nil means the
	// system bundle (RELAY_UPSTREAM_CA_FILE).
	RootCAs *x509.CertPool
	// Timeout bounds the whole upstream call, body read included
	// (RELAY_UPSTREAM_TIMEOUT, PLAN.md R-2).
	Timeout time.Duration
	// MaxResponseBytes is RELAY_MAX_RESPONSE_BYTES.
	MaxResponseBytes int64
}

// Forwarder sends allowed requests to the upstream. It does not change
// after New and is safe for concurrent use.
type Forwarder struct {
	client *http.Client
	// dialer is the one the client's transport dials with, kept so that a
	// test can check the timeouts that DialContext hides (PLAN.md §5).
	dialer           *net.Dialer
	upstream         Upstream
	routes           []Route
	credential       *Credential
	requestHeaders   []string // canonical
	responseHeaders  []string // canonical
	timeout          time.Duration
	maxResponseBytes int64
}

// New returns a Forwarder with its own upstream client (PLAN.md §5).
func New(o Options) *Forwarder {
	// HTTP/2 is off in both directions (PLAN.md §7).
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: tcpKeepAlive}
	transport := &http.Transport{
		// HTTPS_PROXY and NO_PROXY apply (PLAN.md §5).
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         dialer.DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.RootCAs},
		TLSHandshakeTimeout: tlsHandshakeTimeout,
		// Go decompresses only an answer to the Accept-Encoding it added
		// itself. Turned off, it adds none, so the body stays unchanged.
		DisableCompression:     true,
		MaxIdleConns:           MaxIdleConnsPerHost,
		MaxIdleConnsPerHost:    MaxIdleConnsPerHost,
		IdleConnTimeout:        idleConnTimeout,
		MaxResponseHeaderBytes: UpstreamMaxHeaderBytes,
		Protocols:              protocols,
	}
	f := &Forwarder{
		client: &http.Client{
			Transport: transport,
			// A 3xx is an answer for Forge to read, wrapped like any other
			// (PLAN.md D7). Following it would send the token request to a
			// destination the configuration did not name.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		dialer:           dialer,
		upstream:         o.Upstream,
		routes:           slices.Clone(o.Routes),
		requestHeaders:   canonical(o.RequestHeaders),
		responseHeaders:  canonical(o.ResponseHeaders),
		timeout:          o.Timeout,
		maxResponseBytes: o.MaxResponseBytes,
	}
	if o.Credential != nil {
		c := *o.Credential
		f.credential = &c
	}
	return f
}

// canonical copies names in canonical form, so the runtime exclusions below
// hold even for an allowlist that did not come from the Parse functions.
func canonical(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = textproto.CanonicalMIMEHeaderKey(n)
	}
	return out
}

// Match returns the route whose method and path equal method and target
// byte for byte (PLAN.md §4.2 step 3, §5). target is the request target as
// received, http.Request.RequestURI, never a cleaned or decoded path. Routes
// are ValidPath paths, so a target with a query, an absolute-form or "*"
// target, percent-encoding or a dot segment never matches, and HEAD never
// matches a GET route.
func Match(routes []Route, method, target string) (Route, bool) {
	for _, r := range routes {
		if r.Method == method && r.Path == target {
			return r, true
		}
	}
	return Route{}, false
}

// Response is a complete upstream answer. Forward reads it in full, within
// Options.MaxResponseBytes, before the relay sends anything, so an oversize
// answer still becomes a clean 502 (PLAN.md §5, R-4).
type Response struct {
	Status int         // the upstream status, for Relay-Upstream-Status (D7)
	Header http.Header // allowlisted headers only
	Body   []byte      // exactly as received
}

// Forward sends one request on route and returns the upstream's answer,
// whatever its status from 200 up. in holds the caller's headers; body is
// the request body, already bounded by the server (PLAN.md §4.2 step 4).
//
// route must be one of Options.Routes. Any other route is a programmer
// error and panics, which the recover middleware answers with 500
// internal_error (PLAN.md R-6).
//
// Forward never retries: a token exchange may have spent its one-time code
// even if the answer was lost (PLAN.md §5, R-8). Go's transport re-sends a
// request on its own only on a reused connection, and then only if nothing
// was written yet or the request is idempotent. A POST is idempotent to Go
// only with an Idempotency-Key or X-Idempotency-Key header, which the
// relay never sends.
func (f *Forwarder) Forward(ctx context.Context, route Route, in http.Header, body []byte) (*Response, error) {
	if !slices.Contains(f.routes, route) {
		panic("forward: route is not an allowed route")
	}
	// One deadline covers the request and the body read (PLAN.md R-2); the
	// caller's context ends the call early when Forge disconnects (R-3).
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, route.Method, f.upstream.URL(route.Path), bytes.NewReader(body))
	if err != nil {
		// Only an Upstream that did not come from ParseUpstream gets here.
		return nil, ErrUnreachable
	}
	req.Header = f.requestHeader(in)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, classify(ctx)
	}
	// Closing an unread body drops the connection instead of draining it.
	defer func() { _ = resp.Body.Close() }() // the answer is decided; a close error changes nothing

	// Go reads past 100 and 102-199 itself, but returns 101 and 000-099 as
	// final. A 101 the relay never asked for, or a status under 100, is not a
	// valid answer. A 101 with Upgrade headers also hands over the raw
	// connection, whose reads no deadline bounds (PLAN.md R-2, R-3); the
	// deferred Close closes it.
	if resp.StatusCode < 200 {
		return nil, ErrUnreachable
	}
	if resp.ContentLength > f.maxResponseBytes {
		return nil, ErrTooLarge
	}
	// One byte more than the limit tells an oversize body from one that
	// fits exactly; the guard keeps the sum from overflowing.
	limit := f.maxResponseBytes
	if limit < math.MaxInt64 {
		limit++
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, classify(ctx)
	}
	if int64(len(b)) > f.maxResponseBytes {
		return nil, ErrTooLarge
	}
	header := make(http.Header, len(f.responseHeaders))
	copyAllowed(header, resp.Header, f.responseHeaders, responseExcluded)
	return &Response{Status: resp.StatusCode, Header: header, Body: b}, nil
}

// requestHeader builds the upstream request header from nothing, so only
// allowlisted caller headers pass (PLAN.md §5). Go adds Host from the URL,
// Content-Length from the body and its own User-Agent unless one is passed;
// nothing adds X-Forwarded-For.
func (f *Forwarder) requestHeader(in http.Header) http.Header {
	out := make(http.Header, len(f.requestHeaders)+1)
	copyAllowed(out, in, f.requestHeaders, requestExcluded)
	// Last, and with Set: a caller's header of the same name is replaced,
	// never joined (PLAN.md §5).
	if f.credential != nil {
		out.Set(f.credential.Name, f.credential.Value.Reveal())
	}
	return out
}

// copyAllowed copies the allowlisted fields of src to dst. A name that
// src's Connection header nominates is hop-by-hop on that connection
// (RFC 9110 §7.6.1) and is dropped even when allowlisted. excluded repeats
// the mandatory exclusions of PLAN.md §5 at runtime, so an allowlist that
// skipped ParseRequestHeaders or ParseResponseHeaders still cannot pass
// them.
func copyAllowed(dst, src http.Header, allowed []string, excluded func(string) bool) {
	nominated := connectionNominated(src)
	for _, name := range allowed {
		if excluded(name) || slices.Contains(nominated, name) {
			continue
		}
		if vs := src[name]; len(vs) > 0 {
			dst[name] = slices.Clone(vs)
		}
	}
}

// connectionNominated returns the canonical names listed in h's Connection
// fields. Its size is bounded by the header limit of the side that sent it.
func connectionNominated(h http.Header) []string {
	var names []string
	for _, v := range h["Connection"] {
		for tok := range strings.SplitSeq(v, ",") {
			if tok = strings.Trim(tok, " \t"); tok != "" {
				names = append(names, textproto.CanonicalMIMEHeaderKey(tok))
			}
		}
	}
	return names
}

// classify names the reason a call failed by asking its context, never by
// reading the transport's error, whose text and types are not a contract.
func classify(ctx context.Context) error {
	switch err := ctx.Err(); {
	case errors.Is(err, context.DeadlineExceeded):
		return ErrTimeout
	case err != nil:
		return ErrCanceled
	}
	return ErrUnreachable
}

// ProxyInUse reports whether HTTPS_PROXY and NO_PROXY send requests for
// rawURL through a proxy, for the startup log (PLAN.md §5).
func ProxyInUse(rawURL string) bool {
	return proxyInUse(http.ProxyFromEnvironment, rawURL)
}

// proxyInUse is ProxyInUse with the proxy function as a test seam: Go reads
// the proxy environment once per process, so tests cannot vary it. A proxy
// setting Go cannot parse counts as in use, since the transport then fails
// every call rather than connect directly.
func proxyInUse(proxy func(*http.Request) (*url.URL, error), rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	p, err := proxy(&http.Request{URL: u})
	return err != nil || p != nil
}
