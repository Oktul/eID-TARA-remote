// SPDX-License-Identifier: EUPL-1.2

package forward

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
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
	// MaxResponseBytes.
	ErrTooLarge = errors.New("upstream response too large")
	// ErrTimeout is 504 upstream_timeout: Options.Timeout, or a deadline
	// on the caller's context, ran out before the answer was complete.
	ErrTimeout = errors.New("upstream timeout")
	// ErrCanceled reports that the caller went away (PLAN.md R-3). Nobody is
	// left to answer, so it is only a log class.
	ErrCanceled = errors.New("caller canceled")
)

const (
	// TokenPath is TARA's token endpoint, the only forwarded path
	// (PLAN.md §5, D11).
	TokenPath = "/oidc/token"
	// TokenRoute is its fixed method and path, safe for logs and the info
	// endpoint.
	TokenRoute = "POST " + TokenPath
	// MaxResponseBytes is the upstream body limit, fixed for token calls,
	// whose answers are a few KB (PLAN.md D8, owner, 2026-10-16).
	MaxResponseBytes = 64 << 10
	// UpstreamMaxHeaderBytes bounds the upstream's response header, which is
	// read before MaxResponseBytes applies. Go's default is 10 MiB,
	// far beyond a token response (PLAN.md R-4).
	UpstreamMaxHeaderBytes = 32 << 10
	// MaxIdleConnsPerHost is how many idle upstream connections are kept
	// for reuse (PLAN.md §5, R-9).
	MaxIdleConnsPerHost = 10

	// The plan sets no value for these; they are net/http.DefaultTransport's.
	idleConnTimeout = 90 * time.Second
	tcpKeepAlive    = 30 * time.Second

	// PLAN.md §5 (2026-10-16): Go dials on a context detached from the
	// request, so Options.Timeout alone would not end a connect that never
	// completes or a peer that accepts and then stays silent.
	dialTimeout         = 30 * time.Second
	tlsHandshakeTimeout = 10 * time.Second
)

// Options configures a Forwarder from the validated settings (PLAN.md §8).
type Options struct {
	Upstream Upstream
	// Credential is set last on every upstream request; nil sets none
	// (PLAN.md §5).
	Credential *Credential
	// RootCAs are the only CAs trusted for the upstream; nil means the
	// system bundle (RELAY_UPSTREAM_CA_FILE).
	RootCAs *x509.CertPool
	// Timeout bounds the whole upstream call, body read included
	// (RELAY_UPSTREAM_TIMEOUT, PLAN.md R-2).
	Timeout time.Duration
}

// Forwarder sends allowed requests to the upstream. It does not change
// after New and is safe for concurrent use.
type Forwarder struct {
	client *http.Client
	// dialer is the one the client's transport dials with, kept so that a
	// test can check the timeouts that DialContext hides (PLAN.md §5).
	dialer     *net.Dialer
	upstream   Upstream
	credential *Credential
	timeout    time.Duration
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
	return &Forwarder{
		client: &http.Client{
			Transport: transport,
			// A 3xx is an answer for Forge to read, wrapped like any other
			// (PLAN.md D7). Following it would send the token request to a
			// destination the configuration did not name.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		dialer:     dialer,
		upstream:   o.Upstream,
		credential: o.Credential,
		timeout:    o.Timeout,
	}
}

// Response is a complete upstream answer. Forward reads it in full, within
// MaxResponseBytes, before the relay sends anything, so an oversize
// answer still becomes a clean 502 (PLAN.md §5, R-4).
type Response struct {
	Status int         // the upstream status, for Relay-Upstream-Status (D7)
	Header http.Header // allowlisted headers only
	Body   []byte      // exactly as received
}

// Forward sends one POST to TARA's token endpoint and returns its answer,
// whatever its status from 200 up. in holds the caller's headers; body is
// the request body, already bounded by the server (PLAN.md §4.2 step 4).
//
// Forward never retries: a token exchange may have spent its one-time code
// even if the answer was lost (PLAN.md §5, R-8). Go's transport re-sends a
// request on its own only on a reused connection, and then only if nothing
// was written yet or the request is idempotent. A POST is idempotent to Go
// only with an Idempotency-Key or X-Idempotency-Key header, which the
// relay never sends, and a POST with a body has no GetBody (below), so Go
// never re-sends it.
func (f *Forwarder) Forward(ctx context.Context, in http.Header, body []byte) (*Response, error) {
	// One deadline covers the request and the body read (PLAN.md R-2); the
	// caller's context ends the call early when Forge disconnects (R-3).
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.upstream.URL(), bytes.NewReader(body))
	if err != nil {
		// Only an Upstream that did not come from ParseUpstream gets here.
		return nil, ErrUnreachable
	}
	// NewRequest adds GetBody for bytes.Reader. PLAN.md §5 forbids a replay
	// callback for token POSTs; without one, Go also skips its resend of a
	// POST with a body when nothing was written, so a stale idle connection
	// costs a 502.
	req.GetBody = nil
	req.Header = f.requestHeader(in)

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, classify(ctx)
	}
	// Closing an unread body hands the relay nothing more; Go may drain a
	// short rest to reuse the connection, or drop it.
	defer func() { _ = resp.Body.Close() }() // the answer is decided; a close error changes nothing

	// Disabling HTTP/2 controls negotiation, but Go's HTTP/1 parser still
	// accepts other version numbers. PLAN.md §4.3 and §5 require HTTP/1.1.
	if resp.ProtoMajor != 1 || resp.ProtoMinor != 1 {
		return nil, ErrUnreachable
	}
	// Go reads past 100 and 102-199 itself, but returns 101 and 000-099 as
	// final. A 101 the relay never asked for, or a status under 100, is not a
	// valid answer. A 101 with Upgrade headers also hands over the raw
	// connection, whose reads no deadline bounds (PLAN.md R-2, R-3); the
	// deferred Close closes it.
	if resp.StatusCode < 200 {
		return nil, ErrUnreachable
	}
	if resp.ContentLength > MaxResponseBytes {
		return nil, ErrTooLarge
	}
	// One byte more than the limit tells an oversize body from one that
	// fits exactly.
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, classify(ctx)
	}
	if len(b) > MaxResponseBytes {
		return nil, ErrTooLarge
	}
	header := make(http.Header, 3)
	copyAllowed(header, resp.Header, []string{"Content-Type", "Cache-Control", "Pragma"})
	return &Response{Status: resp.StatusCode, Header: header, Body: b}, nil
}

// requestHeader builds the upstream request header from nothing, so only
// Content-Type and Accept pass from the caller: a token call needs no other,
// so the allowlist is fixed (PLAN.md §5, owner, 2026-10-16). Go adds Host
// from the URL, Content-Length from the body and its own User-Agent unless
// one is passed; nothing adds X-Forwarded-For.
func (f *Forwarder) requestHeader(in http.Header) http.Header {
	out := make(http.Header, 3)
	copyAllowed(out, in, []string{"Content-Type", "Accept"})
	// Last, and with Set: a caller's header of the same name is replaced,
	// never joined (PLAN.md §5).
	if f.credential != nil {
		out.Set(f.credential.Name, f.credential.Value.Reveal())
	}
	return out
}

// copyAllowed copies the allowlisted fields of src to dst. A name that
// src's Connection header nominates is hop-by-hop on that connection
// (RFC 9110 §7.6.1) and is dropped even when allowlisted (PLAN.md §5).
func copyAllowed(dst, src http.Header, allowed []string) {
	nominated := connectionNominated(src)
	for _, name := range allowed {
		if slices.Contains(nominated, name) {
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
