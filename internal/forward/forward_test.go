// SPDX-License-Identifier: EUPL-1.2

package forward

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

const (
	tokenBody  = "grant_type=authorization_code&code=synthetic-code-1"
	tokenBody2 = "grant_type=authorization_code&code=synthetic-code-2"
	// secretMarker stands for a FIT, a credential or upstream error text. It
	// must never reach the upstream unless allowlisted, nor any error.
	secretMarker = "SECRET-MARKER-7f3a"
	// testTimeout is generous: loopback tests never rely on it to finish.
	testTimeout = time.Minute
	// okResponse is a complete keep-alive answer for raw upstreams.
	okResponse = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
)

// testCertificate is the loopback upstream's certificate, generated once per
// test run so no key is committed (CONTRIBUTING.md, Tests). The synctest
// tests do not use it: a bubble's clock would date it in the year 2000.
var testCertificate = sync.OnceValues(func() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay test upstream"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
})

func certificate(t *testing.T) tls.Certificate {
	t.Helper()
	c, err := testCertificate()
	if err != nil {
		t.Fatalf("generate test certificate: %v", err)
	}
	return c
}

func trustPool(t *testing.T) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(certificate(t).Leaf)
	return pool
}

// newUpstream starts a loopback TLS upstream with handler h.
func newUpstream(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	s := httptest.NewTestServer(t, h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{certificate(t)}}
	// Some tests fail handshakes on purpose; keep their noise out of the output.
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	return s
}

// newForwarder returns a Forwarder for the origin,
// trusting only the test certificate. edit, if set, changes the options.
func newForwarder(t *testing.T, base string, edit func(*Options)) *Forwarder {
	t.Helper()
	u, err := ParseUpstream(base)
	if err != nil {
		t.Fatalf("ParseUpstream: %v", err)
	}
	o := Options{
		Upstream: u,
		RootCAs:  trustPool(t),
		Timeout:  testTimeout,
	}
	if edit != nil {
		edit(&o)
	}
	f := New(o)
	// Registered after the upstream, so it runs first and the upstream's
	// shutdown does not wait for idle client connections.
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

func mustForward(t *testing.T, f *Forwarder, in http.Header, body string) *Response {
	t.Helper()
	resp, err := f.Forward(t.Context(), in, []byte(body))
	if err != nil {
		t.Fatalf("Forward: %v", err)
	}
	return resp
}

// wantErr fails unless err is exactly want. Forward must return the bare
// sentinel, never a transport error whose text could carry upstream bytes.
func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if err != want {
		t.Fatalf("err = %v, want %v", err, want)
	}
}

// received is what an upstream saw of one request.
type received struct {
	method, target, host string
	proto                int
	header               http.Header
	body                 string
}

// recorder returns a handler that reports each request on the returned
// channel and then lets answer, if set, respond.
func recorder(t *testing.T, answer http.HandlerFunc) (http.HandlerFunc, <-chan received) {
	got := make(chan received, 16)
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream: read body: %v", err)
			return
		}
		got <- received{
			method: r.Method, target: r.RequestURI, host: r.Host, proto: r.ProtoMajor,
			header: r.Header.Clone(), body: string(body),
		}
		if answer != nil {
			answer(w, r)
		}
	}, got
}

// wantUpstreamHeader fails unless the upstream received exactly want, apart
// from User-Agent, which must be Go's own and never the caller's.
func wantUpstreamHeader(t *testing.T, got, want http.Header) {
	t.Helper()
	got = got.Clone()
	if ua := got.Get("User-Agent"); ua == "" || strings.Contains(ua, secretMarker) {
		t.Errorf("upstream User-Agent = %q, want Go's default", ua)
	}
	delete(got, "User-Agent")
	if !maps.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("upstream header = %v, want %v", got, want)
	}
}

// rawUpstream accepts loopback TLS connections and runs serve on each, with
// n counting connections from 0. It returns the base URL and a stop function
// that closes the listener and waits for every connection to end; close the
// client's idle connections first. stop also runs at cleanup.
func rawUpstream(t *testing.T, serve func(n int, c net.Conn)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tln := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{certificate(t)}})
	var wg sync.WaitGroup
	wg.Go(func() {
		for n := 0; ; n++ {
			c, err := tln.Accept()
			if err != nil {
				return // the listener was closed
			}
			wg.Go(func() {
				defer func() { _ = c.Close() }() // the test reads results, not close errors
				serve(n, c)
			})
		}
	})
	stop := sync.OnceFunc(func() {
		_ = ln.Close() // ends the accept loop; an error would only mean it already ended
		wg.Wait()
	})
	t.Cleanup(stop)
	return "https://" + ln.Addr().String(), stop
}

// readRequest reads one request in full and describes it.
func readRequest(br *bufio.Reader) (string, error) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	return req.Method + " " + req.RequestURI + " " + string(body), nil
}

// answerRaw serves each request with raw, written as is.
func answerRaw(raw string) func(int, net.Conn) {
	return func(_ int, c net.Conn) {
		br := bufio.NewReader(c)
		for {
			if _, err := readRequest(br); err != nil {
				return
			}
			if _, err := io.WriteString(c, raw); err != nil {
				return
			}
		}
	}
}

func TestForwardSendsTokenPOSTAndBodyUnchanged(t *testing.T) {
	h, got := recorder(t, nil)
	s := newUpstream(t, h)
	f := newForwarder(t, s.URL, nil)
	for _, body := range []string{tokenBody, "\x00\x01\xfe\xff{\"a\":1}\r\n\r\n", ""} {
		mustForward(t, f, nil, body)
		if r := <-got; r.method != "POST" || r.target != "/oidc/token" || r.body != body {
			t.Errorf("upstream got %s %s %q, want POST /oidc/token %q", r.method, r.target, r.body, body)
		}
	}
}

func TestForwardRequestHeaders(t *testing.T) {
	// caller is what an inbound request could carry besides the allowlisted
	// headers: the FIT, Forge's OAuth and tracing headers, forwarding,
	// framing, hop-by-hop and idempotency headers and a Host it chose.
	caller := func() http.Header {
		return http.Header{
			"Content-Type":         {"application/x-www-form-urlencoded"},
			"Accept":               {"application/json", "text/plain"},
			"Authorization":        {"Bearer " + secretMarker},
			"Proxy-Authorization":  {"Basic " + secretMarker},
			"X-Forge-Oauth-System": {secretMarker},
			"X-Forge-Oauth-User":   {secretMarker},
			"X-B3-Traceid":         {"0123456789abcdef"},
			"X-B3-Spanid":          {"0123456789abcdef"},
			"Idempotency-Key":      {secretMarker},
			"X-Idempotency-Key":    {secretMarker},
			"X-Forwarded-For":      {"192.0.2.1"},
			"X-Forwarded-Host":     {"relay.example"},
			"Forwarded":            {"for=192.0.2.1"},
			"Relay-Error":          {"invalid_token"},
			"Host":                 {"attacker.example"},
			"Cookie":               {secretMarker},
			"User-Agent":           {secretMarker},
			"X-Custom":             {secretMarker},
			"Te":                   {"trailers"},
			"Upgrade":              {"h2c"},
			"Keep-Alive":           {"timeout=5"},
			"Connection":           {"keep-alive"},
			"Content-Length":       {"999"},
			"Transfer-Encoding":    {"chunked"},
		}
	}
	framing := http.Header{"Content-Length": {strconv.Itoa(len(tokenBody))}}

	t.Run("only_allowlisted_headers_pass", func(t *testing.T) {
		h, got := recorder(t, nil)
		s := newUpstream(t, h)
		f := newForwarder(t, s.URL, nil)
		mustForward(t, f, caller(), tokenBody)
		r := <-got
		want := framing.Clone()
		want["Content-Type"] = []string{"application/x-www-form-urlencoded"}
		want["Accept"] = []string{"application/json", "text/plain"}
		wantUpstreamHeader(t, r.header, want)
		if addr := s.Listener.Addr().String(); r.host != addr {
			t.Errorf("upstream Host = %q, want its own address %q", r.host, addr)
		}
	})

	t.Run("connection_nominated_headers_dropped", func(t *testing.T) {
		in := http.Header{
			// Case-insensitive, OWS around tokens, several fields.
			"Connection":   {"keep-alive, x-client-hint", " ACCEPT\t"},
			"Accept":       {"application/json"},
			"Content-Type": {"application/x-www-form-urlencoded"},
		}
		h, got := recorder(t, nil)
		s := newUpstream(t, h)
		f := newForwarder(t, s.URL, nil)
		mustForward(t, f, in, tokenBody)
		want := framing.Clone()
		want["Content-Type"] = []string{"application/x-www-form-urlencoded"}
		wantUpstreamHeader(t, (<-got).header, want)
	})

	t.Run("credential_replaces_caller_header", func(t *testing.T) {
		tests := []struct {
			name string
			cred Credential
			in   http.Header
		}{
			{
				name: "authorization_replaces_fit",
				cred: Credential{Name: "Authorization", Value: newSecret("Basic c3ludGhldGljOnRlc3Q=")},
				in:   http.Header{"Authorization": {"Bearer " + secretMarker}},
			},
			{
				name: "allowlisted_name_replaced_not_joined",
				cred: Credential{Name: "Accept", Value: newSecret("synthetic-credential")},
				in:   http.Header{"Accept": {secretMarker, secretMarker}},
			},
			{
				name: "connection_nomination_cannot_remove_it",
				cred: Credential{Name: "X-Api-Key", Value: newSecret("synthetic-credential")},
				in:   http.Header{"Connection": {"X-Api-Key, Authorization"}, "X-Api-Key": {secretMarker}},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				h, got := recorder(t, nil)
				s := newUpstream(t, h)
				f := newForwarder(t, s.URL, func(o *Options) { o.Credential = &tt.cred })
				mustForward(t, f, tt.in, tokenBody)
				want := framing.Clone()
				want[tt.cred.Name] = []string{tt.cred.Value.Reveal()}
				wantUpstreamHeader(t, (<-got).header, want)
			})
		}
	})
}

func TestForwardResponseHeaders(t *testing.T) {
	spoofing := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Cache-Control: no-store\r\n" +
		"Cache-Control: max-age=0\r\n" +
		"Pragma: no-cache\r\n" +
		"Relay-Error: invalid_token\r\n" +
		"Relay-Protocol: 2\r\n" +
		"Relay-Version: 9.9.9\r\n" +
		"Relay-Upstream-Status: 200\r\n" +
		"Set-Cookie: session=synthetic\r\n" +
		"Keep-Alive: timeout=5\r\n" +
		"Proxy-Authenticate: Basic\r\n" +
		"Upgrade: h2c\r\n" +
		"Location: https://elsewhere.example/\r\n" +
		"X-Upstream-Detail: internal\r\n" +
		"Content-Length: 2\r\n\r\n{}"
	tests := []struct {
		name string
		raw  string
		want http.Header
	}{
		{
			name: "only_allowlisted_headers_return",
			raw:  spoofing,
			want: http.Header{
				"Content-Type":  {"application/json"},
				"Cache-Control": {"no-store", "max-age=0"},
				"Pragma":        {"no-cache"},
			},
		},
		{
			name: "connection_nominated_headers_dropped",
			raw: "HTTP/1.1 200 OK\r\n" +
				"Connection: cache-control,  PRAGMA\r\n" +
				"Content-Type: application/json\r\n" +
				"Cache-Control: no-store\r\n" +
				"Pragma: no-cache\r\n" +
				"Content-Length: 2\r\n\r\n{}",
			want: http.Header{"Content-Type": {"application/json"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base, _ := rawUpstream(t, answerRaw(tt.raw))
			f := newForwarder(t, base, nil)
			resp := mustForward(t, f, nil, tokenBody)
			if !maps.EqualFunc(resp.Header, tt.want, slices.Equal[[]string]) {
				t.Errorf("response header = %v, want %v", resp.Header, tt.want)
			}
			if string(resp.Body) != "{}" {
				t.Errorf("response body = %q, want {}", resp.Body)
			}
		})
	}
}

func TestForwardReturnsUpstreamStatusAndBody(t *testing.T) {
	for _, code := range []int{200, 302, 400, 401, 404, 500, 503} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			body := `{"error":"synthetic_` + strconv.Itoa(code) + `"}`
			s := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/elsewhere")
				w.WriteHeader(code)
				_, _ = io.WriteString(w, body) // a failed write fails the comparison below
			})
			f := newForwarder(t, s.URL, nil)
			resp := mustForward(t, f, nil, tokenBody)
			if resp.Status != code || string(resp.Body) != body {
				t.Errorf("Forward = %d %q, want %d %q", resp.Status, resp.Body, code, body)
			}
		})
	}
}

func TestForwardDoesNotFollowRedirects(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			var followed atomic.Int32
			s := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/elsewhere" {
					followed.Add(1)
					return
				}
				http.Redirect(w, r, "/elsewhere", code)
			})
			f := newForwarder(t, s.URL, nil)
			resp := mustForward(t, f, nil, tokenBody)
			if resp.Status != code {
				t.Errorf("status = %d, want %d", resp.Status, code)
			}
			if n := followed.Load(); n != 0 {
				t.Errorf("redirect target got %d requests, want 0", n)
			}
		})
	}
}

func TestForwardPassesCompressedBodyUnchanged(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := io.WriteString(zw, `{"access_token":"synthetic"}`); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	s := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if ae := r.Header.Values("Accept-Encoding"); len(ae) > 0 {
			t.Errorf("upstream got Accept-Encoding %q, want none", ae)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(gz.Bytes()) // a failed write fails the comparison below
	})
	f := newForwarder(t, s.URL, nil)
	resp := mustForward(t, f, nil, tokenBody)
	if !bytes.Equal(resp.Body, gz.Bytes()) {
		t.Errorf("body = %x, want the gzip bytes %x unchanged", resp.Body, gz.Bytes())
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		t.Errorf("Content-Encoding = %q, want no non-allowlisted header", ce)
	}
}

func TestForwardResponseSizeLimit(t *testing.T) {
	const limit = 65536
	atLimit := strings.Repeat("a", limit)
	tests := []struct {
		name    string
		body    string
		chunked bool // no Content-Length, so only the read can find the size
		want    error
	}{
		{"declared_length_at_limit", atLimit, false, nil},
		{"declared_length_over_limit", atLimit + "b", false, ErrTooLarge},
		{"chunked_at_limit", atLimit, true, nil},
		{"chunked_over_limit", atLimit + "b", true, ErrTooLarge},
		{"empty_body", "", false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
				if !tt.chunked {
					w.Header().Set("Content-Length", strconv.Itoa(len(tt.body)))
					_, _ = io.WriteString(w, tt.body) // a failed write fails the test below
					return
				}
				// The flush sends the headers without a length. A failed write
				// or flush fails the test below.
				_, _ = io.WriteString(w, tt.body[:1])
				_ = http.NewResponseController(w).Flush()
				_, _ = io.WriteString(w, tt.body[1:])
			})
			f := newForwarder(t, s.URL, nil)
			resp, err := f.Forward(t.Context(), nil, []byte(tokenBody))
			wantErr(t, err, tt.want)
			if err == nil && string(resp.Body) != tt.body {
				t.Errorf("body = %q, want %q", resp.Body, tt.body)
			}
		})
	}

	// Without the bounded read, the two tests below would wait for the
	// upstream until testTimeout and fail with ErrTimeout.
	t.Run("endless_body_read_is_bounded", func(t *testing.T) {
		s := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			rc := http.NewResponseController(w)
			for {
				if _, err := io.WriteString(w, atLimit); err != nil || rc.Flush() != nil {
					return // the relay closed the connection
				}
			}
		})
		f := newForwarder(t, s.URL, nil)
		_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrTooLarge)
	})
	t.Run("declared_oversize_body_is_not_read", func(t *testing.T) {
		s := newUpstream(t, func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.ReadAll(r.Body); err != nil {
				return
			}
			// The body sent is far less than declared. A failed write or flush
			// fails the test below.
			w.Header().Set("Content-Length", strconv.Itoa(1<<20))
			_, _ = io.WriteString(w, "{")
			_ = http.NewResponseController(w).Flush()
			<-r.Context().Done() // until the relay drops the connection
		})
		f := newForwarder(t, s.URL, nil)
		_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrTooLarge)
	})
}

func TestForwardUnreachable(t *testing.T) {
	t.Run("untrusted_certificate", func(t *testing.T) {
		var hits atomic.Int32
		s := newUpstream(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
		f := newForwarder(t, s.URL, func(o *Options) { o.RootCAs = x509.NewCertPool() })
		_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrUnreachable)
		if n := hits.Load(); n != 0 {
			t.Errorf("upstream got %d requests over an untrusted connection, want 0", n)
		}
	})
	t.Run("connection_refused", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		f := newForwarder(t, "https://"+addr, nil)
		_, err = f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrUnreachable)
	})
	t.Run("closed_during_tls_handshake", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Go(func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				_ = c.Close() // the point of the test
			}
		})
		t.Cleanup(func() {
			_ = ln.Close() // ends the accept loop; an error would only mean it already ended
			wg.Wait()
		})
		f := newForwarder(t, "https://"+ln.Addr().String(), nil)
		_, err = f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrUnreachable)
	})
	t.Run("malformed_response_text_never_returned", func(t *testing.T) {
		// Go's error for this answer quotes it; Forward must not.
		base, _ := rawUpstream(t, answerRaw("garbage "+secretMarker+"\r\n\r\n"))
		f := newForwarder(t, base, nil)
		_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrUnreachable)
	})
	t.Run("response_header_over_limit", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nX-Padding: " + strings.Repeat("a", 40<<10) + "\r\nContent-Length: 0\r\n\r\n"
		base, _ := rawUpstream(t, answerRaw(raw))
		f := newForwarder(t, base, nil)
		_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrUnreachable)
	})
	// Go returns these as final answers. The relay asks for no upgrade and
	// status codes start at 100 (RFC 9110 §15), so none is a valid answer.
	for _, tt := range []struct{ name, raw string }{
		{"status_000_refused", "HTTP/1.1 000 Synthetic\r\nContent-Length: 0\r\n\r\n"},
		{"status_099_refused", "HTTP/1.1 099 Synthetic\r\nContent-Length: 0\r\n\r\n"},
		{"switching_protocols_without_upgrade_refused", "HTTP/1.1 101 Switching Protocols\r\n\r\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base, _ := rawUpstream(t, answerRaw(tt.raw))
			f := newForwarder(t, base, nil)
			_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
			wantErr(t, err, ErrUnreachable)
		})
	}
	t.Run("response_header_under_limit_accepted", func(t *testing.T) {
		raw := "HTTP/1.1 200 OK\r\nX-Padding: " + strings.Repeat("a", 24<<10) + "\r\nContent-Length: 0\r\n\r\n"
		base, _ := rawUpstream(t, answerRaw(raw))
		f := newForwarder(t, base, nil)
		mustForward(t, f, nil, tokenBody)
	})
	t.Run("transport_error_text_never_returned", func(t *testing.T) {
		f := newForwarder(t, "https://provider.example", nil)
		f.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New(secretMarker)
		})
		_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrUnreachable)
	})
}

// Go's HTTP/1 parser also accepts other version numbers. The relay still
// requires an HTTP/1.1 answer before wrapping it (PLAN.md §4.3, §5).
func TestForwardResponseVersion(t *testing.T) {
	for _, proto := range []string{"HTTP/1.0", "HTTP/1.1", "HTTP/1.2", "HTTP/2.0"} {
		t.Run(proto, func(t *testing.T) {
			base, _ := rawUpstream(t, answerRaw(proto+" 200 OK\r\nContent-Length: 2\r\n\r\n{}"))
			f := newForwarder(t, base, nil)
			resp, err := f.Forward(t.Context(), nil, []byte(tokenBody))
			if proto != "HTTP/1.1" {
				wantErr(t, err, ErrUnreachable)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if resp.Status != http.StatusOK || string(resp.Body) != "{}" {
				t.Errorf("got status %d body %q, want 200 and {}", resp.Status, resp.Body)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// PLAN.md §5 forbids offering a token POST body for replay, even though Go
// currently requires an idempotency header to retry after possible delivery.
func TestTokenBodyHasNoReplayCallback(t *testing.T) {
	f := newForwarder(t, "https://provider.example", nil)
	f.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.GetBody != nil {
			t.Error("token request exposes a body replay callback")
		}
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(b) != tokenBody || r.ContentLength != int64(len(tokenBody)) {
			t.Errorf("got body %q length %d, want original token body and length", b, r.ContentLength)
		}
		return nil, errors.New("synthetic upstream failure")
	})
	_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
	wantErr(t, err, ErrUnreachable)
}

// inMemoryForwarder returns a Forwarder whose upstream is s on httptest's
// in-memory network, so testing/synctest controls every clock involved. The
// test server's dialer also does the TLS handshake with its own settings;
// the loopback tests cover the relay's.
func inMemoryForwarder(t *testing.T, s *httptest.Server, timeout time.Duration) *Forwarder {
	t.Helper()
	u, err := ParseUpstream("https://provider.example")
	if err != nil {
		t.Fatal(err)
	}
	f := New(Options{Upstream: u, Timeout: timeout})
	f.client.Transport.(*http.Transport).DialTLSContext = s.Client().Transport.(*http.Transport).DialTLSContext
	t.Cleanup(f.client.CloseIdleConnections)
	return f
}

func TestForwardTimeout(t *testing.T) {
	const timeout = 10 * time.Second
	stallHeaders := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body) // lets the server notice the relay hanging up
		<-r.Context().Done()
	}
	stallBody := func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body) // lets the server notice the relay hanging up
		// A failed write or flush breaks the connection, which fails the
		// test below.
		w.Header().Set("Content-Length", "100")
		_, _ = io.WriteString(w, "{")
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		callerDeadline time.Duration // 0: none
		want           time.Duration
	}{
		{"timeout_waiting_for_headers", stallHeaders, 0, timeout},
		{"timeout_covers_body_read", stallBody, 0, timeout},
		{"caller_deadline_counts_as_timeout", stallHeaders, 3 * time.Second, 3 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := inMemoryForwarder(t, httptest.NewTestServer(t, tt.handler), timeout)
				ctx := t.Context()
				if tt.callerDeadline > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tt.callerDeadline)
					defer cancel()
				}
				start := time.Now()
				_, err := f.Forward(ctx, nil, []byte(tokenBody))
				wantErr(t, err, ErrTimeout)
				if elapsed := time.Since(start); elapsed != tt.want {
					t.Errorf("Forward returned after %v, want %v", elapsed, tt.want)
				}
			})
		})
	}
}

// TestForwardClosesSilentHandshake covers an upstream, or a TLS-intercepting
// box on the way, that accepts the connection and never answers the
// ClientHello. Go dials on a context detached from the request, so
// Options.Timeout ends the call but leaves the handshake running, and only
// the handshake timeout closes the socket; without it every login attempt
// during such a stall would leave one behind (PLAN.md R-2, §13). The peer is
// an in-memory pipe, so the bubble's fake clock runs both timeouts.
func TestForwardClosesSilentHandshake(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		u, err := ParseUpstream("https://provider.example")
		if err != nil {
			t.Fatal(err)
		}
		f := New(Options{Upstream: u, Timeout: time.Second})
		tr := f.client.Transport.(*http.Transport)
		// The pipe stands for the upstream, whatever proxy the test
		// environment sets.
		tr.Proxy = nil
		closedAfter := make(chan time.Duration, 1)
		tr.DialContext = func(context.Context, string, string) (net.Conn, error) {
			conn, peer := net.Pipe()
			dialed := time.Now()
			go func() {
				// Reads the ClientHello, answers nothing and returns when
				// the relay closes its end.
				_, _ = io.Copy(io.Discard, peer)
				closedAfter <- time.Since(dialed)
			}()
			return conn, nil
		}
		// If the handshake timeout is missing, only this ends the handshake,
		// so the bubble can finish after the failure is reported.
		t.Cleanup(tr.CloseIdleConnections)

		_, err = f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrTimeout)
		select {
		case d := <-closedAfter:
			if d != tlsHandshakeTimeout {
				t.Errorf("connection closed %v after the dial, want %v", d, tlsHandshakeTimeout)
			}
		case <-time.After(time.Hour):
			t.Error("connection still open an hour after Forward returned")
		}
	})
}

func TestForwardCallerCancelCancelsUpstream(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		upstreamErr := make(chan error, 1)
		s := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.ReadAll(r.Body) // lets the server notice the relay hanging up
			<-r.Context().Done()
			upstreamErr <- r.Context().Err()
		}))
		f := inMemoryForwarder(t, s, time.Minute)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		time.AfterFunc(2*time.Second, cancel) // Forge disconnects
		start := time.Now()
		_, err := f.Forward(ctx, nil, []byte(tokenBody))
		wantErr(t, err, ErrCanceled)
		if elapsed := time.Since(start); elapsed != 2*time.Second {
			t.Errorf("Forward returned after %v, want 2s", elapsed)
		}
		if err := <-upstreamErr; !errors.Is(err, context.Canceled) {
			t.Errorf("upstream request context ended with %v, want context.Canceled", err)
		}
	})
}

// TestForwardUnrequestedUpgradeEndsAtOnce covers a 101 with Upgrade headers
// followed by silence. Go hands that answer over as the raw connection, whose
// reads neither Options.Timeout nor the caller's context bound (PLAN.md R-2,
// R-3). Without the status check, Forward would wait until the upstream
// closed it, and the bubble would report a deadlock.
func TestForwardUnrequestedUpgradeEndsAtOnce(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := io.ReadAll(r.Body); err != nil {
				return
			}
			c, _, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("upstream: hijack: %v", err)
				return
			}
			defer func() { _ = c.Close() }() // the test reads results, not close errors
			const switching = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: synthetic\r\n\r\n"
			if _, err := io.WriteString(c, switching); err != nil {
				return
			}
			// Idle until the relay closes the connection; that close is the
			// read's only expected error.
			_, _ = io.Copy(io.Discard, c)
		}))
		f := inMemoryForwarder(t, s, time.Minute)
		start := time.Now()
		_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
		wantErr(t, err, ErrUnreachable)
		if elapsed := time.Since(start); elapsed != 0 {
			t.Errorf("Forward returned after %v, want at once", elapsed)
		}
	})
}

// dropAfter reads every request in full. On the first connection it
// answers the first `answered` requests, then reads one more and closes the
// connection without answering, as if the answer were lost after the
// provider spent the code. Later connections answer everything, so a replay
// would succeed and be seen.
func dropAfter(answered int, seen chan<- string) func(int, net.Conn) {
	return func(n int, c net.Conn) {
		br := bufio.NewReader(c)
		for i := 0; ; i++ {
			req, err := readRequest(br)
			if err != nil {
				return
			}
			seen <- req
			if n == 0 && i == answered {
				return
			}
			if _, err := io.WriteString(c, okResponse); err != nil {
				return
			}
		}
	}
}

// tracedConns returns a context that records, for every connection the
// transport takes, whether it was reused.
func tracedConns(ctx context.Context) (context.Context, func() []bool) {
	var mu sync.Mutex
	var reused []bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) {
		mu.Lock()
		defer mu.Unlock()
		reused = append(reused, i.Reused)
	}})
	return ctx, func() []bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(reused)
	}
}

// TestForwardDoesNotReplayTokenPOST proves PLAN.md §5 R-8: a token POST that
// reached the upstream is sent exactly once, even when its answer is lost.
func TestForwardDoesNotReplayTokenPOST(t *testing.T) {
	tests := []struct {
		name     string
		answered int // requests answered on the first connection before one is lost
		in       http.Header
		// For the last call: its error, the connections it took and every
		// request the upstream saw over the whole test.
		wantErr   error
		wantConns []bool
		wantSeen  []string
	}{
		{
			name: "fresh_connection", answered: 0,
			wantErr: ErrUnreachable, wantConns: []bool{false},
			wantSeen: []string{"POST /oidc/token " + tokenBody},
		},
		{
			name: "reused_connection", answered: 1,
			wantErr: ErrUnreachable, wantConns: []bool{true},
			wantSeen: []string{"POST /oidc/token " + tokenBody, "POST /oidc/token " + tokenBody2},
		},
		{
			// Go treats a POST with either header as idempotent and replays
			// it, so they must never be sent.
			name: "reused_connection_idempotency_headers_dropped", answered: 1,
			in:      http.Header{"Idempotency-Key": {"synthetic"}, "X-Idempotency-Key": {"synthetic"}},
			wantErr: ErrUnreachable, wantConns: []bool{true},
			wantSeen: []string{"POST /oidc/token " + tokenBody, "POST /oidc/token " + tokenBody2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seen := make(chan string, 16)
			base, stop := rawUpstream(t, dropAfter(tt.answered, seen))
			f := newForwarder(t, base, nil)
			bodies := []string{tokenBody, tokenBody2}
			for i := range tt.answered {
				if resp := mustForward(t, f, tt.in, bodies[i]); resp.Status != http.StatusOK {
					t.Fatalf("call %d: status %d, want 200", i+1, resp.Status)
				}
			}
			ctx, conns := tracedConns(t.Context())
			_, err := f.Forward(ctx, tt.in, []byte(bodies[tt.answered]))
			wantErr(t, err, tt.wantErr)
			if got := conns(); !slices.Equal(got, tt.wantConns) {
				t.Errorf("connections reused = %v, want %v", got, tt.wantConns)
			}

			// Every connection ends before the count, so a replay still in
			// flight cannot be missed.
			f.client.CloseIdleConnections()
			stop()
			close(seen)
			var got []string
			for req := range seen {
				got = append(got, req)
			}
			if !slices.Equal(got, tt.wantSeen) {
				t.Errorf("upstream saw %q, want %q", got, tt.wantSeen)
			}
		})
	}
}

func TestForwardReusesConnections(t *testing.T) {
	h, _ := recorder(t, nil)
	s := newUpstream(t, h)
	f := newForwarder(t, s.URL, nil)
	mustForward(t, f, nil, tokenBody)
	ctx, conns := tracedConns(t.Context())
	if _, err := f.Forward(ctx, nil, []byte(tokenBody2)); err != nil {
		t.Fatalf("Forward: %v", err)
	}
	if got := conns(); !slices.Equal(got, []bool{true}) {
		t.Errorf("connections reused = %v, want [true] (PLAN.md R-9)", got)
	}
}

func TestForwardSpeaksOnlyHTTP1(t *testing.T) {
	h, got := recorder(t, nil)
	s := httptest.NewTestServer(t, h)
	s.EnableHTTP2 = true
	s.TLS = &tls.Config{Certificates: []tls.Certificate{certificate(t)}, NextProtos: []string{"h2", "http/1.1"}}
	s.StartTLS()

	// Harness check: a client that offers HTTP/2 gets it from this upstream.
	resp, err := s.Client().Post(s.URL+TokenPath, "text/plain", strings.NewReader(tokenBody))
	if err != nil {
		t.Fatalf("harness request: %v", err)
	}
	_ = resp.Body.Close() // only the protocol matters
	if r := <-got; r.proto != 2 {
		t.Fatalf("harness: upstream spoke HTTP/%d, want 2", r.proto)
	}

	f := newForwarder(t, s.URL, nil)
	mustForward(t, f, nil, tokenBody)
	if r := <-got; r.proto != 1 {
		t.Errorf("relay spoke HTTP/%d to the upstream, want 1 (PLAN.md §7)", r.proto)
	}
}

func TestForwardInvalidUpstreamFailsClosed(t *testing.T) {
	tests := []struct {
		name     string
		upstream Upstream
	}{
		{"zero_upstream", Upstream{}},
		{"unparsable_origin", Upstream{origin: "https://bad host"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := New(Options{Upstream: tt.upstream, Timeout: testTimeout})
			_, err := f.Forward(t.Context(), nil, []byte(tokenBody))
			wantErr(t, err, ErrUnreachable)
		})
	}
}

func TestProxyInUse(t *testing.T) {
	proxyURL := &url.URL{Scheme: "http", Host: "proxy.example:3128"}
	const target = "https://provider.example/oidc/token"
	tests := []struct {
		name  string
		proxy func(*http.Request) (*url.URL, error)
		raw   string
		want  bool
	}{
		{"proxy_selected", func(r *http.Request) (*url.URL, error) {
			if r.URL.String() != target {
				return nil, errors.New("unexpected URL")
			}
			return proxyURL, nil
		}, target, true},
		{"direct", func(*http.Request) (*url.URL, error) { return nil, nil }, target, false},
		{"bad_proxy_setting_counts_as_in_use", func(*http.Request) (*url.URL, error) {
			return nil, errors.New("invalid proxy address")
		}, target, true},
		{"unparsable_url", func(*http.Request) (*url.URL, error) { return proxyURL, nil }, "https://bad host", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxyInUse(tt.proxy, tt.raw); got != tt.want {
				t.Errorf("proxyInUse = %v, want %v", got, tt.want)
			}
		})
	}
	t.Run("loopback_never_proxied", func(t *testing.T) {
		if ProxyInUse("https://127.0.0.1:8443/oidc/token") {
			t.Error("ProxyInUse(loopback) = true")
		}
	})
}

// TestNewClientSettings pins the client settings of PLAN.md §5 that the
// behaviour tests cannot tell apart from Go's defaults.
func TestNewClientSettings(t *testing.T) {
	pool := x509.NewCertPool()
	f := New(Options{RootCAs: pool})
	tr, ok := f.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", f.client.Transport)
	}
	checks := []struct {
		name string
		ok   bool
	}{
		{"tls_1_2_minimum", tr.TLSClientConfig.MinVersion == tls.VersionTLS12},
		{"configured_roots_only", tr.TLSClientConfig.RootCAs == pool},
		{"http1_only", tr.Protocols != nil && tr.Protocols.HTTP1() && !tr.Protocols.HTTP2() && !tr.Protocols.UnencryptedHTTP2()},
		{"no_decompression", tr.DisableCompression},
		{"ten_idle_per_host", tr.MaxIdleConnsPerHost == 10 && tr.MaxIdleConns == 10},
		{"response_header_bound", tr.MaxResponseHeaderBytes == 32<<10},
		{"tls_handshake_timeout_10s", tr.TLSHandshakeTimeout == 10*time.Second},
		{"dial_timeout_30s", f.dialer.Timeout == 30*time.Second},
		{"tcp_keepalive_30s", f.dialer.KeepAlive == 30*time.Second},
		{"proxy_from_environment", tr.Proxy != nil},
		{"redirects_not_followed", f.client.CheckRedirect(nil, nil) == http.ErrUseLastResponse},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("%s: not set", c.name)
		}
	}
	// The dialer checks prove something only if the transport dials with
	// that dialer. Its Control hook runs before the connect, so nothing is
	// sent.
	errHook := errors.New("control hook ran")
	f.dialer.Control = func(string, string, syscall.RawConn) error { return errHook }
	if _, err := tr.DialContext(t.Context(), "tcp", "127.0.0.1:1"); !errors.Is(err, errHook) {
		t.Errorf("dials_with_checked_dialer: the transport dials with another dialer (%v)", err)
	}
}
