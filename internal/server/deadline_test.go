// SPDX-License-Identifier: EUPL-1.2

package server_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"eid-forge-remote/internal/config"
	"eid-forge-remote/internal/server"
)

// TestSlowBodyStillGetsUpstreamAnswer proves that the write deadline
// restarts once the body has been read (PLAN.md §6 R-1). Otherwise a body
// that arrives late would use up the time the answer needs: the token
// exchange would succeed upstream, spending its one-time code, and the
// answer would be dropped (R-8). The deadline is a real socket deadline, so
// the test waits past it on the real clock and is skipped with -short.
func TestSlowBodyStillGetsUpstreamAnswer(t *testing.T) {
	if testing.Short() {
		t.Skip("waits past the server's write timeout on the real clock")
	}
	const upstreamTimeout = 100 * time.Millisecond
	r := newRelay(t, relayOptions{run: true, env: map[string]string{"RELAY_UPSTREAM_TIMEOUT": upstreamTimeout.String()}})
	// The server's WriteTimeout runs from the end of the request header;
	// the body arrives after it has passed, well inside ReadTimeout.
	bodyDelay := upstreamTimeout + config.WriteTimeoutMargin + 300*time.Millisecond

	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }() // one exchange per connection
	if err := conn.SetDeadline(time.Now().Add(bodyDelay + waitTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "POST /oidc/token HTTP/1.1\r\nHost: relay.example\r\nAuthorization: Bearer %s\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 2\r\n\r\n", validFIT(t)); err != nil {
		t.Fatal(err)
	}
	late := time.NewTimer(bodyDelay)
	<-late.C
	if _, err := io.WriteString(conn, "{}"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer after a late body: %v", err)
	}
	defer func() { _ = resp.Body.Close() }() // the status and header decide
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Relay-Upstream-Status") != "200" {
		t.Errorf("got %d with Relay-Upstream-Status %q, want 200 and 200",
			resp.StatusCode, resp.Header.Get("Relay-Upstream-Status"))
	}
}

// TestLateOverrunStillGetsBodyTooLarge proves that the write deadline also
// restarts when the body is refused (PLAN.md §6 R-1, §4.3). With an upstream
// timeout under 5 s, WriteTimeout is shorter than ReadTimeout, so a chunked
// body can go over the request limit after the original deadline has
// passed; its 413 must still arrive. Like the test above, it waits past a
// real socket deadline and is skipped with -short.
func TestLateOverrunStillGetsBodyTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("waits past the server's write timeout on the real clock")
	}
	const upstreamTimeout = 100 * time.Millisecond
	r := newRelay(t, relayOptions{run: true, env: map[string]string{
		"RELAY_UPSTREAM_TIMEOUT": upstreamTimeout.String(),
	}})
	overrunDelay := upstreamTimeout + config.WriteTimeoutMargin + 300*time.Millisecond

	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }() // one exchange per connection
	if err := conn.SetDeadline(time.Now().Add(overrunDelay + waitTimeout)); err != nil {
		t.Fatal(err)
	}
	first, rest := strings.Repeat("a", server.MaxRequestBytes/2), strings.Repeat("a", server.MaxRequestBytes)
	if _, err := fmt.Fprintf(conn, "POST /oidc/token HTTP/1.1\r\nHost: relay.example\r\nAuthorization: Bearer %s\r\n"+
		"Transfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", validFIT(t), len(first), first); err != nil {
		t.Fatal(err)
	}
	late := time.NewTimer(overrunDelay)
	<-late.C
	if _, err := fmt.Fprintf(conn, "%x\r\n%s\r\n0\r\n\r\n", len(rest), rest); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no answer after a late overrun: %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge || resp.Header.Get("Relay-Error") != "body_too_large" {
		t.Fatalf("got %d %q, want 413 body_too_large", resp.StatusCode, resp.Header.Get("Relay-Error"))
	}
	if !resp.Close {
		t.Error("413 does not announce Connection: close")
	}
}

// TestDeclaredOversizedBodyAnsweredAtOnce proves that a declared
// Content-Length over the request limit gets its 413 at once, with
// Connection: close, rather than after net/http has read the body the relay
// refused (PLAN.md R-4). The client sends only the header, so a relay that
// waited for the body would never answer. (After answering, net/http still
// reads up to 256 KiB of the body before it closes the socket, bounded by
// ReadTimeout; closing sooner could reset the connection and lose the 413.)
func TestDeclaredOversizedBodyAnsweredAtOnce(t *testing.T) {
	r := newRelay(t, relayOptions{})
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }() // one exchange per connection
	if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "POST /oidc/token HTTP/1.1\r\nHost: relay.example\r\nAuthorization: Bearer %s\r\n"+
		"Content-Length: %d\r\n\r\n", validFIT(t), server.MaxRequestBytes+1); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no 413 before the body was sent: %v", err)
	}
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusRequestEntityTooLarge || resp.Header.Get("Relay-Error") != "body_too_large" {
		t.Fatalf("got %d %q, want 413 body_too_large", resp.StatusCode, resp.Header.Get("Relay-Error"))
	}
	if !resp.Close {
		t.Error("413 does not announce Connection: close")
	}
}

// Early answers refuse the body before step 4. They must flush without
// waiting for net/http to drain it, just like a 413 (PLAN.md §4.3, §6).
func TestEarlyAnswersDoNotWaitForBody(t *testing.T) {
	const responseWait = time.Second
	for _, c := range []struct {
		name, method, target, code string
		status                     int
		authenticated, notReady    bool
	}{
		{"invalid_token", "POST", "/oidc/token", "invalid_token", 401, false, false},
		{"route_not_allowed", "POST", "/other", "route_not_allowed", 404, true, false},
		{"not_ready", "POST", "/oidc/token", "not_ready", 503, false, true},
		{"live", "GET", "/livez", "", 200, false, false},
		{"ready", "GET", "/readyz", "", 200, false, false},
		{"unready", "GET", "/readyz", "not_ready", 503, false, true},
		{"info", "GET", "/relay/v1/info", "", 200, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			opts := relayOptions{run: true, notReady: c.notReady,
				env: map[string]string{"RELAY_UPSTREAM_TIMEOUT": "100ms"}}
			if c.notReady {
				opts.jwks = jwksUnavailable
			}
			r := newRelay(t, opts)
			for _, framing := range []string{"Content-Length: 2", "Transfer-Encoding: chunked"} {
				t.Run(framing, func(t *testing.T) {
					conn, err := net.Dial("tcp", r.addr)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = conn.Close() }() // intentionally leave the body unsent
					if err := conn.SetDeadline(time.Now().Add(responseWait)); err != nil {
						t.Fatal(err)
					}
					auth := ""
					if c.authenticated {
						auth = "Authorization: Bearer " + validFIT(t) + "\r\n"
					}
					if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: relay.example\r\n%s%s\r\n\r\n",
						c.method, c.target, auth, framing); err != nil {
						t.Fatal(err)
					}
					resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
					if err != nil {
						t.Fatalf("no answer before the refused body: %v", err)
					}
					defer func() { _ = resp.Body.Close() }() // the response read below decides
					if _, err := io.Copy(io.Discard, resp.Body); err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != c.status || resp.Header.Get("Relay-Error") != c.code ||
						resp.Header.Get("Relay-Protocol") != "1" {
						t.Errorf("got %d %v, want %d %q and Relay-Protocol 1", resp.StatusCode, resp.Header, c.status, c.code)
					}
					if !resp.Close {
						t.Error("answer to an unread body does not announce Connection: close")
					}
				})
			}
		})
	}
}

// A fully read body must still allow reuse after early-refusal protection
// is removed (PLAN.md §6). Both exchanges use the same TCP connection.
func TestReadBodyKeepsConnectionReusable(t *testing.T) {
	r := newRelay(t, relayOptions{run: true})
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }() // both requests finish before closing
	if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	fit := validFIT(t)
	for range 2 {
		if _, err := fmt.Fprintf(conn, "POST /oidc/token HTTP/1.1\r\nHost: relay.example\r\n"+
			"Authorization: Bearer %s\r\nContent-Length: 2\r\n\r\n{}", fit); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close() // the full read above decides
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 || resp.Header.Get("Relay-Upstream-Status") != "200" || resp.Close {
			t.Fatalf("got %d %v close=%t, want reusable upstream answer", resp.StatusCode, resp.Header, resp.Close)
		}
	}
}

// TestInfoListsRoutesAsConfigured proves that /relay/v1/info shows each
// route byte for byte as configured (PLAN.md §4.1). "&" is a valid path
// character (§5) that json.Marshal would rewrite as an escape.
func TestInfoListsRoutesAsConfigured(t *testing.T) {
	r := newRelay(t, relayOptions{env: map[string]string{"RELAY_ROUTES": "POST /a&b"}})
	got := r.do(t, "GET", "/relay/v1/info", bearer(validFIT(t)), nil)
	if want := `"routes":["POST /a&b"]`; got.status != http.StatusOK || !strings.Contains(got.body, want) {
		t.Errorf("got %d %s, want 200 with %s", got.status, got.body, want)
	}
}
