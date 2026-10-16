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
// body can go over RELAY_MAX_REQUEST_BYTES after the original deadline has
// passed; its 413 must still arrive. Like the test above, it waits past a
// real socket deadline and is skipped with -short.
func TestLateOverrunStillGetsBodyTooLarge(t *testing.T) {
	if testing.Short() {
		t.Skip("waits past the server's write timeout on the real clock")
	}
	const upstreamTimeout = 100 * time.Millisecond
	r := newRelay(t, relayOptions{run: true, env: map[string]string{
		"RELAY_UPSTREAM_TIMEOUT":  upstreamTimeout.String(),
		"RELAY_MAX_REQUEST_BYTES": "1024",
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
	first, rest := strings.Repeat("a", 512), strings.Repeat("a", 1024)
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
// Content-Length over RELAY_MAX_REQUEST_BYTES gets its 413 at once, with
// Connection: close, rather than after net/http has read the body the relay
// refused (PLAN.md R-4). The client sends only the header, so a relay that
// waited for the body would never answer. (After answering, net/http still
// reads up to 256 KiB of the body before it closes the socket, bounded by
// ReadTimeout; closing sooner could reset the connection and lose the 413.)
func TestDeclaredOversizedBodyAnsweredAtOnce(t *testing.T) {
	r := newRelay(t, relayOptions{env: map[string]string{"RELAY_MAX_REQUEST_BYTES": "1024"}})
	conn, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }() // one exchange per connection
	if err := conn.SetDeadline(time.Now().Add(waitTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "POST /oidc/token HTTP/1.1\r\nHost: relay.example\r\nAuthorization: Bearer %s\r\n"+
		"Content-Length: 2048\r\n\r\n", validFIT(t)); err != nil {
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
