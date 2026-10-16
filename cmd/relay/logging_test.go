// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// net/http logs unsolicited bytes on an idle pooled upstream connection
// through the process's standard logger. Those bytes can contain secrets
// (PLAN.md §10).
func TestIdleUpstreamBytesNeverLogged(t *testing.T) {
	// The standard logger is process-wide, so this test stays sequential.
	oldWriter := log.Writer()
	captured := &logSink{wrote: make(chan struct{}, 1)}
	log.SetOutput(captured)
	// Registered first so the relay stops before its log destination changes.
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	upstream, closed := upstreamWithExtraBytes(t, "{}")
	upstream.StartTLS()
	caPath := filepath.Join(t.TempDir(), "upstream-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "synthetic-upstream-log-key"
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, jwksDocument(kid, &key.PublicKey)) // a lost answer fails readiness
	}))
	t.Cleanup(jwks.Close)
	r := startRelay(t, with(validEnv(), "RELAY_JWKS_URL", jwks.URL+"/jwks.json",
		"RELAY_UPSTREAM_URL", upstream.URL, "RELAY_UPSTREAM_CA_FILE", caPath), jwks.Client())
	r.waitFor(t, "signing keys ready")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		"http://127.0.0.1:"+strconv.Itoa(r.port)+"/oidc/token", strings.NewReader("synthetic-token-request"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+signFIT(t, key, kid))
	client := &http.Client{Transport: &http.Transport{}, Timeout: waitLimit}
	defer client.CloseIdleConnections()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close() // body read determines the result
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || resp.Header.Get("Relay-Upstream-Status") != "200" || string(body) != "{}" {
		t.Fatalf("response = %d %v %q", resp.StatusCode, resp.Header, body)
	}
	waitIdleClose(t, closed)
	if code := r.stop(t); code != 0 {
		t.Fatalf("stop = %d", code)
	}
	if strings.Contains(captured.String()+r.log.String(), marker) {
		t.Fatal("unsolicited upstream bytes reached a log")
	}
	lines := logLines(t, r.log.String())
	startup, stopped := find(lines, "starting"), find(lines, "stopped")
	if startup == nil || startup["level"] != "INFO" || startup["version"] != version ||
		startup["RELAY_PORT"] != float64(r.port) || stopped == nil || stopped["level"] != "INFO" {
		t.Fatalf("structured lifecycle logs missing: %s", r.log.String())
	}
}

func TestHealthcheckIdleBytesNeverLogged(t *testing.T) {
	oldWriter := log.Writer()
	captured := &logSink{wrote: make(chan struct{}, 1)}
	log.SetOutput(captured)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	probe, closed := upstreamWithExtraBytes(t, "")
	probe.Start()
	port := strings.TrimPrefix(probe.URL, "http://127.0.0.1:")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"healthcheck"}, []string{"RELAY_PORT=" + port}, &stdout, &stderr); code != 0 {
		t.Fatalf("healthcheck = %d; stderr=%s", code, &stderr)
	}
	waitIdleClose(t, closed)
	if strings.Contains(captured.String()+stdout.String()+stderr.String(), marker) {
		t.Fatal("unsolicited healthcheck bytes reached a log")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("successful healthcheck wrote stdout=%q stderr=%q", &stdout, &stderr)
	}
}

// upstreamWithExtraBytes returns an unstarted server that sends marker after
// its framed body, exercising net/http's diagnostic path on idle connections.
func upstreamWithExtraBytes(t *testing.T, body string) (*httptest.Server, <-chan error) {
	t.Helper()
	closed := make(chan error, 1)
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if _, err := io.Copy(io.Discard, req.Body); err != nil {
			closed <- err
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			closed <- err
			return
		}
		defer func() { _ = conn.Close() }() // the checks never depend on the close
		if err := conn.SetDeadline(time.Now().Add(waitLimit)); err != nil {
			closed <- err
			return
		}
		if _, err := io.WriteString(rw, "HTTP/1.1 200 OK\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body+marker); err != nil {
			closed <- err
			return
		}
		if err := rw.Flush(); err != nil {
			closed <- err
			return
		}
		// EOF proves the transport processed and rejected the extra bytes;
		// the assertion does not pass merely because a log is delayed.
		_, err = io.Copy(io.Discard, conn)
		closed <- err
	}))
	t.Cleanup(upstream.Close)
	return upstream, closed
}

func waitIdleClose(t *testing.T, closed <-chan error) {
	t.Helper()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(waitLimit):
		t.Fatal("upstream idle connection was not closed after unsolicited bytes")
	}
}
