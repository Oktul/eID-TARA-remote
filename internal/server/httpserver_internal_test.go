// SPDX-License-Identifier: EUPL-1.2

package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"eid-forge-remote/internal/config"
)

// TestHTTPServerSettingsMatchPlan pins the listener settings of PLAN.md §6
// R-1 and §7 (HTTP/1.1 only inbound, plain HTTP behind the proxy, D6).
// The values are spelled out, so changing one breaks this test rather than
// passing silently; the timeouts cannot be seen over HTTP without waiting
// them out.
func TestHTTPServerSettingsMatchPlan(t *testing.T) {
	s := &Server{cfg: &config.Config{UpstreamTimeout: 7 * time.Second}, log: slog.New(slog.DiscardHandler)}
	hs := s.httpServer()
	checks := []struct {
		name string
		ok   bool
	}{
		{"read_header_timeout_5s", hs.ReadHeaderTimeout == 5*time.Second},
		{"read_timeout_10s", hs.ReadTimeout == 10*time.Second},
		{"write_timeout_upstream_plus_5s", hs.WriteTimeout == 12*time.Second},
		{"idle_timeout_60s", hs.IdleTimeout == 60*time.Second},
		{"max_header_bytes_16KiB", hs.MaxHeaderBytes == 16384},
		{"http1_only", hs.Protocols != nil && hs.Protocols.HTTP1() && !hs.Protocols.HTTP2() && !hs.Protocols.UnencryptedHTTP2()},
		{"no_general_options_handler", hs.DisableGeneralOptionsHandler},
		{"error_log_replaced", hs.ErrorLog != nil},
		{"refusals_tracked", hs.ConnState != nil && hs.ConnContext != nil}, // SR-9
		{"plain_http", hs.TLSConfig == nil},
	}
	for _, c := range checks {
		if !c.ok {
			t.Errorf("%s: not set", c.name)
		}
	}
}

// TestHTTPServerErrorLogRedacted proves PLAN.md §10 for net/http's own error
// log. Its messages carry client addresses and raw error text; only a fixed
// message reaches the log.
func TestHTTPServerErrorLogRedacted(t *testing.T) {
	var out bytes.Buffer
	s := &Server{
		cfg: &config.Config{UpstreamTimeout: time.Second},
		log: slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	const input = "http: TLS handshake error from 192.0.2.1:4711: SECRETMARKER"
	s.httpServer().ErrorLog.Print(input)
	got := out.String()
	if !strings.Contains(got, `"msg":"http server error"`) {
		t.Fatalf("log = %q, want the fixed message", got)
	}
	for _, leak := range []string{"SECRETMARKER", "192.0.2.1", "handshake"} {
		if strings.Contains(got, leak) {
			t.Errorf("log contains %q", leak)
		}
	}
}
