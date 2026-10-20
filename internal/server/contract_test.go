// SPDX-License-Identifier: EUPL-1.2

package server_test

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"

	"eid-forge-remote/internal/forward"
	"eid-forge-remote/internal/server"
)

// The contract fixtures of PLAN.md §4.6, exercised over HTTP. Header names,
// error codes, setting names and bodies are spelled as literals: changing
// one of them here is a protocol change (CONTRIBUTING.md, Tests).

// TestContractFixedLimits pins the limits of PLAN.md D8 and §6, which are
// fixed rather than settings (owner, 2026-10-16): 64 KiB bodies each way
// and 50 requests at once. A relay built with them accepts a request body
// of exactly 64 KiB and refuses one byte more.
func TestContractFixedLimits(t *testing.T) {
	if server.MaxRequestBytes != 65536 || forward.MaxResponseBytes != 65536 || server.MaxConcurrent != 50 {
		t.Errorf("limits = %d, %d, %d; want 65536, 65536, 50",
			server.MaxRequestBytes, forward.MaxResponseBytes, server.MaxConcurrent)
	}
	r := newRelay(t, relayOptions{})
	fit := validFIT(t)
	if got := r.do(t, "POST", "/oidc/token", bearer(fit), strings.NewReader(strings.Repeat("a", 65536))); got.status != 200 {
		t.Errorf("64 KiB body: status %d, want 200", got.status)
	}
	if got := r.do(t, "POST", "/oidc/token", bearer(fit), strings.NewReader(strings.Repeat("a", 65537))); got.status != 413 {
		t.Errorf("64 KiB + 1 body: status %d, want 413", got.status)
	}
}

// TestContractRelayErrors covers every relay error code of PLAN.md §4.3 with
// its status, headers and exact body. Relay-Version appears only on answers
// to a valid FIT.
func TestContractRelayErrors(t *testing.T) {
	cases := []struct {
		name      string
		status    int
		code      string
		versioned bool
		answer    func(t *testing.T) reply
	}{
		{"invalid_token", 401, "invalid_token", false, func(t *testing.T) reply {
			r := newRelay(t, relayOptions{})
			return r.do(t, "POST", "/oidc/token", nil, nil)
		}},
		{"route_not_allowed", 404, "route_not_allowed", true, func(t *testing.T) reply {
			r := newRelay(t, relayOptions{})
			return r.do(t, "POST", "/oidc/other", bearer(validFIT(t)), nil)
		}},
		{"body_too_large", 413, "body_too_large", true, func(t *testing.T) reply {
			r := newRelay(t, relayOptions{})
			return r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), strings.NewReader(strings.Repeat("a", 65537)))
		}},
		{"internal_error", 500, "internal_error", true, func(t *testing.T) reply {
			r := newRelay(t, relayOptions{nilForwarder: true})
			return r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil)
		}},
		{"upstream_unreachable", 502, "upstream_unreachable", true, func(t *testing.T) reply {
			r := newRelay(t, relayOptions{upstreamURL: closedPortURL(t)})
			return r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil)
		}},
		{"upstream_too_large", 502, "upstream_too_large", true, func(t *testing.T) reply {
			r := newRelay(t, relayOptions{upstream: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat("a", 65537))) // the relay checks the body size
			}})
			return r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil)
		}},
		{"not_ready", 503, "not_ready", false, func(t *testing.T) reply {
			r := newRelay(t, relayOptions{jwks: jwksUnavailable, notReady: true})
			return r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil)
		}},
		{"not_ready_readyz", 503, "not_ready", false, func(t *testing.T) reply {
			r := newRelay(t, relayOptions{jwks: jwksUnavailable, notReady: true})
			return r.do(t, "GET", "/readyz", nil, nil)
		}},
		{"too_busy", 503, "too_busy", true, func(t *testing.T) reply {
			g := newGate()
			defer g.release()
			r := newRelay(t, relayOptions{upstream: g.handler})
			fit := validFIT(t)
			held := make(chan error, 50)
			for range 50 {
				go func() {
					_, err := r.send(context.Background(), "POST", "/oidc/token", bearer(fit), nil)
					held <- err
				}()
			}
			g.waitEntered(t, 50)
			got := r.do(t, "POST", "/oidc/token", bearer(fit), nil)
			g.release()
			for range 50 {
				if err := <-held; err != nil {
					t.Errorf("held request: %v", err)
				}
			}
			return got
		}},
		{"upstream_timeout", 504, "upstream_timeout", true, func(t *testing.T) reply {
			g := newGate()
			defer g.release()
			r := newRelay(t, relayOptions{env: map[string]string{"RELAY_UPSTREAM_TIMEOUT": "100ms"}, upstream: g.handler})
			return r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			expectRelayError(t, c.answer(t), c.status, c.code, c.versioned)
		})
	}
}

// TestContractHealth pins the health answers of PLAN.md §4.1.
func TestContractHealth(t *testing.T) {
	r := newRelay(t, relayOptions{})
	for _, target := range []string{"/livez", "/readyz"} {
		t.Run(strings.TrimPrefix(target, "/"), func(t *testing.T) {
			expectHealthy(t, r.do(t, "GET", target, nil, nil))
		})
	}
	if n := r.upstreamHits.Load(); n != 0 {
		t.Errorf("health checks made %d upstream calls", n)
	}
}

// TestContractInfo pins the /relay/v1/info body of PLAN.md §4.1. It is
// answered locally and only after a valid FIT.
func TestContractInfo(t *testing.T) {
	cases := []struct {
		name       string
		env        map[string]string
		credential string
	}{
		{"credential_set", nil, "true"},
		{"credential_not_set", map[string]string{"RELAY_UPSTREAM_AUTH": unset}, "false"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newRelay(t, relayOptions{env: c.env})
			got := r.do(t, "GET", "/relay/v1/info", bearer(validFIT(t)), nil)
			want := `{"relay_version":"1.2.0","protocol_version":1,"upstream_url":"` + r.upstreamURL +
				`","routes":["POST /oidc/token"],"credential_set":` + c.credential + `}`
			if got.status != http.StatusOK || got.body != want {
				t.Errorf("got %d %s\nwant 200 %s", got.status, got.body, want)
			}
			if v := got.header.Get("Content-Type"); v != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", v)
			}
			if strings.Contains(got.body, secretMarker) {
				t.Error("info shows the credential value")
			}
			expectProtocol(t, got)
			expectVersion(t, got, true)
			expectNoStore(t, got)
			if n := r.upstreamHits.Load(); n != 0 {
				t.Errorf("info made %d upstream calls", n)
			}
		})
	}
}

// TestContractUpstreamAnswerWrapped pins PLAN.md D7 and §4.3: any upstream
// status comes back as 200 with Relay-Upstream-Status, the body unchanged
// and only the allowed response headers. Upstream Relay-* headers never
// survive, so an upstream 401 cannot pose as a relay error.
func TestContractUpstreamAnswerWrapped(t *testing.T) {
	body := "{\"error\":\"invalid_client\",\"bytes\":\"\x00\xff\r\n\"}"
	for _, status := range []int{200, 302, 400, 401, 500, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			r := newRelay(t, relayOptions{upstream: func(w http.ResponseWriter, req *http.Request) {
				h := w.Header()
				h.Set("Content-Type", "application/json;charset=UTF-8")
				h.Set("Cache-Control", "no-store, max-age=0")
				h.Set("Pragma", "no-cache")
				h.Set("X-Content-Type-Options", "synthetic")
				h.Set("Set-Cookie", "session=synthetic")
				h.Set("Location", "https://elsewhere.example/")
				h.Set("WWW-Authenticate", `Basic realm="synthetic"`)
				h.Set("X-Upstream-Other", "synthetic")
				h.Set("Relay-Error", "invalid_token")
				h.Set("Relay-Protocol", "9")
				h.Set("Relay-Version", "6.6.6")
				h.Set("Relay-Upstream-Status", "299")
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
			}})
			got := r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), strings.NewReader("grant_type=synthetic"))
			if got.status != http.StatusOK {
				t.Errorf("status = %d, want 200", got.status)
			}
			if got.body != body {
				t.Errorf("body = %q, want %q unchanged", got.body, body)
			}
			if v := got.header.Values("Relay-Upstream-Status"); len(v) != 1 || v[0] != strconv.Itoa(status) {
				t.Errorf("Relay-Upstream-Status = %q, want %d", v, status)
			}
			expectProtocol(t, got)
			expectVersion(t, got, true)
			for name, want := range map[string]string{
				"Content-Type":           "application/json;charset=UTF-8",
				"Cache-Control":          "no-store, max-age=0", // the upstream's own value passes
				"Pragma":                 "no-cache",
				"X-Content-Type-Options": "nosniff",
			} {
				if v := got.header.Values(name); len(v) != 1 || v[0] != want {
					t.Errorf("%s = %q, want %q", name, v, want)
				}
			}
			wantNames := []string{"Cache-Control", "Content-Length", "Content-Type", "Date", "Pragma",
				"Relay-Protocol", "Relay-Upstream-Status", "Relay-Version", "X-Content-Type-Options"}
			if names := headerNames(got.header); !slices.Equal(names, wantNames) {
				t.Errorf("header names = %q, want %q", names, wantNames)
			}
		})
	}
}

// TestContractUpstreamWithoutContentType checks that the relay adds no
// Content-Type the upstream did not send: net/http would otherwise sniff
// one from the body. Without an upstream Cache-Control, the relay adds
// no-store, and nosniff stops a client from sniffing instead (SR-8).
func TestContractUpstreamWithoutContentType(t *testing.T) {
	const body = "<html><body>synthetic</body></html>"
	r := newRelay(t, relayOptions{upstream: func(w http.ResponseWriter, _ *http.Request) {
		w.Header()["Content-Type"] = nil
		_, _ = w.Write([]byte(body))
	}})
	got := r.do(t, "POST", "/oidc/token", bearer(validFIT(t)), nil)
	if got.status != http.StatusOK || got.body != body {
		t.Fatalf("got %d %q, want 200 %q", got.status, got.body, body)
	}
	if v, ok := got.header["Content-Type"]; ok {
		t.Errorf("Content-Type = %q, but the upstream sent none", v)
	}
	expectNoStore(t, got)
}

// TestContractTransportLevelRejections shows the requests net/http refuses
// before the relay's handler runs: they carry no relay headers (PLAN.md
// §4.3) and leave no request log line, and their content is not logged.
func TestContractTransportLevelRejections(t *testing.T) {
	r := newRelay(t, relayOptions{run: true})
	cases := []struct {
		name    string
		request string
		status  int
	}{
		// Server.MaxHeaderBytes is 16 KiB (PLAN.md R-1); net/http allows
		// 4 KiB of slack on top.
		{"header_over_limit", "GET /livez HTTP/1.1\r\nHost: relay.example\r\nX-Pad: " + secretMarker +
			strings.Repeat("a", 32<<10) + "\r\n\r\n", http.StatusRequestHeaderFieldsTooLarge},
		{"malformed_request_line", "NOT-HTTP " + secretMarker + "\r\n\r\n", http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := r.raw(t, "GET", c.request)
			if got.status != c.status {
				t.Errorf("status = %d, want %d", got.status, c.status)
			}
			for _, name := range []string{"Relay-Protocol", "Relay-Version", "Relay-Error"} {
				if v, ok := got.header[name]; ok {
					t.Errorf("%s = %q on a transport-level rejection", name, v)
				}
			}
		})
	}
	// A handled request after the rejections proves the log is written at all.
	expectHealthy(t, r.do(t, "GET", "/livez", nil, nil))
	lines := r.logs.waitRequests(t, 1)
	if len(lines) != 1 {
		t.Errorf("%d request log lines, want only the health check's", len(lines))
	}
	if strings.Contains(r.logs.String(), secretMarker) {
		t.Error("a rejected request's content reached the log")
	}
}

func headerNames(h http.Header) []string {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}
