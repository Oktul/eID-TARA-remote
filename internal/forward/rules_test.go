// SPDX-License-Identifier: EUPL-1.2

package forward

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/textproto"
	"net/url"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestParseRoutes(t *testing.T) {
	t.Run("valid_routes_in_order", func(t *testing.T) {
		got, err := ParseRoutes([]string{
			"POST /oidc/token", "GET /oidc/jwks", "POST /oidc/jwks", "PUT /a", "PATCH /a",
			"DELETE /a", "POST /", "POST /relayed", "GET /livez/extra", "GET /.well-known/jwks.json",
		})
		want := []Route{
			{"POST", "/oidc/token"}, {"GET", "/oidc/jwks"}, {"POST", "/oidc/jwks"}, {"PUT", "/a"},
			{"PATCH", "/a"}, {"DELETE", "/a"}, {"POST", "/"}, {"POST", "/relayed"},
			{"GET", "/livez/extra"}, {"GET", "/.well-known/jwks.json"},
		}
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("ParseRoutes = %v, %v; want %v", got, err, want)
		}
	})
	t.Run("route_string_is_the_configured_form", func(t *testing.T) {
		if s := (Route{"POST", "/oidc/token"}).String(); s != "POST /oidc/token" {
			t.Errorf("String = %q", s)
		}
	})

	tests := []struct {
		name string
		item string
		want error
	}{
		{"empty_item", "", errRoute},
		{"method_only", "POST", errRoute},
		{"missing_space", "POST/oidc/token", errRoute},
		{"tab_separator", "POST\t/oidc/token", errRoute},
		{"lowercase_method", "post /oidc/token", errRouteMethod},
		{"empty_method", " /oidc/token", errRouteMethod},
		{"head_method", "HEAD /oidc/token", errRouteMethod},
		{"options_method", "OPTIONS /oidc/token", errRouteMethod},
		{"connect_method", "CONNECT /oidc/token", errRouteMethod},
		{"trace_method", "TRACE /oidc/token", errRouteMethod},
		{"two_spaces", "POST  /oidc/token", errRoutePath},
		{"trailing_space", "POST /oidc/token ", errRoutePath},
		{"relative_path", "POST oidc/token", errRoutePath},
		{"query", "POST /oidc/token?x=1", errRoutePath},
		{"encoded_slash", "POST /oidc%2Ftoken", errRoutePath},
		{"dot_dot", "POST /oidc/../token", errRoutePath},
		{"reserved_livez", "GET /livez", errRouteReserved},
		{"reserved_readyz", "GET /readyz", errRouteReserved},
		{"reserved_livez_other_method", "POST /livez", errRouteReserved},
		{"reserved_relay", "GET /relay", errRouteReserved},
		{"reserved_relay_slash", "GET /relay/", errRouteReserved},
		{"reserved_relay_info", "GET /relay/v1/info", errRouteReserved},
		{"reserved_under_relay", "POST /relay/v2/token", errRouteReserved},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRoutes([]string{"POST /oidc/token", tt.item})
			if err != tt.want || got != nil {
				t.Errorf("ParseRoutes = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
	t.Run("duplicate_route", func(t *testing.T) {
		if _, err := ParseRoutes([]string{"POST /oidc/token", "GET /a", "POST /oidc/token"}); err != errRouteDuplicate {
			t.Errorf("err = %v, want %v", err, errRouteDuplicate)
		}
	})
	t.Run("error_never_echoes_input", func(t *testing.T) {
		for _, item := range []string{secretMarker, "POST /" + secretMarker + "?", "GET /relay/" + secretMarker} {
			if _, err := ParseRoutes([]string{item}); err == nil || strings.Contains(err.Error(), secretMarker) {
				t.Errorf("ParseRoutes(%q) err = %v", item, err)
			}
		}
	})
}

// FuzzParseRoutes checks that a RELAY_ROUTES list, split at its commas, is
// accepted only as distinct routes that keep each item byte for byte, with a
// route method and a ValidPath the relay does not answer itself (PLAN.md
// §4.1, §5). A rejection is a fixed error, so it never echoes the input
// (PLAN.md §8). Its seeds are in testdata/fuzz/FuzzParseRoutes.
func FuzzParseRoutes(f *testing.F) {
	fixed := []error{errRoute, errRouteMethod, errRoutePath, errRouteReserved, errRouteDuplicate}
	f.Fuzz(func(t *testing.T, list string) {
		items := strings.Split(list, ",")
		routes, err := ParseRoutes(items)
		if err != nil {
			if !slices.Contains(fixed, err) || routes != nil {
				t.Fatalf("ParseRoutes(%q) = %v, %v; want a fixed error and no routes", items, routes, err)
			}
			return
		}
		if len(routes) != len(items) {
			t.Fatalf("ParseRoutes(%q) = %v; want one route per item", items, routes)
		}
		for i, r := range routes {
			if r.String() != items[i] || !routeMethod(r.Method) || !ValidPath(r.Path) ||
				reservedPath(r.Path) || slices.Contains(routes[:i], r) {
				t.Fatalf("ParseRoutes(%q) accepted item %q as %#v", items, items[i], r)
			}
		}
	})
}

func TestLogMethod(t *testing.T) {
	for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		if got := LogMethod(m); got != m {
			t.Errorf("LogMethod(%q) = %q", m, got)
		}
	}
	for _, m := range []string{"HEAD", "OPTIONS", "CONNECT", "TRACE", "get", "", "PROPFIND", secretMarker} {
		if got := LogMethod(m); got != "other" {
			t.Errorf("LogMethod(%q) = %q, want other", m, got)
		}
	}
}

func TestValidPath(t *testing.T) {
	valid := []string{
		"/", "/oidc/token", "/oidc/token/", "/a.b", "/.well-known/jwks.json", "/a-b_c~d",
		"/a!$&'()*+;=:@b", "/A/Z/0/9",
	}
	for _, p := range valid {
		if !ValidPath(p) {
			t.Errorf("ValidPath(%q) = false, want true", p)
		}
	}
	invalid := map[string]string{
		"empty":                "",
		"relative":             "oidc/token",
		"asterisk":             "*",
		"absolute_url":         "https://provider.example/oidc/token",
		"double_slash_start":   "//oidc/token",
		"double_slash_inside":  "/oidc//token",
		"dot_dot_segment":      "/oidc/../token",
		"dot_dot_end":          "/oidc/..",
		"dot_dot_in_name":      "/oidc..token",
		"dot_segment":          "/oidc/./token",
		"dot_segment_end":      "/oidc/.",
		"dot_only":             "/.",
		"encoded_slash":        "/oidc%2Ftoken",
		"encoded_slash_lower":  "/oidc%2ftoken",
		"encoded_dot":          "/%2e/token",
		"encoded_dot_dot":      "/%2E%2E/token",
		"encoded_space":        "/a%20b",
		"backslash":            "/oidc\\token",
		"non_ascii":            "/tökén",
		"non_ascii_lookalike":  "/oidc∕token",
		"nul":                  "/oidc\x00",
		"del":                  "/oidc\x7f",
		"space":                "/oidc token",
		"tab":                  "/oidc\ttoken",
		"crlf":                 "/oidc\r\ntoken",
		"query":                "/oidc/token?x",
		"fragment":             "/oidc/token#x",
		"comma":                "/oidc,token",
		"quote":                "/oidc\"token",
		"angle_brackets":       "/<token>",
		"brackets":             "/[token]",
		"braces":               "/{token}",
		"pipe_caret_backquote": "/a|b^c`d",
	}
	for name, p := range invalid {
		t.Run(name, func(t *testing.T) {
			if ValidPath(p) {
				t.Errorf("ValidPath(%q) = true, want false", p)
			}
		})
	}
}

func TestParseUpstream(t *testing.T) {
	valid := []struct {
		name, raw, url, str string
	}{
		{"origin", "https://provider.example", "https://provider.example/oidc/token", "https://provider.example"},
		{"root_path_means_no_base", "https://provider.example/", "https://provider.example/oidc/token", "https://provider.example"},
		{"base_path", "https://provider.example/base", "https://provider.example/base/oidc/token", "https://provider.example/base"},
		{"port_and_nested_base", "https://provider.example:8443/a/b", "https://provider.example:8443/a/b/oidc/token", "https://provider.example:8443/a/b"},
		{"ipv6_literal", "https://[::1]:8443", "https://[::1]:8443/oidc/token", "https://[::1]:8443"},
		{"lowest_port", "https://provider.example:1", "https://provider.example:1/oidc/token", "https://provider.example:1"},
		{"highest_port", "https://provider.example:65535", "https://provider.example:65535/oidc/token", "https://provider.example:65535"},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			u, err := ParseUpstream(tt.raw)
			if err != nil {
				t.Fatalf("ParseUpstream(%q): %v", tt.raw, err)
			}
			if got := u.URL("/oidc/token"); got != tt.url {
				t.Errorf("URL = %q, want %q", got, tt.url)
			}
			if got := u.String(); got != tt.str {
				t.Errorf("String = %q, want %q", got, tt.str)
			}
		})
	}

	invalid := map[string]string{
		"empty":                    "",
		"http":                     "http://provider.example",
		"uppercase_scheme":         "HTTPS://provider.example",
		"opaque":                   "https:provider.example",
		"scheme_relative":          "//provider.example",
		"no_scheme":                "provider.example",
		"leading_space":            " https://provider.example",
		"no_host":                  "https://",
		"no_host_with_path":        "https:///oidc",
		"port_without_host":        "https://:8443",
		"bad_port":                 "https://provider.example:port",
		"port_zero":                "https://provider.example:0",
		"port_above_65535":         "https://provider.example:65536",
		"port_beyond_int":          "https://provider.example:99999999999999999999",
		"ipv6_port_above_65535":    "https://[::1]:84433",
		"userinfo":                 "https://user@provider.example",
		"userinfo_with_password":   "https://user:" + secretMarker + "@provider.example",
		"backslash_authority":      "https://provider.example\\@attacker.example",
		"query":                    "https://provider.example?x=1",
		"empty_query":              "https://provider.example/?",
		"fragment":                 "https://provider.example#x",
		"empty_fragment":           "https://provider.example/#",
		"trailing_slash_base":      "https://provider.example/base/",
		"double_slash_base":        "https://provider.example//base",
		"double_slash_inside_base": "https://provider.example/a//b",
		"dot_dot_base":             "https://provider.example/a/../b",
		"dot_base":                 "https://provider.example/a/./b",
		"encoded_slash_base":       "https://provider.example/a%2Fb",
		"encoded_letter_base":      "https://provider.example/a%41",
		"encoded_space_base":       "https://provider.example/a%20b",
		"space_base":               "https://provider.example/a b",
		"non_ascii_base":           "https://provider.example/é",
		"comma_base":               "https://provider.example/a,b",
	}
	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			u, err := ParseUpstream(raw)
			if err != errUpstreamURL || u != (Upstream{}) {
				t.Errorf("ParseUpstream(%q) = %v, %v; want %v", raw, u, err, errUpstreamURL)
			}
		})
	}
}

// checkUpstreamURL fails unless an accepted RELAY_UPSTREAM_URL s yields a
// request URL on exactly the https host that s names, with a port, if any,
// from 1 to 65535, the base path and the route path joined unchanged and
// nothing after them (PLAN.md §5, §8).
func checkUpstreamURL(t *testing.T, s string) {
	t.Helper()
	up, err := ParseUpstream(s)
	if err != nil {
		return
	}
	configured, err := url.Parse(s)
	if err != nil {
		t.Fatalf("ParseUpstream(%q) accepted a URL that does not parse", s)
	}
	const route = "/oidc/token"
	raw := up.URL(route)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("ParseUpstream(%q) accepted, but its URL %q does not parse", s, raw)
	}
	if u.Scheme != "https" || u.User != nil || u.Host != configured.Host || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || "https://"+u.Host+u.EscapedPath() != raw ||
		!strings.HasSuffix(u.EscapedPath(), route) {
		t.Fatalf("ParseUpstream(%q) accepted, but its URL %q parses as %#v", s, raw, u)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			t.Fatalf("ParseUpstream(%q) accepted port %q", s, p)
		}
	}
}

// FuzzParseUpstream runs checkUpstreamURL on arbitrary settings. Its seeds,
// named after the trick each tries, are in testdata/fuzz/FuzzParseUpstream.
func FuzzParseUpstream(f *testing.F) {
	f.Fuzz(checkUpstreamURL)
}

func TestParseUpstreamZoneYieldsUsableURL(t *testing.T) {
	checkUpstreamURL(t, "https://[fe80::1%25en0]")
}

// FuzzValidPath checks that an allowed path means the same to every parser
// it meets: Go's URL parser keeps it, the request line carries it unchanged
// and path cleaning cannot turn it into another path (PLAN.md §5). Its seeds
// are in testdata/fuzz/FuzzValidPath.
func FuzzValidPath(f *testing.F) {
	f.Fuzz(func(t *testing.T, p string) {
		if !ValidPath(p) {
			return
		}
		u, err := url.Parse("https://provider.example" + p)
		if err != nil || u.Host != "provider.example" || u.Path != p || u.EscapedPath() != p ||
			u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			t.Fatalf("ValidPath(%q), but URL parsing changes it: %#v, %v", p, u, err)
		}
		if c := path.Clean(p); c != p && c+"/" != p {
			t.Fatalf("ValidPath(%q), but it cleans to %q", p, c)
		}
	})
}

// responseExclusions lists every name PLAN.md §5 bans from the response
// allowlist, in several spellings.
var (
	responseExclusions = []string{
		"Content-Length", "content-length", "Set-Cookie", "set-cookie", "SET-COOKIE",
		"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
		"Relay-Error", "relay-protocol", "Relay-Version", "Relay-Upstream-Status", "RELAY-ANYTHING",
	}
	// invalidHeaderNames are not RFC 9110 tokens; each case is named after
	// what breaks the token syntax.
	invalidHeaderNames = []struct{ name, header string }{
		{"empty", ""},
		{"space_inside", "Content Type"},
		{"colon", "Content-Type:"},
		{"leading_space", " Accept"},
		{"trailing_space", "Accept "},
		{"nul", "X\x00"},
		{"crlf", "X\r\nY"},
		{"non_ascii", "Contént"},
		{"parentheses", "(x)"},
		{"comma", "a,b"},
		{"slash", "a/b"},
		{"at_sign", "a@b"},
		{"equals_sign", "a=b"},
		{"double_quote", "a\"b"},
		{"brackets", "a[b]"},
	}
)

func TestParseResponseHeaders(t *testing.T) {
	t.Run("canonical_names", func(t *testing.T) {
		got, err := ParseResponseHeaders([]string{"content-type", "cache-control", "PRAGMA", "www-authenticate"})
		if want := []string{"Content-Type", "Cache-Control", "Pragma", "Www-Authenticate"}; err != nil || !slices.Equal(got, want) {
			t.Errorf("ParseResponseHeaders = %v, %v; want %v", got, err, want)
		}
	})
	t.Run("exclusions_do_not_overmatch", func(t *testing.T) {
		names := []string{"Relayed", "Content-Length-Hint", "Set-Cookie2", "Upgrade-Insecure-Requests"}
		if _, err := ParseResponseHeaders(names); err != nil {
			t.Errorf("ParseResponseHeaders(%q): %v", names, err)
		}
	})
	for _, name := range responseExclusions {
		t.Run("excluded_"+name, func(t *testing.T) {
			if got, err := ParseResponseHeaders([]string{"Content-Type", name}); err != errHeaderExcluded || got != nil {
				t.Errorf("ParseResponseHeaders(%q) = %v, %v; want %v", name, got, err, errHeaderExcluded)
			}
		})
	}
	for _, tt := range invalidHeaderNames {
		t.Run("invalid_name_"+tt.name, func(t *testing.T) {
			if _, err := ParseResponseHeaders([]string{tt.header}); err != errHeaderName {
				t.Errorf("ParseResponseHeaders(%q) err = %v, want %v", tt.header, err, errHeaderName)
			}
		})
	}
	t.Run("duplicate_in_any_case", func(t *testing.T) {
		if _, err := ParseResponseHeaders([]string{"Pragma", "PRAGMA"}); err != errHeaderDup {
			t.Errorf("err = %v, want %v", err, errHeaderDup)
		}
	})
}

func TestParseCredential(t *testing.T) {
	valid := []struct {
		name, raw         string
		wantName, wantVal string
	}{
		{"basic_authorization", "Authorization: Basic c3ludGhldGljOnRlc3Q=", "Authorization", "Basic c3ludGhldGljOnRlc3Q="},
		{"name_canonicalized_no_space", "authorization:Basic x", "Authorization", "Basic x"},
		{"surrounding_ows_removed", "X-Api-Key: 	 value 	", "X-Api-Key", "value"},
		{"inner_tab_and_space_kept", "X-Api-Key: a	b c", "X-Api-Key", "a	b c"},
		{"colon_in_value", "X-Api-Key: a:b", "X-Api-Key", "a:b"},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredential(tt.raw)
			if err != nil || got.Name != tt.wantName || got.Value.Reveal() != tt.wantVal {
				t.Errorf("ParseCredential = %q, %q, %v; want %q, %q", got.Name, got.Value.Reveal(), err, tt.wantName, tt.wantVal)
			}
		})
	}

	invalid := []struct {
		name, raw string
		want      error
	}{
		{"empty", "", errCredential},
		{"no_colon", "Authorization Basic x", errCredential},
		{"name_only", "Authorization", errCredential},
		{"empty_name", ": x", errCredential},
		{"space_in_name", "X Api: x", errCredential},
		{"space_before_colon", "X-Api-Key : x", errCredential},
		{"leading_space", " X-Api-Key: x", errCredential},
		{"non_ascii_name", "Contént: x", errCredential},
		{"empty_value", "X-Api-Key:", errCredential},
		{"blank_value", "X-Api-Key: \t ", errCredential},
		{"cr_in_value", "X-Api-Key: a\rb", errCredential},
		{"lf_in_value", "X-Api-Key: a\nb", errCredential},
		{"header_injection", "X-Api-Key: a\r\nHost: attacker.example", errCredential},
		{"trailing_crlf", "X-Api-Key: a\r\n", errCredential},
		{"nul_in_value", "X-Api-Key: a\x00b", errCredential},
		{"del_in_value", "X-Api-Key: a\x7fb", errCredential},
		{"other_control_in_value", "X-Api-Key: a\x01b", errCredential},
		{"unit_separator_in_value", "X-Api-Key: a\x1fb", errCredential},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := ParseCredential(tt.raw); err != tt.want || got != (Credential{}) {
				t.Errorf("ParseCredential(%q) = %v, %v; want %v", tt.raw, got, err, tt.want)
			}
		})
	}
	// Authorization is the one credential name the request exclusions ban
	// that the credential may use (PLAN.md §5).
	for _, name := range []string{
		"Host", "host", "Content-Length", "Forwarded", "Idempotency-Key", "X-Idempotency-Key",
		"x-idempotency-key", "Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "X-Forwarded-For",
		"x-forwarded-host", "Relay-Error", "relay-anything",
	} {
		t.Run("excluded_"+name, func(t *testing.T) {
			if got, err := ParseCredential(name + ": x"); err != errHeaderExcluded || got != (Credential{}) {
				t.Errorf("ParseCredential(%q) = %v, %v; want %v", name, got, err, errHeaderExcluded)
			}
		})
	}
	t.Run("error_never_echoes_value", func(t *testing.T) {
		for _, raw := range []string{"X-Api-Key: " + secretMarker + "\n", "Host: " + secretMarker, secretMarker} {
			if _, err := ParseCredential(raw); err == nil || strings.Contains(err.Error(), secretMarker) {
				t.Errorf("ParseCredential err = %v", err)
			}
		}
	})
}

// FuzzParseCredential checks that an accepted RELAY_UPSTREAM_AUTH has a
// canonical name the credential may use and that Go's own header parser
// reads it as exactly that one field, so no value can inject a second header
// or carry a byte a header may not hold (PLAN.md §5). A rejection is a fixed
// error, so it never echoes the value (PLAN.md §8). Its seeds are in
// testdata/fuzz/FuzzParseCredential.
func FuzzParseCredential(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCredential(s)
		if err != nil {
			if (err != errCredential && err != errHeaderExcluded) || c != (Credential{}) {
				t.Fatalf("ParseCredential(%q) = %v, %v; want a fixed error and no credential", s, c, err)
			}
			return
		}
		if c.Name != textproto.CanonicalMIMEHeaderKey(c.Name) || credentialExcluded(c.Name) {
			t.Fatalf("ParseCredential(%q) accepted the name %q", s, c.Name)
		}
		h, err := textproto.NewReader(bufio.NewReader(strings.NewReader(s + "\r\n\r\n"))).ReadMIMEHeader()
		if err != nil || len(h) != 1 || !slices.Equal(h[c.Name], []string{c.Value.Reveal()}) {
			t.Fatalf("ParseCredential(%q) = %q: %q, but Go's header parser reads %q, %v",
				s, c.Name, c.Value.Reveal(), h, err)
		}
	})
}

// TestSecretNeverPrints covers the formatting paths a log line or an error
// could take (PLAN.md S-8, CONTRIBUTING.md "Secrets cannot print").
func TestSecretNeverPrints(t *testing.T) {
	s := newSecret(secretMarker)
	c := Credential{Name: "Authorization", Value: s}
	out := map[string]string{
		"Sprint":        fmt.Sprint(s),
		"Sprintln":      fmt.Sprintln(s, c, &c),
		"Errorf":        fmt.Errorf("upstream auth %v: %s", s, c).Error(),
		"slice":         fmt.Sprintf("%v", []Secret{s}),
		"map":           fmt.Sprintf("%v", map[string]Secret{"k": s}),
		"interface":     fmt.Sprintf("%v", any(s)),
		"embedded":      fmt.Sprintf("%+v", struct{ Credential }{c}),
		"string_method": s.String(),
		"gostring":      s.GoString(),
		"log_value":     s.LogValue().String(),
	}
	// The verb is a variable so vet does not object to verbs that do not
	// suit a string; fmt still calls Format for every one of them.
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%d", "%x", "%X", "%q", "%10s", "%-10v", "%.3s", "%t"} {
		out["secret "+verb] = fmt.Sprintf(verb, s)
		out["credential "+verb] = fmt.Sprintf(verb, c)
		out["pointer "+verb] = fmt.Sprintf(verb, &c)
	}
	var text, js bytes.Buffer
	slog.New(slog.NewTextHandler(&text, nil)).Info("m", "secret", s, "credential", c, "pointer", &c)
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "secret", s, slog.Any("any", s))
	out["slog text"] = text.String()
	out["slog json"] = js.String()

	for name, got := range out {
		if strings.Contains(got, secretMarker) || !strings.Contains(got, "[redacted]") {
			t.Errorf("%s printed %q", name, got)
		}
	}
}

func TestSecretNotInJSON(t *testing.T) {
	c := Credential{Name: "Authorization", Value: newSecret(secretMarker)}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var js bytes.Buffer
	slog.New(slog.NewJSONHandler(&js, nil)).Info("m", "credential", c, "pointer", &c)
	for name, got := range map[string]string{"json.Marshal": string(b), "slog json": js.String()} {
		if strings.Contains(got, secretMarker) {
			t.Errorf("%s printed %q", name, got)
		}
	}
}

func TestSecretNotPrintedByPointerVerb(t *testing.T) {
	s := newSecret(secretMarker)
	// The verbs come from a slice so vet and staticcheck accept the
	// deliberate misuse: fmt's error paths skip Format and must still not
	// reach the value.
	for _, verb := range []string{"%p", "%z", "%!"} {
		for name, got := range map[string]string{
			"secret":     fmt.Sprintf(verb, s),
			"credential": fmt.Sprintf(verb, Credential{Name: "Authorization", Value: s}),
		} {
			if strings.Contains(got, secretMarker) {
				t.Errorf("%s with %s printed %q", name, verb, got)
			}
		}
	}
}
