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
	"slices"
	"strconv"
	"strings"
	"testing"
)

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

func TestParseUpstream(t *testing.T) {
	valid := []struct {
		name, raw, url, str string
	}{
		{"origin", "https://provider.example", "https://provider.example/oidc/token", "https://provider.example"},
		{"root_slash_normalized", "https://provider.example/", "https://provider.example/oidc/token", "https://provider.example"},
		{"port", "https://provider.example:8443", "https://provider.example:8443/oidc/token", "https://provider.example:8443"},
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
			if got := u.URL(); got != tt.url {
				t.Errorf("URL = %q, want %q", got, tt.url)
			}
			if got := u.String(); got != tt.str {
				t.Errorf("String = %q, want %q", got, tt.str)
			}
		})
	}

	invalid := map[string]string{
		"empty":                      "",
		"http":                       "http://provider.example",
		"uppercase_scheme":           "HTTPS://provider.example",
		"opaque":                     "https:provider.example",
		"scheme_relative":            "//provider.example",
		"no_scheme":                  "provider.example",
		"leading_space":              " https://provider.example",
		"no_host":                    "https://",
		"no_host_with_path":          "https:///oidc",
		"port_without_host":          "https://:8443",
		"bad_port":                   "https://provider.example:port",
		"port_zero":                  "https://provider.example:0",
		"port_above_65535":           "https://provider.example:65536",
		"port_beyond_int":            "https://provider.example:99999999999999999999",
		"ipv6_port_above_65535":      "https://[::1]:84433",
		"userinfo":                   "https://user@provider.example",
		"userinfo_with_password":     "https://user:" + secretMarker + "@provider.example",
		"backslash_authority":        "https://provider.example\\@attacker.example",
		"query":                      "https://provider.example?x=1",
		"empty_query":                "https://provider.example/?",
		"fragment":                   "https://provider.example#x",
		"empty_fragment":             "https://provider.example/#",
		"base_path":                  "https://provider.example/base",
		"token_path":                 "https://provider.example/oidc/token",
		"trailing_slash_base":        "https://provider.example/base/",
		"double_slash":               "https://provider.example//",
		"escaped_root_slash":         "https://provider.example/%2f",
		"escaped_slash_without_root": "https://provider.example%2f",
		"ipv6_zone":                  "https://[fe80::1%25en0]",
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
// from 1 to 65535, and exactly the fixed token path (PLAN.md §5, §8).
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
	raw := up.URL()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("ParseUpstream(%q) accepted, but its URL %q does not parse", s, raw)
	}
	if u.Scheme != "https" || u.User != nil || u.Host != configured.Host || u.RawQuery != "" ||
		u.ForceQuery || u.Fragment != "" || "https://"+u.Host+u.EscapedPath() != raw ||
		u.EscapedPath() != route || up.String() != "https://"+configured.Host ||
		configured.EscapedPath() != "" && configured.EscapedPath() != "/" {
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
