// SPDX-License-Identifier: EUPL-1.2

package forward

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// The configuration errors below are fixed strings. Configuration errors
// never echo values (PLAN.md §8), so none of them includes its input.
var (
	errUpstreamURL    = errors.New("want an https origin with a host, without a path, userinfo, query or fragment")
	errHeaderExcluded = errors.New("header may not be configured")
	errCredential     = errors.New(`want "Name: value" with a non-empty value and no control characters`)
)

// MaxPort is the largest TCP port number, the upper bound of every port
// setting (PLAN.md §8).
const MaxPort = 65535

// LogMethod returns a fixed HTTP method or "other", so a caller-chosen
// method never reaches a log line (PLAN.md §10).
func LogMethod(m string) string {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return m
	}
	return "other"
}

// Upstream is the validated HTTPS origin in RELAY_UPSTREAM_URL (PLAN.md §5).
type Upstream struct{ origin string }

// ParseUpstream validates RELAY_UPSTREAM_URL. The scheme must be exactly
// "https"; the URL must have a host, a port from 1 to 65535 if it names one,
// and no userinfo, query or fragment. A root slash is normalized away;
// every other path, including an escaped root slash, is refused.
func ParseUpstream(s string) (Upstream, error) {
	if !strings.HasPrefix(s, "https://") || strings.ContainsAny(s, "?#") {
		return Upstream{}, errUpstreamURL
	}
	u, err := url.Parse(s)
	// A "%" in the host is an IPv6 zone, which url.Parse unescapes; joined
	// back into a URL it would no longer parse, so refuse it here.
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.Host == "" || u.Hostname() == "" || strings.Contains(u.Host, "%") || !ValidURLPort(u.Port()) {
		return Upstream{}, errUpstreamURL
	}
	if p := u.EscapedPath(); p != "" && p != "/" {
		return Upstream{}, errUpstreamURL
	}
	return Upstream{origin: "https://" + u.Host}, nil
}

// ValidURLPort reports whether p, a port as url.URL.Port returns it, is
// absent or from 1 to MaxPort. It is the one port rule for
// RELAY_UPSTREAM_URL and RELAY_JWKS_URL (PLAN.md §8). url.Parse checks only
// that a port is digits, and a port such as 0 or 84433 would pass startup
// and then fail every call, which points the operator at the network
// instead of the setting (R-13).
func ValidURLPort(p string) bool {
	if p == "" {
		return true
	}
	n, err := strconv.Atoi(p)
	return err == nil && n >= 1 && n <= MaxPort
}

// TARAOrigins are the two origins TARA serves its token endpoint on:
// production and the demo (test) environment (PLAN.md §5, SR-5).
var TARAOrigins = []string{"https://tara.ria.ee", "https://tara-test.ria.ee"}

// TARA reports whether u is exactly one of TARAOrigins. The comparison is
// byte for byte on the normalized origin, so an explicit port or another
// spelling of the host does not count as TARA.
func (u Upstream) TARA() bool {
	return slices.Contains(TARAOrigins, u.origin)
}

// URL returns the fixed TARA token URL. Nothing in a request can change its
// scheme, host, port or path (PLAN.md §5).
func (u Upstream) URL() string { return u.origin + TokenPath }

// String returns the configured origin, for the startup summary and the
// info endpoint.
func (u Upstream) String() string { return u.origin }

// credentialExcluded reports headers the credential setting may not supply:
// routing, framing, hop-by-hop, idempotency and relay-owned headers
// (PLAN.md §5). Authorization is allowed, since TARA's client_secret_basic
// needs it. name is canonical.
func credentialExcluded(name string) bool {
	switch name {
	case "Host", "Content-Length", "Forwarded", "Idempotency-Key", "X-Idempotency-Key":
		return true
	}
	return hopByHop(name) || hasPrefixFold(name, "X-Forwarded-") || hasPrefixFold(name, "Relay-")
}

// hopByHop reports the hop-by-hop headers of RFC 9110 §7.6.1 plus the
// legacy ones Go's proxy code also removes. Proxy-Authorization is among
// them: it authenticates to the next proxy and must never reach a provider.
// name is canonical.
func hopByHop(name string) bool {
	switch name {
	case "Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade":
		return true
	}
	return false
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// validToken reports whether s is an RFC 9110 token, the syntax of a header
// name.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// Secret holds the upstream credential value. Every formatting path prints a
// redaction marker, so the value cannot reach a log line or an error by
// accident (CONTRIBUTING.md, PLAN.md S-8). The value sits behind a pointer,
// so even fmt's error paths, which skip Format (%p, for one), print an
// address rather than the value.
type Secret struct{ v *string }

const redacted = "[redacted]"

func newSecret(v string) Secret { return Secret{v: &v} }

// Reveal returns the value. Only the code that sets the upstream header
// calls it.
func (s Secret) Reveal() string {
	if s.v == nil {
		return ""
	}
	return *s.v
}

// String returns the redaction marker to code that asks for a fmt.Stringer
// itself; fmt calls Format instead.
func (Secret) String() string { return redacted }

// GoString returns the redaction marker to code that asks for a
// fmt.GoStringer itself; fmt calls Format instead, even for %#v.
func (Secret) GoString() string { return redacted }

// LogValue returns the redaction marker to log/slog, which asks for it
// before any other method.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText returns the redaction marker to encoding/json, which slog's
// JSON handler uses for a struct that holds a Secret.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// Format writes the redaction marker for every verb fmt hands it, %#v, %d
// and %x included.
func (Secret) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, redacted) // a failed write to f is fmt's to report
}

// Credential is the header the relay adds to every upstream request
// (RELAY_UPSTREAM_AUTH, PLAN.md §5). It is set last, so a caller can never
// override it.
type Credential struct {
	Name  string // canonical
	Value Secret
}

// ParseCredential parses RELAY_UPSTREAM_AUTH, "Name: value". Optional
// whitespace around the value is removed, as in an HTTP header field
// (RFC 9110 §5.5). Control characters other than tab are refused, so a value
// can never inject a second header.
func ParseCredential(s string) (Credential, error) {
	name, value, ok := strings.Cut(s, ":")
	if !ok || !validToken(name) {
		return Credential{}, errCredential
	}
	c := textproto.CanonicalMIMEHeaderKey(name)
	if credentialExcluded(c) {
		return Credential{}, errHeaderExcluded
	}
	value = strings.Trim(value, " \t")
	if value == "" {
		return Credential{}, errCredential
	}
	for i := 0; i < len(value); i++ {
		if b := value[i]; (b < 0x20 && b != '\t') || b == 0x7f {
			return Credential{}, errCredential
		}
	}
	return Credential{Name: c, Value: newSecret(value)}, nil
}
