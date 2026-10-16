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
	errRoute          = errors.New(`want "METHOD /path"`)
	errRouteMethod    = errors.New("method must be GET, POST, PUT, PATCH or DELETE")
	errRoutePath      = errors.New("path is not an allowed absolute path")
	errRouteReserved  = errors.New("path is reserved for the relay")
	errRouteDuplicate = errors.New("duplicate route")
	errUpstreamURL    = errors.New("want an https URL with a host and an optional base path, without userinfo, query or fragment")
	errHeaderName     = errors.New("invalid header name")
	errHeaderExcluded = errors.New("header may not be configured")
	errHeaderDup      = errors.New("duplicate header")
	errCredential     = errors.New(`want "Name: value" with a non-empty value and no control characters`)
)

// MaxPort is the largest TCP port number, the upper bound of every port
// setting (PLAN.md §8).
const MaxPort = 65535

// Route is one allowed "METHOD /path" pair from RELAY_ROUTES (PLAN.md §8).
type Route struct {
	Method string
	Path   string
}

// String returns the route as configured. It is a configured constant, so it
// is safe as the route log field (PLAN.md §10).
func (r Route) String() string { return r.Method + " " + r.Path }

// routeMethod lists the methods a route may use. Logs show any other method as
// "other" (PLAN.md §10).
func routeMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// LogMethod returns m if it is a route method and "other" otherwise, so a
// caller-chosen method never reaches a log line (PLAN.md §10).
func LogMethod(m string) string {
	if routeMethod(m) {
		return m
	}
	return "other"
}

// ParseRoutes parses the items of RELAY_ROUTES. Each is exactly
// "METHOD /path" with one space.
func ParseRoutes(items []string) ([]Route, error) {
	routes := make([]Route, 0, len(items))
	for _, item := range items {
		method, path, ok := strings.Cut(item, " ")
		switch {
		case !ok:
			return nil, errRoute
		case !routeMethod(method):
			return nil, errRouteMethod
		case !ValidPath(path):
			return nil, errRoutePath
		case reservedPath(path):
			return nil, errRouteReserved
		}
		r := Route{Method: method, Path: path}
		if slices.Contains(routes, r) {
			return nil, errRouteDuplicate
		}
		routes = append(routes, r)
	}
	return routes, nil
}

// reservedPath reports the paths the relay answers itself (PLAN.md §4.1). A
// route that shadowed them would make the health checks or the info endpoint
// reach the upstream.
func reservedPath(p string) bool {
	return p == "/livez" || p == "/readyz" || p == "/relay" || strings.HasPrefix(p, "/relay/")
}

// ValidPath reports whether p is an absolute path the relay may configure as
// a route or a base path (PLAN.md §5). It allows only ASCII letters, digits
// and "-._~!$&'()*+;=:@/". Everything else is refused, notably
// percent-encoding (so no encoded slash or dot can exist), backslashes,
// non-ASCII bytes, "?", "#" and the comma that separates RELAY_ROUTES items.
// It also refuses "//", "..", and "." segments, so an upstream that
// normalizes paths cannot turn an allowed route into a different one.
//
// Requests are matched byte for byte against these validated paths, so a
// request target that breaks any of these rules can never match a route.
func ValidPath(p string) bool {
	if p == "" || p[0] != '/' || strings.Contains(p, "//") || strings.Contains(p, "..") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~!$&'()*+;=:@/", c) >= 0:
		default:
			return false
		}
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." {
			return false
		}
	}
	return true
}

// Upstream is the validated RELAY_UPSTREAM_URL: an https origin and an
// optional base path (PLAN.md §5).
type Upstream struct {
	origin   string // "https://host[:port]"
	basePath string // "" or a ValidPath without a trailing slash
}

// ParseUpstream validates RELAY_UPSTREAM_URL. The scheme must be exactly
// "https"; the URL must have a host, a port from 1 to 65535 if it names one,
// and no userinfo, query or fragment; the base path obeys ValidPath and has
// no trailing slash, except that "/" means no base path.
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
	// EscapedPath is the path as written. ValidPath refuses "%", so it equals
	// the decoded path, and characters such as "!" that url.Parse would
	// record in RawPath are judged by the same rule as route paths.
	base := u.EscapedPath()
	switch {
	case base == "" || base == "/":
		base = ""
	case strings.HasSuffix(base, "/") || !ValidPath(base):
		return Upstream{}, errUpstreamURL
	}
	return Upstream{origin: "https://" + u.Host, basePath: base}, nil
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

// URL returns the upstream URL for an allowed route path. The validated base
// path and route path are concatenated, never resolved as a URL reference,
// so nothing in a request can change the scheme, host or port (PLAN.md §5).
func (u Upstream) URL(routePath string) string { return u.origin + u.basePath + routePath }

// String returns the configured origin and base path, which contain no
// secret, for the startup summary and /relay/v1/info.
func (u Upstream) String() string { return u.origin + u.basePath }

// requestExcluded reports request headers that no allowlist may pass
// (PLAN.md §5): credentials, routing, framing, hop-by-hop, idempotency,
// tracing and relay-owned headers. name is canonical.
func requestExcluded(name string) bool {
	switch name {
	case "Authorization", "Host", "Content-Length", "Forwarded",
		"Idempotency-Key", "X-Idempotency-Key":
		return true
	}
	return hopByHop(name) || hasPrefixFold(name, "X-Forwarded-") ||
		hasPrefixFold(name, "X-Forge-Oauth-") || hasPrefixFold(name, "X-B3-") ||
		hasPrefixFold(name, "Relay-")
}

// responseExcluded reports response headers that no allowlist may pass
// (PLAN.md §5). The relay computes framing and owns the Relay-* headers, so
// an upstream can never impersonate a relay error. name is canonical.
func responseExcluded(name string) bool {
	return name == "Content-Length" || name == "Set-Cookie" || hopByHop(name) ||
		hasPrefixFold(name, "Relay-")
}

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

// ParseRequestHeaders validates RELAY_REQUEST_HEADERS and returns canonical
// names. The mandatory exclusions of PLAN.md §5 override the allowlist, so
// an excluded name is a startup error rather than silently dropped.
func ParseRequestHeaders(names []string) ([]string, error) {
	return parseHeaders(names, requestExcluded)
}

// ParseResponseHeaders validates RELAY_RESPONSE_HEADERS, as
// ParseRequestHeaders does for requests.
func ParseResponseHeaders(names []string) ([]string, error) {
	return parseHeaders(names, responseExcluded)
}

func parseHeaders(names []string, excluded func(string) bool) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !validToken(n) {
			return nil, errHeaderName
		}
		c := textproto.CanonicalMIMEHeaderKey(n)
		if excluded(c) {
			return nil, errHeaderExcluded
		}
		if slices.Contains(out, c) {
			return nil, errHeaderDup
		}
		out = append(out, c)
	}
	return out, nil
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
