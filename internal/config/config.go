// SPDX-License-Identifier: EUPL-1.2

// Package config reads the relay's settings once at startup and checks all of
// them before the listener opens (PLAN.md §8, §6 R-13).
//
// Any setting may instead come from the file named by <NAME>_FILE, for the
// secret mechanisms of Docker and Kubernetes. Errors name the setting and
// never its value, a file's path or its contents: the credential travels
// through the same mechanism, and startup output ends up in shared logs
// (PLAN.md §8, §10).
package config

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"eid-forge-remote/internal/forward"
)

// Limits and the JWKS default of PLAN.md §4.5, §6 and §8.
const (
	// MaxSettingFileBytes bounds a <NAME>_FILE read, so a wrong path (a log
	// file, a device) cannot exhaust memory at startup.
	MaxSettingFileBytes = 64 << 10
	// MaxCAFileBytes bounds the read of RELAY_UPSTREAM_CA_FILE, which holds
	// a PEM bundle rather than a single value.
	MaxCAFileBytes = 1 << 20
	// MaxPayloadBudget caps RELAY_MAX_CONCURRENT × (RELAY_MAX_REQUEST_BYTES +
	// RELAY_MAX_RESPONSE_BYTES), the body memory the relay may hold at once
	// (PLAN.md §6, R-4, R-12).
	MaxPayloadBudget = 64 << 20
	// MaxClockSkew caps RELAY_CLOCK_SKEW. FITs live about 25 s, so a larger
	// skew would in effect switch the exp and nbf checks off; a clock that
	// far off needs fixing instead (PLAN.md §8, 2026-10-16).
	MaxClockSkew = time.Minute
	// DefaultJWKSURL is Atlassian's Forge signing-key set (PLAN.md §4.5).
	DefaultJWKSURL = "https://forge.cdn.prod.atlassian-dev.net/.well-known/jwks.json"
)

// The defaults of PLAN.md §8. They go through the same parsers as operator
// input, so a default can never bypass a rule.
const (
	defaultRequestHeaders   = "Content-Type,Accept"
	defaultResponseHeaders  = "Content-Type,Cache-Control,Pragma"
	defaultPort             = "8080"
	defaultUpstreamTimeout  = "10s"
	defaultMaxRequestBytes  = "65536"
	defaultMaxResponseBytes = "65536"
	defaultMaxConcurrent    = "50"
	defaultClockSkew        = "10s"
	defaultJWKSRefresh      = "6h"
	defaultJWKSMaxAge       = "24h"
	defaultShutdownGrace    = "15s"
	defaultLogLevel         = "info"
)

const (
	settingPrefix = "RELAY_"
	fileSuffix    = "_FILE"

	// appIDPrefix and uuidLen describe the app ARI that FITs carry in aud.
	appIDPrefix = "ari:cloud:ecosystem::app/"
	uuidLen     = 36
	// maxIDBytes bounds each site, environment and installation ID.
	maxIDBytes = 256

	// maxReportedNameBytes bounds an unknown name that Load reports as is;
	// the longest known name with _FILE has 29 bytes.
	maxReportedNameBytes = 64
	// malformedName replaces an unknown name that cannot be a setting name.
	malformedName = "RELAY_* (malformed name)"
)

// WriteTimeoutMargin is what the server adds to RELAY_UPSTREAM_TIMEOUT for
// its WriteTimeout, so a slow upstream answer can still be written
// (PLAN.md §6 R-1). Load rejects a timeout whose sum would overflow.
const WriteTimeoutMargin = 5 * time.Second

// Config is the validated configuration, one field per setting of PLAN.md
// §8. Do not print a Config whole: it holds the credential.
// Summary lists the settings safely.
type Config struct {
	AppID           string   // RELAY_APP_ID
	EnvironmentID   string   // RELAY_ENVIRONMENT_ID
	CloudIDs        []string // RELAY_CLOUD_IDS
	InstallationIDs []string // RELAY_INSTALLATION_IDS; nil: any installation

	Upstream   forward.Upstream    // RELAY_UPSTREAM_URL
	Routes     []forward.Route     // RELAY_ROUTES
	Credential *forward.Credential // RELAY_UPSTREAM_AUTH; nil: no credential header
	// CredentialFromFile records that the credential came from
	// RELAY_UPSTREAM_AUTH_FILE, for the startup summary (PLAN.md §10).
	CredentialFromFile bool
	UpstreamCAs        *x509.CertPool // RELAY_UPSTREAM_CA_FILE; nil: system roots
	RequestHeaders     []string       // RELAY_REQUEST_HEADERS, canonical names
	ResponseHeaders    []string       // RELAY_RESPONSE_HEADERS, canonical names

	Port int // RELAY_PORT

	UpstreamTimeout  time.Duration // RELAY_UPSTREAM_TIMEOUT
	MaxRequestBytes  int64         // RELAY_MAX_REQUEST_BYTES
	MaxResponseBytes int64         // RELAY_MAX_RESPONSE_BYTES
	MaxConcurrent    int           // RELAY_MAX_CONCURRENT
	ClockSkew        time.Duration // RELAY_CLOCK_SKEW

	JWKSURL       string        // RELAY_JWKS_URL
	JWKSRefresh   time.Duration // RELAY_JWKS_REFRESH
	JWKSMaxAge    time.Duration // RELAY_JWKS_MAX_AGE
	ShutdownGrace time.Duration // RELAY_SHUTDOWN_GRACE
	LogLevel      slog.Level    // RELAY_LOG_LEVEL
}

// Error is a configuration error. It names the setting and says what is
// wrong, never the value, so it is safe to print at startup (PLAN.md §8,
// R-13). Setting is a variable name such as RELAY_PORT or RELAY_PORT_FILE,
// or a comma-separated list for a rule that spans several settings.
type Error struct {
	Setting string
	Reason  string
}

// Error returns "<Setting>: <Reason>".
func (e *Error) Error() string { return e.Setting + ": " + e.Reason }

func fail(setting, reason string) error { return &Error{Setting: setting, Reason: reason} }

// Load reads and validates the settings in environ, which has the
// "NAME=value" form of os.Environ. Settings are checked in the order of the
// PLAN.md §8 table, and the first failure is returned as an *Error.
//
// Load also returns the sorted names of unknown RELAY_* variables, even when
// it fails, so the caller can warn about them (PLAN.md §8): a mistyped
// required setting is otherwise reported only as missing. A name that cannot
// be a setting name is reported once, as "RELAY_* (malformed name)".
func Load(environ []string) (*Config, []string, error) {
	env, unknown := parseEnviron(environ)
	c, err := env.load()
	if err != nil {
		return nil, unknown, err
	}
	return c, unknown, nil
}

// HealthPort returns the port the relay listens on, for `relay healthcheck`
// (PLAN.md §7, O-3). It reads only RELAY_PORT (possibly through _FILE), so
// the probe does not depend on the rest of the configuration.
func HealthPort(environ []string) (int, error) {
	env, _ := parseEnviron(environ)
	return env.port()
}

// Summary returns the startup summary of PLAN.md §10 (O-5): one attribute
// per setting, keyed by its name, in table order. The credential appears only
// as "set (from file)", "set" or "not set" (S-8); file settings show only
// whether they are set.
func (c *Config) Summary() []slog.Attr {
	routes := make([]string, len(c.Routes))
	for i, r := range c.Routes {
		routes[i] = r.String()
	}
	installations := "any"
	if c.InstallationIDs != nil {
		installations = strings.Join(c.InstallationIDs, ",")
	}
	credential := "not set"
	switch {
	case c.Credential != nil && c.CredentialFromFile:
		credential = "set (from file)"
	case c.Credential != nil:
		credential = "set"
	}
	return []slog.Attr{
		slog.String("RELAY_APP_ID", c.AppID),
		slog.String("RELAY_ENVIRONMENT_ID", c.EnvironmentID),
		slog.String("RELAY_CLOUD_IDS", strings.Join(c.CloudIDs, ",")),
		slog.String("RELAY_UPSTREAM_URL", c.Upstream.String()),
		slog.String("RELAY_ROUTES", strings.Join(routes, ",")),
		slog.String("RELAY_UPSTREAM_AUTH", credential),
		slog.String("RELAY_UPSTREAM_CA_FILE", state(c.UpstreamCAs != nil, "system bundle")),
		slog.String("RELAY_INSTALLATION_IDS", installations),
		slog.String("RELAY_REQUEST_HEADERS", strings.Join(c.RequestHeaders, ",")),
		slog.String("RELAY_RESPONSE_HEADERS", strings.Join(c.ResponseHeaders, ",")),
		slog.Int("RELAY_PORT", c.Port),
		slog.String("RELAY_UPSTREAM_TIMEOUT", c.UpstreamTimeout.String()),
		slog.Int64("RELAY_MAX_REQUEST_BYTES", c.MaxRequestBytes),
		slog.Int64("RELAY_MAX_RESPONSE_BYTES", c.MaxResponseBytes),
		slog.Int("RELAY_MAX_CONCURRENT", c.MaxConcurrent),
		slog.String("RELAY_CLOCK_SKEW", c.ClockSkew.String()),
		slog.String("RELAY_JWKS_URL", c.JWKSURL),
		slog.String("RELAY_JWKS_REFRESH", c.JWKSRefresh.String()),
		slog.String("RELAY_JWKS_MAX_AGE", c.JWKSMaxAge.String()),
		slog.String("RELAY_SHUTDOWN_GRACE", c.ShutdownGrace.String()),
		slog.String("RELAY_LOG_LEVEL", strings.ToLower(c.LogLevel.String())),
	}
}

// state returns "set" or, for a setting that is not set, the summary of its
// default.
func state(set bool, unset string) string {
	if set {
		return "set"
	}
	return unset
}

// known reports the 21 settings of the PLAN.md §8 table. Any other RELAY_*
// variable, other than a known name plus _FILE, is reported as unknown so
// that a typo does not go unnoticed.
func known(name string) bool {
	switch name {
	case "RELAY_APP_ID", "RELAY_ENVIRONMENT_ID", "RELAY_CLOUD_IDS",
		"RELAY_UPSTREAM_URL", "RELAY_ROUTES", "RELAY_UPSTREAM_AUTH",
		"RELAY_UPSTREAM_CA_FILE", "RELAY_INSTALLATION_IDS",
		"RELAY_REQUEST_HEADERS", "RELAY_RESPONSE_HEADERS", "RELAY_PORT",
		"RELAY_UPSTREAM_TIMEOUT",
		"RELAY_MAX_REQUEST_BYTES", "RELAY_MAX_RESPONSE_BYTES",
		"RELAY_MAX_CONCURRENT", "RELAY_CLOCK_SKEW", "RELAY_JWKS_URL",
		"RELAY_JWKS_REFRESH", "RELAY_JWKS_MAX_AGE", "RELAY_SHUTDOWN_GRACE",
		"RELAY_LOG_LEVEL":
		return true
	}
	return false
}

// environment holds the RELAY_* variables of the process environment.
type environment struct {
	vars     map[string]string
	repeated map[string]bool // names that appear more than once
}

func parseEnviron(environ []string) (environment, []string) {
	env := environment{vars: map[string]string{}, repeated: map[string]bool{}}
	var unknown []string
	for _, kv := range environ {
		// Entries without "=" or with an empty name, such as the Windows
		// per-drive directories "=C:=C:\...", fail the prefix test.
		name, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, settingPrefix) {
			continue
		}
		if _, seen := env.vars[name]; seen {
			// os.Environ never repeats a name, but a hand-built slice can.
			// Picking one of the values would be a guess.
			env.repeated[name] = true
			continue
		}
		env.vars[name] = v
		if !known(name) && !known(strings.TrimSuffix(name, fileSuffix)) {
			unknown = append(unknown, reportedName(name))
		}
	}
	slices.Sort(unknown)
	return env, slices.Compact(unknown)
}

// reportedName returns name, which starts with RELAY_, if it has the shape of
// a setting name, and malformedName otherwise. The caller logs unknown names,
// and a ':' typed for '=' puts the value into the name: the entry
// "RELAY_UPSTREAM_AUTH: Authorization: Basic <secret>==" splits at the base64
// padding (PLAN.md §10).
func reportedName(name string) string {
	if len(name) > maxReportedNameBytes {
		return malformedName
	}
	for i := len(settingPrefix); i < len(name); i++ {
		if c := name[i]; (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return malformedName
		}
	}
	return name
}

// load checks the settings in the order of the PLAN.md §8 table.
//
// The forward parsers return fixed error strings that never contain their
// input (internal/forward), so their text is a safe Reason.
func (e environment) load() (*Config, error) {
	var c Config
	var err error
	if c.AppID, err = e.appID(); err != nil {
		return nil, err
	}
	if c.EnvironmentID, err = e.id("RELAY_ENVIRONMENT_ID"); err != nil {
		return nil, err
	}
	if c.CloudIDs, err = e.ids("RELAY_CLOUD_IDS", true); err != nil {
		return nil, err
	}
	if c.Upstream, err = e.upstream(); err != nil {
		return nil, err
	}
	if c.Routes, err = e.routes(); err != nil {
		return nil, err
	}
	if c.Credential, c.CredentialFromFile, err = e.credential(); err != nil {
		return nil, err
	}
	if c.UpstreamCAs, err = e.upstreamCAs(); err != nil {
		return nil, err
	}
	if c.InstallationIDs, err = e.ids("RELAY_INSTALLATION_IDS", false); err != nil {
		return nil, err
	}
	if c.RequestHeaders, err = e.headers("RELAY_REQUEST_HEADERS", defaultRequestHeaders, forward.ParseRequestHeaders); err != nil {
		return nil, err
	}
	if c.ResponseHeaders, err = e.headers("RELAY_RESPONSE_HEADERS", defaultResponseHeaders, forward.ParseResponseHeaders); err != nil {
		return nil, err
	}
	if c.Port, err = e.port(); err != nil {
		return nil, err
	}
	if c.UpstreamTimeout, err = e.upstreamTimeout(); err != nil {
		return nil, err
	}
	if c.MaxRequestBytes, c.MaxResponseBytes, c.MaxConcurrent, err = e.payloadLimits(); err != nil {
		return nil, err
	}
	if c.ClockSkew, err = e.clockSkew(); err != nil {
		return nil, err
	}
	if c.JWKSURL, err = e.jwksURL(); err != nil {
		return nil, err
	}
	if c.JWKSRefresh, c.JWKSMaxAge, err = e.jwksAges(); err != nil {
		return nil, err
	}
	if c.ShutdownGrace, err = e.duration("RELAY_SHUTDOWN_GRACE", defaultShutdownGrace, true); err != nil {
		return nil, err
	}
	if c.LogLevel, err = e.logLevel(); err != nil {
		return nil, err
	}
	return &c, nil
}

// value returns the raw value of setting name, from NAME or from the file
// named by NAME_FILE, and whether it came from the file. It returns "" when
// neither is set. A variable that is present but empty is an error rather
// than a request for the default (PLAN.md §8): in a deploy file it is more
// likely a mistake than a choice.
func (e environment) value(name string, required bool) (string, bool, error) {
	fileName := name + fileSuffix
	for _, n := range [...]string{name, fileName} {
		if e.repeated[n] {
			return "", false, fail(n, "set more than once")
		}
	}
	v, inEnv := e.vars[name]
	path, inFile := e.vars[fileName]
	switch {
	case inEnv && inFile:
		return "", false, fail(name, "set only one of "+name+" and "+fileName)
	case inEnv && v == "":
		return "", false, fail(name, emptyReason(required))
	case inEnv:
		return v, false, nil
	case inFile && path == "":
		return "", false, fail(fileName, emptyReason(required))
	case inFile:
		b, reason := readFile(path, MaxSettingFileBytes)
		if reason != "" {
			return "", false, fail(fileName, reason)
		}
		v = trimLineEnding(string(b))
		if v == "" {
			return "", false, fail(fileName, "file is empty")
		}
		return v, true, nil
	case required:
		return "", false, fail(name, "required")
	}
	return "", false, nil
}

func emptyReason(required bool) string {
	if required {
		return "empty; a value is required"
	}
	return "empty; unset it to use the default"
}

// optional returns the value of a setting, or def when it is unset.
func (e environment) optional(name, def string) (string, error) {
	v, _, err := e.value(name, false)
	if err != nil {
		return "", err
	}
	if v == "" {
		return def, nil
	}
	return v, nil
}

// readFile reads path, which must hold at most limit bytes. It returns a
// fixed reason on failure, because the errors of package os contain the path.
func readFile(path string, limit int64) ([]byte, string) {
	f, err := os.Open(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, "file does not exist"
	case errors.Is(err, fs.ErrPermission):
		return nil, "file is not readable"
	case err != nil:
		return nil, "cannot open the file"
	}
	// One byte past the limit tells "exactly the limit" from "larger".
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	_ = f.Close() // opened read-only: closing cannot lose data
	switch {
	case err != nil:
		return nil, "cannot read the file"
	case int64(len(b)) > limit:
		return nil, "file is larger than " + strconv.FormatInt(limit, 10) + " bytes"
	}
	return b, ""
}

// trimLineEnding removes one trailing "\n" or "\r\n", which editors and echo
// add to secret files. Removing more could hide a second line.
func trimLineEnding(s string) string {
	if t, ok := strings.CutSuffix(s, "\r\n"); ok {
		return t
	}
	return strings.TrimSuffix(s, "\n")
}

// splitList splits a comma-separated setting (PLAN.md §8). Spaces and tabs
// around an item are ignored; an empty or repeated item is refused, since it
// usually means a copy-and-paste mistake.
func splitList(name, s string) ([]string, error) {
	items := strings.Split(s, ",")
	seen := make(map[string]bool, len(items))
	for i, item := range items {
		item = strings.Trim(item, " \t")
		switch {
		case item == "":
			return nil, fail(name, "empty list item")
		case seen[item]:
			return nil, fail(name, "duplicate list item")
		}
		seen[item] = true
		items[i] = item
	}
	return items, nil
}

func (e environment) appID() (string, error) {
	const name = "RELAY_APP_ID"
	v, _, err := e.value(name, true)
	if err != nil {
		return "", err
	}
	if !validAppID(v) {
		return "", fail(name, "want "+appIDPrefix+" followed by a lowercase UUID")
	}
	return v, nil
}

// validAppID reports whether s is a canonical app ARI. The FIT audience is
// compared byte for byte (PLAN.md §4.4), and Forge writes the UUID in
// lowercase, so any other spelling would make every token fail.
func validAppID(s string) bool {
	uuid, ok := strings.CutPrefix(s, appIDPrefix)
	if !ok || len(uuid) != uuidLen {
		return false
	}
	for i := 0; i < len(uuid); i++ {
		c := uuid[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

func (e environment) id(name string) (string, error) {
	v, _, err := e.value(name, true)
	if err != nil {
		return "", err
	}
	if !validID(v) {
		return "", fail(name, idReason())
	}
	return v, nil
}

func (e environment) ids(name string, required bool) ([]string, error) {
	v, _, err := e.value(name, required)
	if err != nil || v == "" {
		return nil, err
	}
	items, err := splitList(name, v)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if !validID(item) {
			return nil, fail(name, idReason())
		}
	}
	return items, nil
}

func idReason() string {
	return "each ID must be 1 to " + strconv.Itoa(maxIDBytes) + " printable ASCII characters without spaces or commas"
}

// validID reports whether s can be a site, environment or installation ID.
// FIT claims are compared to these IDs byte for byte (PLAN.md §4.4) and a
// verified site ID is logged, so spaces, control characters and the list
// separator are refused.
func validID(s string) bool {
	if s == "" || len(s) > maxIDBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c <= ' ' || c > '~' || c == ',' {
			return false
		}
	}
	return true
}

func (e environment) upstream() (forward.Upstream, error) {
	const name = "RELAY_UPSTREAM_URL"
	v, _, err := e.value(name, true)
	if err != nil {
		return forward.Upstream{}, err
	}
	u, err := forward.ParseUpstream(v)
	if err != nil {
		return forward.Upstream{}, fail(name, err.Error())
	}
	return u, nil
}

func (e environment) routes() ([]forward.Route, error) {
	const name = "RELAY_ROUTES"
	v, _, err := e.value(name, true)
	if err != nil {
		return nil, err
	}
	items, err := splitList(name, v)
	if err != nil {
		return nil, err
	}
	routes, err := forward.ParseRoutes(items)
	if err != nil {
		return nil, fail(name, err.Error())
	}
	return routes, nil
}

func (e environment) credential() (*forward.Credential, bool, error) {
	const name = "RELAY_UPSTREAM_AUTH"
	v, fromFile, err := e.value(name, false)
	if err != nil || v == "" {
		return nil, false, err
	}
	cred, err := forward.ParseCredential(v)
	if err != nil {
		return nil, false, fail(name, err.Error())
	}
	return &cred, fromFile, nil
}

func (e environment) upstreamCAs() (*x509.CertPool, error) {
	const name = "RELAY_UPSTREAM_CA_FILE"
	path, _, err := e.value(name, false)
	if err != nil || path == "" {
		return nil, err
	}
	data, reason := readFile(path, MaxCAFileBytes)
	if reason != "" {
		return nil, fail(name, reason)
	}
	pool, reason := parseCAs(data)
	if reason != "" {
		return nil, fail(name, reason)
	}
	return pool, nil
}

const pemSpace = " \t\r\n"

// parseCAs parses a PEM bundle in which every block is a certificate and
// nothing but whitespace lies outside the blocks. pem.Decode skips text it
// does not understand, including a damaged block, and a bundle that trusts
// fewer CAs than the operator expects fails only later, at the first token
// exchange.
func parseCAs(data []byte) (*x509.CertPool, string) {
	pool := x509.NewCertPool()
	n := 0
	for rest := bytes.TrimLeft(data, pemSpace); len(rest) > 0; rest = bytes.TrimLeft(rest, pemSpace) {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN ")) {
			return nil, "unexpected text outside the PEM blocks"
		}
		var block *pem.Block
		block, rest = pem.Decode(rest)
		switch {
		case block == nil:
			return nil, "malformed PEM block"
		case block.Type != "CERTIFICATE":
			return nil, "PEM block is not a CERTIFICATE"
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, "invalid certificate"
		}
		pool.AddCert(cert)
		n++
	}
	// A BEGIN line without a block of its own means pem.Decode skipped a
	// damaged block to reach a later one.
	switch {
	case n == 0:
		return nil, "no PEM certificate"
	case bytes.Count(data, []byte("-----BEGIN")) != n:
		return nil, "malformed PEM block"
	}
	return pool, ""
}

func (e environment) headers(name, def string, parse func([]string) ([]string, error)) ([]string, error) {
	v, err := e.optional(name, def)
	if err != nil {
		return nil, err
	}
	items, err := splitList(name, v)
	if err != nil {
		return nil, err
	}
	h, err := parse(items)
	if err != nil {
		return nil, fail(name, err.Error())
	}
	return h, nil
}

func (e environment) port() (int, error) {
	const name = "RELAY_PORT"
	v, err := e.optional(name, defaultPort)
	if err != nil {
		return 0, err
	}
	n, ok := parseDigits(v)
	if !ok || n < 1 || n > forward.MaxPort {
		return 0, fail(name, "want a port number from 1 to "+strconv.Itoa(forward.MaxPort))
	}
	return int(n), nil
}

// parseDigits parses a decimal integer of ASCII digits only: strconv alone
// also accepts a sign, and its errors quote the input.
func parseDigits(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// duration parses a time.ParseDuration setting such as "10s". positive
// refuses zero; every duration refuses negative values.
func (e environment) duration(name, def string, positive bool) (time.Duration, error) {
	v, err := e.optional(name, def)
	if err != nil {
		return 0, err
	}
	d, err := time.ParseDuration(v)
	switch {
	case err != nil: // its text quotes the input
		return 0, fail(name, "want a duration such as 10s")
	case positive && d <= 0:
		return 0, fail(name, "must be greater than zero")
	case d < 0:
		return 0, fail(name, "must not be negative")
	}
	return d, nil
}

func (e environment) clockSkew() (time.Duration, error) {
	const name = "RELAY_CLOCK_SKEW"
	d, err := e.duration(name, defaultClockSkew, false)
	if err != nil {
		return 0, err
	}
	if d > MaxClockSkew {
		return 0, fail(name, "must be at most "+MaxClockSkew.String())
	}
	return d, nil
}

func (e environment) upstreamTimeout() (time.Duration, error) {
	const name = "RELAY_UPSTREAM_TIMEOUT"
	d, err := e.duration(name, defaultUpstreamTimeout, true)
	if err != nil {
		return 0, err
	}
	if d > math.MaxInt64-WriteTimeoutMargin {
		return 0, fail(name, "too large: the server's write timeout adds "+WriteTimeoutMargin.String())
	}
	return d, nil
}

func (e environment) count(name, def string) (int64, error) {
	v, err := e.optional(name, def)
	if err != nil {
		return 0, err
	}
	n, ok := parseDigits(v)
	if !ok || n < 1 {
		return 0, fail(name, "want a whole number of at least 1, digits only")
	}
	return n, nil
}

func (e environment) payloadLimits() (request, response int64, concurrent int, err error) {
	if request, err = e.count("RELAY_MAX_REQUEST_BYTES", defaultMaxRequestBytes); err != nil {
		return 0, 0, 0, err
	}
	if response, err = e.count("RELAY_MAX_RESPONSE_BYTES", defaultMaxResponseBytes); err != nil {
		return 0, 0, 0, err
	}
	n, err := e.count("RELAY_MAX_CONCURRENT", defaultMaxConcurrent)
	if err != nil {
		return 0, 0, 0, err
	}
	if !withinBudget(n, request, response) {
		return 0, 0, 0, fail("RELAY_MAX_CONCURRENT, RELAY_MAX_REQUEST_BYTES, RELAY_MAX_RESPONSE_BYTES",
			"concurrency times (request limit + response limit) must not exceed "+strconv.Itoa(MaxPayloadBudget)+" bytes")
	}
	// The budget keeps n far inside the int range.
	return request, response, int(n), nil
}

// withinBudget reports whether concurrent × (request + response) is at most
// MaxPayloadBudget, for operands of at least 1, without int64 overflow: each
// limit is first bounded by the budget, so the sum cannot overflow, and the
// product is compared by division (PLAN.md §6).
func withinBudget(concurrent, request, response int64) bool {
	if request > MaxPayloadBudget || response > MaxPayloadBudget {
		return false
	}
	return concurrent <= MaxPayloadBudget/(request+response)
}

func (e environment) jwksURL() (string, error) {
	const name = "RELAY_JWKS_URL"
	v, err := e.optional(name, DefaultJWKSURL)
	if err != nil {
		return "", err
	}
	// The keys decide which FITs are trusted, so only HTTPS will do
	// (PLAN.md §4.5). Userinfo or a query would put a secret into the URL
	// that the startup summary logs, and a fragment is never sent, so it can
	// only be a mistake. The port rule is RELAY_UPSTREAM_URL's: a port
	// outside 1 to 65535 would keep the relay from ever becoming ready
	// instead of failing startup (PLAN.md §8, R-13).
	u, err := url.Parse(v)
	if !strings.HasPrefix(v, "https://") || strings.ContainsAny(v, "?#") ||
		err != nil || u.User != nil || u.Hostname() == "" || !forward.ValidURLPort(u.Port()) {
		return "", fail(name, "want an https URL with a host and no userinfo, query or fragment")
	}
	return v, nil
}

func (e environment) jwksAges() (refresh, maxAge time.Duration, err error) {
	if refresh, err = e.duration("RELAY_JWKS_REFRESH", defaultJWKSRefresh, true); err != nil {
		return 0, 0, err
	}
	if maxAge, err = e.duration("RELAY_JWKS_MAX_AGE", defaultJWKSMaxAge, true); err != nil {
		return 0, 0, err
	}
	// The snapshot would otherwise reach its maximum age before the next
	// scheduled refresh (PLAN.md §4.5: 0 < refresh < max age).
	if refresh >= maxAge {
		return 0, 0, fail("RELAY_JWKS_REFRESH", "must be less than RELAY_JWKS_MAX_AGE")
	}
	return refresh, maxAge, nil
}

func (e environment) logLevel() (slog.Level, error) {
	const name = "RELAY_LOG_LEVEL"
	v, err := e.optional(name, defaultLogLevel)
	if err != nil {
		return 0, err
	}
	// Exact names only: slog's own parser also accepts "INFO+2" and any case.
	switch v {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fail(name, "want debug, info, warn or error")
}
