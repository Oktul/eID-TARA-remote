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

	"eid-tara-remote/internal/forward"
)

// Limits and the JWKS default of PLAN.md §4.5, §6 and §8.
const (
	// MaxSettingFileBytes bounds a <NAME>_FILE read, so a wrong path (a log
	// file, a device) cannot exhaust memory at startup.
	MaxSettingFileBytes = 64 << 10
	// MaxCAFileBytes bounds the read of RELAY_UPSTREAM_CA_FILE, which holds
	// a PEM bundle rather than a single value.
	MaxCAFileBytes = 1 << 20
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
	defaultPort            = "8080"
	defaultUpstreamTimeout = "10s"
	defaultClockSkew       = "10s"
	defaultJWKSRefresh     = "6h"
	defaultJWKSMaxAge      = "24h"
	defaultShutdownGrace   = "15s"
	defaultLogLevel        = "info"
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
	// the longest known name with _FILE has 27 bytes.
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

	Upstream        forward.Upstream    // RELAY_UPSTREAM_URL
	UpstreamAnyHost bool                // RELAY_UPSTREAM_ANY_HOST; true: not only TARA's origins (SR-5)
	Credential      *forward.Credential // RELAY_UPSTREAM_AUTH; nil: no credential header
	// CredentialFromFile records that the credential came from
	// RELAY_UPSTREAM_AUTH_FILE, for the startup summary (PLAN.md §10).
	CredentialFromFile bool
	UpstreamCAs        *x509.CertPool // RELAY_UPSTREAM_CA_FILE; nil: system roots

	Port int // RELAY_PORT

	UpstreamTimeout time.Duration // RELAY_UPSTREAM_TIMEOUT
	ClockSkew       time.Duration // RELAY_CLOCK_SKEW

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
	l := &loader{env: env}
	port := l.port()
	return port, l.err
}

// Summary returns the startup summary of PLAN.md §10 (O-5): one attribute
// per setting, keyed by its name, in table order. The credential appears only
// as "set (from file)", "set" or "not set" (S-8); file settings show only
// whether they are set.
func (c *Config) Summary() []slog.Attr {
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
		slog.Bool("RELAY_UPSTREAM_ANY_HOST", c.UpstreamAnyHost),
		slog.String("RELAY_UPSTREAM_AUTH", credential),
		slog.String("RELAY_UPSTREAM_CA_FILE", state(c.UpstreamCAs != nil, "system bundle")),
		slog.String("RELAY_INSTALLATION_IDS", installations),
		slog.Int("RELAY_PORT", c.Port),
		slog.String("RELAY_UPSTREAM_TIMEOUT", c.UpstreamTimeout.String()),
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

// known reports the 16 settings of the PLAN.md §8 table. Any other RELAY_*
// variable, other than a known name plus _FILE, is reported as unknown so
// that a typo does not go unnoticed.
func known(name string) bool {
	switch name {
	case "RELAY_APP_ID", "RELAY_ENVIRONMENT_ID", "RELAY_CLOUD_IDS",
		"RELAY_UPSTREAM_URL", "RELAY_UPSTREAM_ANY_HOST", "RELAY_UPSTREAM_AUTH",
		"RELAY_UPSTREAM_CA_FILE", "RELAY_INSTALLATION_IDS",
		"RELAY_PORT", "RELAY_UPSTREAM_TIMEOUT",
		"RELAY_CLOCK_SKEW", "RELAY_JWKS_URL",
		"RELAY_JWKS_REFRESH", "RELAY_JWKS_MAX_AGE", "RELAY_SHUTDOWN_GRACE",
		"RELAY_LOG_LEVEL":
		return true
	}
	return false
}

// environment holds the RELAY_* variables of the process environment.
type environment map[string]string

// parseEnviron reads the RELAY_* entries of environ, which comes from
// os.Environ and so never repeats a name.
func parseEnviron(environ []string) (environment, []string) {
	env := environment{}
	var unknown []string
	for _, kv := range environ {
		// Entries without "=" or with an empty name, such as the Windows
		// per-drive directories "=C:=C:\...", fail the prefix test.
		name, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(name, settingPrefix) {
			continue
		}
		env[name] = v
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

// loader reads the settings of env and keeps the first error, so load reads
// as the list of settings it checks. Once an error is kept, value returns
// nothing: no later file is read and no later setting is reported. Checks on
// the empty values that follow are harmless, since fail keeps only the
// first error and load discards the Config.
type loader struct {
	env environment
	err error
}

// fail records a configuration error unless an earlier one is kept.
func (l *loader) fail(setting, reason string) {
	if l.err == nil {
		l.err = &Error{Setting: setting, Reason: reason}
	}
}

// load checks the settings in the order of the PLAN.md §8 table.
//
// The forward parsers return fixed error strings that never contain their
// input (internal/forward), so their text is a safe Reason.
func (e environment) load() (*Config, error) {
	l := &loader{env: e}
	var c Config
	c.AppID = l.appID()
	c.EnvironmentID = l.id("RELAY_ENVIRONMENT_ID")
	c.CloudIDs = l.ids("RELAY_CLOUD_IDS", true)
	c.Upstream, c.UpstreamAnyHost = l.upstream()
	c.Credential, c.CredentialFromFile = l.credential()
	c.UpstreamCAs = l.upstreamCAs()
	c.InstallationIDs = l.ids("RELAY_INSTALLATION_IDS", false)
	c.Port = l.port()
	c.UpstreamTimeout = l.upstreamTimeout()
	c.ClockSkew = l.clockSkew()
	c.JWKSURL = l.jwksURL()
	c.JWKSRefresh, c.JWKSMaxAge = l.jwksAges()
	c.ShutdownGrace = l.duration("RELAY_SHUTDOWN_GRACE", defaultShutdownGrace, true)
	c.LogLevel = l.logLevel()
	if l.err != nil {
		return nil, l.err
	}
	return &c, nil
}

// value returns the raw value of setting name, from NAME or from the file
// named by NAME_FILE, and whether it came from the file. It returns "" when
// neither is set. A variable that is present but empty is an error rather
// than a request for the default (PLAN.md §8): in a deploy file it is more
// likely a mistake than a choice.
func (l *loader) value(name string, required bool) (string, bool) {
	if l.err != nil {
		return "", false
	}
	fileName := name + fileSuffix
	v, inEnv := l.env[name]
	path, inFile := l.env[fileName]
	switch {
	case inEnv && inFile:
		l.fail(name, "set only one of "+name+" and "+fileName)
	case inEnv && v == "":
		l.fail(name, emptyReason(required))
	case inEnv:
		return v, false
	case inFile && path == "":
		l.fail(fileName, emptyReason(required))
	case inFile:
		b, reason := readFile(path, MaxSettingFileBytes)
		if reason != "" {
			l.fail(fileName, reason)
			break
		}
		if v = trimLineEnding(string(b)); v == "" {
			l.fail(fileName, "file is empty")
			break
		}
		return v, true
	case required:
		l.fail(name, "required")
	}
	return "", false
}

func emptyReason(required bool) string {
	if required {
		return "empty; a value is required"
	}
	return "empty; unset it to use the default"
}

// optional returns the value of a setting, or def when it is unset.
func (l *loader) optional(name, def string) string {
	if v, _ := l.value(name, false); v != "" {
		return v
	}
	return def
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

// list splits the comma-separated setting name (PLAN.md §8). Spaces and tabs
// around an item are ignored; an empty or repeated item is refused, since it
// usually means a copy-and-paste mistake.
func (l *loader) list(name, s string) []string {
	items := strings.Split(s, ",")
	seen := make(map[string]bool, len(items))
	for i, item := range items {
		item = strings.Trim(item, " \t")
		switch {
		case item == "":
			l.fail(name, "empty list item")
			return nil
		case seen[item]:
			l.fail(name, "duplicate list item")
			return nil
		}
		seen[item] = true
		items[i] = item
	}
	return items
}

func (l *loader) appID() string {
	const name = "RELAY_APP_ID"
	v, _ := l.value(name, true)
	if !validAppID(v) {
		l.fail(name, "want "+appIDPrefix+" followed by a lowercase UUID")
	}
	return v
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

func (l *loader) id(name string) string {
	v, _ := l.value(name, true)
	if !validID(v) {
		l.fail(name, idReason())
	}
	return v
}

func (l *loader) ids(name string, required bool) []string {
	v, _ := l.value(name, required)
	if v == "" {
		return nil
	}
	items := l.list(name, v)
	for _, item := range items {
		if !validID(item) {
			l.fail(name, idReason())
		}
	}
	return items
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

// upstream reads RELAY_UPSTREAM_URL and RELAY_UPSTREAM_ANY_HOST. The relay
// sends TARA's client secret to this origin, so a wrong or
// social-engineered value would hand it to someone else; anything but
// TARA's two origins needs the explicit override (PLAN.md §8, SR-5).
func (l *loader) upstream() (forward.Upstream, bool) {
	const name, anyHostName = "RELAY_UPSTREAM_URL", "RELAY_UPSTREAM_ANY_HOST"
	v, _ := l.value(name, true)
	u, err := forward.ParseUpstream(v)
	if err != nil {
		l.fail(name, err.Error())
	}
	anyHost := l.boolean(anyHostName)
	if l.err == nil && !anyHost && !u.TARA() {
		l.fail(name, "not one of "+forward.TARAProductionOrigin+", "+forward.TARADemoOrigin+"; set "+anyHostName+"=true for another upstream")
	}
	return u, anyHost
}

// boolean reads a setting that is exactly "true" or "false", default false.
func (l *loader) boolean(name string) bool {
	switch l.optional(name, "false") {
	case "true":
		return true
	case "false":
		return false
	}
	l.fail(name, "want true or false")
	return false
}

func (l *loader) credential() (*forward.Credential, bool) {
	const name = "RELAY_UPSTREAM_AUTH"
	v, fromFile := l.value(name, false)
	if v == "" {
		return nil, false
	}
	cred, err := forward.ParseCredential(v)
	if err != nil {
		l.fail(name, err.Error())
		return nil, false
	}
	return &cred, fromFile
}

func (l *loader) upstreamCAs() *x509.CertPool {
	const name = "RELAY_UPSTREAM_CA_FILE"
	path, _ := l.value(name, false)
	if path == "" {
		return nil
	}
	data, reason := readFile(path, MaxCAFileBytes)
	if reason != "" {
		l.fail(name, reason)
		return nil
	}
	pool, reason := parseCAs(data)
	if reason != "" {
		l.fail(name, reason)
	}
	return pool
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

func (l *loader) port() int {
	const name = "RELAY_PORT"
	n, err := strconv.ParseUint(l.optional(name, defaultPort), 10, 16)
	if err != nil || n == 0 {
		l.fail(name, "want a port number from 1 to "+strconv.Itoa(forward.MaxPort))
		return 0
	}
	return int(n)
}

// duration parses a time.ParseDuration setting such as "10s". positive
// refuses zero; every duration refuses negative values.
func (l *loader) duration(name, def string, positive bool) time.Duration {
	d, err := time.ParseDuration(l.optional(name, def))
	switch {
	case err != nil: // its text quotes the input
		l.fail(name, "want a duration such as 10s")
	case positive && d <= 0:
		l.fail(name, "must be greater than zero")
	case d < 0:
		l.fail(name, "must not be negative")
	}
	return d
}

func (l *loader) clockSkew() time.Duration {
	const name = "RELAY_CLOCK_SKEW"
	d := l.duration(name, defaultClockSkew, false)
	if d > MaxClockSkew {
		l.fail(name, "must be at most "+MaxClockSkew.String())
	}
	return d
}

func (l *loader) upstreamTimeout() time.Duration {
	const name = "RELAY_UPSTREAM_TIMEOUT"
	d := l.duration(name, defaultUpstreamTimeout, true)
	if d > math.MaxInt64-WriteTimeoutMargin {
		l.fail(name, "too large: the server's write timeout adds "+WriteTimeoutMargin.String())
	}
	return d
}

func (l *loader) jwksURL() string {
	const name = "RELAY_JWKS_URL"
	v := l.optional(name, DefaultJWKSURL)
	// The keys decide which FITs are trusted, so only HTTPS will do
	// (PLAN.md §4.5). Userinfo or a query would put a secret into the URL
	// that the startup summary logs, and a fragment is never sent, so it can
	// only be a mistake. The port rule is RELAY_UPSTREAM_URL's: a port
	// outside 1 to 65535 would keep the relay from ever becoming ready
	// instead of failing startup (PLAN.md §8, R-13).
	u, err := url.Parse(v)
	if !strings.HasPrefix(v, "https://") || strings.ContainsAny(v, "?#") ||
		err != nil || u.User != nil || u.Hostname() == "" || !forward.ValidURLPort(u.Port()) {
		l.fail(name, "want an https URL with a host and no userinfo, query or fragment")
	}
	return v
}

func (l *loader) jwksAges() (refresh, maxAge time.Duration) {
	refresh = l.duration("RELAY_JWKS_REFRESH", defaultJWKSRefresh, true)
	maxAge = l.duration("RELAY_JWKS_MAX_AGE", defaultJWKSMaxAge, true)
	// The snapshot would otherwise reach its maximum age before the next
	// scheduled refresh (PLAN.md §4.5: 0 < refresh < max age).
	if refresh >= maxAge {
		l.fail("RELAY_JWKS_REFRESH", "must be less than RELAY_JWKS_MAX_AGE")
	}
	return refresh, maxAge
}

func (l *loader) logLevel() slog.Level {
	const name = "RELAY_LOG_LEVEL"
	// Exact names only: slog's own parser also accepts "INFO+2" and any case.
	switch l.optional(name, defaultLogLevel) {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	l.fail(name, "want debug, info, warn or error")
	return 0
}
