// SPDX-License-Identifier: EUPL-1.2

package config_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"maps"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"eid-forge-remote/internal/config"
	"eid-forge-remote/internal/forward"
)

// Synthetic identifiers; none belongs to a real app, environment or site.
const (
	appID   = "ari:cloud:ecosystem::app/00000000-0000-4000-8000-000000000001"
	envID   = "ari:cloud:ecosystem::environment/00000000-0000-4000-8000-000000000001/00000000-0000-4000-8000-000000000002"
	cloudID = "00000000-0000-4000-8000-000000000003"
	// marker is planted in rejected values, file contents and file names.
	// It must never appear in an error (PLAN.md §8, §13 Config).
	marker = "SECRETMARKER5f1c"
)

// requiredEnv returns valid values for the five required settings.
func requiredEnv() map[string]string {
	return map[string]string{
		"RELAY_APP_ID":         appID,
		"RELAY_ENVIRONMENT_ID": envID,
		"RELAY_CLOUD_IDS":      cloudID,
		"RELAY_UPSTREAM_URL":   "https://provider.example",
		"RELAY_ROUTES":         "POST /oidc/token",
	}
}

// with returns a copy of m with the name/value pairs kv set.
func with(m map[string]string, kv ...string) map[string]string {
	m = maps.Clone(m)
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i]] = kv[i+1]
	}
	return m
}

func environ(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		out = append(out, k+"="+v)
	}
	slices.Sort(out)
	return out
}

func mustLoad(t *testing.T, m map[string]string) *config.Config {
	t.Helper()
	c, _, err := config.Load(environ(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

// loadError runs Load on m, which must fail on setting.
func loadError(t *testing.T, m map[string]string, setting string) *config.Error {
	t.Helper()
	_, _, err := config.Load(environ(m))
	return checkError(t, err, setting)
}

// checkError asserts that err is a *config.Error that names setting and
// contains no marker.
func checkError(t *testing.T, err error, setting string) *config.Error {
	t.Helper()
	var ce *config.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error = %v, want a *config.Error for %s", err, setting)
	}
	msg := err.Error()
	if ce.Setting != setting || !strings.HasPrefix(msg, setting+": ") {
		t.Fatalf("error = %q, want it to name %s", msg, setting)
	}
	if strings.Contains(msg, marker) {
		t.Fatalf("error %q contains the rejected value", msg)
	}
	return ce
}

func writeFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// testPEM is a self-signed certificate with its key, and an unrelated key.
type testPEM struct {
	cert, key, otherKey []byte
	err                 error
}

// generatedPEM creates the test keys once per test run (CONTRIBUTING.md,
// Tests); nothing is committed.
var generatedPEM = sync.OnceValue(func() testPEM {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return testPEM{err: err}
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return testPEM{err: err}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "relay test CA"},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return testPEM{err: err}
	}
	keyPEM := func(k *ecdsa.PrivateKey) ([]byte, error) {
		b, err := x509.MarshalPKCS8PrivateKey(k)
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), err
	}
	p := testPEM{cert: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	if p.key, err = keyPEM(key); err != nil {
		return testPEM{err: err}
	}
	if p.otherKey, err = keyPEM(other); err != nil {
		return testPEM{err: err}
	}
	return p
})

func pemFiles(t *testing.T) testPEM {
	t.Helper()
	p := generatedPEM()
	if p.err != nil {
		t.Fatalf("generate test certificate: %v", p.err)
	}
	return p
}

// row is one setting of the PLAN.md §8 table: a valid value other than the
// default, a value that breaks the setting's rule and carries the marker,
// and a check that the valid value reached the Config.
type row struct {
	name  string
	valid string
	bad   string
	check func(c *config.Config) bool
}

// table returns every setting in the order of the PLAN.md §8 table, spelled
// as literals (PLAN.md §4.6).
func table(t *testing.T) []row {
	t.Helper()
	p := pemFiles(t)
	cert := writeFile(t, "cert.pem", p.cert)
	key := writeFile(t, "key.pem", p.key)
	missing := filepath.Join(t.TempDir(), marker+".pem")
	return []row{
		{"RELAY_APP_ID", appID, "ari:cloud:ecosystem::app/" + marker,
			func(c *config.Config) bool { return c.AppID == appID }},
		{"RELAY_ENVIRONMENT_ID", envID, marker + " " + marker,
			func(c *config.Config) bool { return c.EnvironmentID == envID }},
		{"RELAY_CLOUD_IDS", " " + cloudID + " ,\tsite-2", cloudID + "," + marker + "\x01",
			func(c *config.Config) bool { return slices.Equal(c.CloudIDs, []string{cloudID, "site-2"}) }},
		{"RELAY_UPSTREAM_URL", "https://provider.example/base", "http://" + marker + ".example",
			func(c *config.Config) bool { return c.Upstream.String() == "https://provider.example/base" }},
		{"RELAY_ROUTES", "POST /oidc/token, GET /oidc/jwks", "POST /oidc/" + marker + "%2F",
			func(c *config.Config) bool {
				return slices.Equal(c.Routes, []forward.Route{{Method: "POST", Path: "/oidc/token"}, {Method: "GET", Path: "/oidc/jwks"}})
			}},
		{"RELAY_UPSTREAM_AUTH", "x-api-key: synthetic", "Authorization: Basic " + marker + "\r\nX: y",
			func(c *config.Config) bool {
				return c.Credential != nil && c.Credential.Name == "X-Api-Key" && c.Credential.Value.Reveal() == "synthetic"
			}},
		{"RELAY_UPSTREAM_CA_FILE", cert, missing,
			func(c *config.Config) bool { return c.UpstreamCAs != nil }},
		{"RELAY_INSTALLATION_IDS", "install-1,install-2", "install-1," + marker + "\x7f",
			func(c *config.Config) bool {
				return slices.Equal(c.InstallationIDs, []string{"install-1", "install-2"})
			}},
		{"RELAY_REQUEST_HEADERS", "content-type, Accept-Language", "Content-Type,X-Forwarded-" + marker,
			func(c *config.Config) bool {
				return slices.Equal(c.RequestHeaders, []string{"Content-Type", "Accept-Language"})
			}},
		{"RELAY_RESPONSE_HEADERS", "Content-Type,expires", "Content-Type,Relay-" + marker,
			func(c *config.Config) bool {
				return slices.Equal(c.ResponseHeaders, []string{"Content-Type", "Expires"})
			}},
		{"RELAY_PORT", "8443", "8443" + marker,
			func(c *config.Config) bool { return c.Port == 8443 }},
		{"RELAY_TLS_CERT_FILE", cert, missing,
			func(c *config.Config) bool { return c.TLSCertificate != nil }},
		{"RELAY_TLS_KEY_FILE", key, missing,
			func(c *config.Config) bool { return c.TLSCertificate != nil }},
		{"RELAY_UPSTREAM_TIMEOUT", "3s", "3s" + marker,
			func(c *config.Config) bool { return c.UpstreamTimeout == 3*time.Second }},
		{"RELAY_MAX_REQUEST_BYTES", "1000", "1000" + marker,
			func(c *config.Config) bool { return c.MaxRequestBytes == 1000 }},
		{"RELAY_MAX_RESPONSE_BYTES", "2000", "2000" + marker,
			func(c *config.Config) bool { return c.MaxResponseBytes == 2000 }},
		{"RELAY_MAX_CONCURRENT", "7", "7" + marker,
			func(c *config.Config) bool { return c.MaxConcurrent == 7 }},
		{"RELAY_CLOCK_SKEW", "0s", "1s" + marker,
			func(c *config.Config) bool { return c.ClockSkew == 0 }},
		{"RELAY_JWKS_URL", "https://keys.example/jwks.json", "http://" + marker + ".example/jwks.json",
			func(c *config.Config) bool { return c.JWKSURL == "https://keys.example/jwks.json" }},
		{"RELAY_JWKS_REFRESH", "1h", "1h" + marker,
			func(c *config.Config) bool { return c.JWKSRefresh == time.Hour }},
		{"RELAY_JWKS_MAX_AGE", "2h", "2h" + marker,
			func(c *config.Config) bool { return c.JWKSMaxAge == 2*time.Hour }},
		{"RELAY_SHUTDOWN_GRACE", "1s", "1s" + marker,
			func(c *config.Config) bool { return c.ShutdownGrace == time.Second }},
		{"RELAY_LOG_LEVEL", "debug", marker,
			func(c *config.Config) bool { return c.LogLevel == slog.LevelDebug }},
	}
}

// set stores value under name, or in a file named by name_FILE with the
// trailing newline an editor adds.
func set(t *testing.T, m map[string]string, name, value string, viaFile bool) {
	t.Helper()
	if !viaFile {
		m[name] = value
		return
	}
	delete(m, name)
	m[name+"_FILE"] = writeFile(t, marker+name, []byte(value+"\n"))
}

// sources are the two ways to supply a setting (PLAN.md §8).
var sources = []struct {
	name    string
	viaFile bool
}{{"env", false}, {"file", true}}

func allValid(rows []row) map[string]string {
	m := map[string]string{}
	for _, r := range rows {
		m[r.name] = r.valid
	}
	return m
}

func TestEverySettingIsRead(t *testing.T) {
	rows := table(t)
	for _, src := range sources {
		t.Run(src.name, func(t *testing.T) {
			viaFile := src.viaFile
			m := map[string]string{}
			for _, r := range rows {
				set(t, m, r.name, r.valid, viaFile)
			}
			c, unknown, err := config.Load(environ(m))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(unknown) != 0 {
				t.Errorf("unknown = %v, want none", unknown)
			}
			for _, r := range rows {
				if !r.check(c) {
					t.Errorf("%s: valid value not applied", r.name)
				}
			}
			if c.CredentialFromFile != viaFile {
				t.Errorf("CredentialFromFile = %v, want %v", c.CredentialFromFile, viaFile)
			}
		})
	}
}

// TestSettingNames pins the 23 setting names of PLAN.md §8 as literals: none
// of them, nor its _FILE variant, is reported as unknown.
func TestSettingNames(t *testing.T) {
	names := []string{
		"RELAY_APP_ID", "RELAY_ENVIRONMENT_ID", "RELAY_CLOUD_IDS", "RELAY_UPSTREAM_URL",
		"RELAY_ROUTES", "RELAY_UPSTREAM_AUTH", "RELAY_UPSTREAM_CA_FILE", "RELAY_INSTALLATION_IDS",
		"RELAY_REQUEST_HEADERS", "RELAY_RESPONSE_HEADERS", "RELAY_PORT", "RELAY_TLS_CERT_FILE",
		"RELAY_TLS_KEY_FILE", "RELAY_UPSTREAM_TIMEOUT", "RELAY_MAX_REQUEST_BYTES",
		"RELAY_MAX_RESPONSE_BYTES", "RELAY_MAX_CONCURRENT", "RELAY_CLOCK_SKEW", "RELAY_JWKS_URL",
		"RELAY_JWKS_REFRESH", "RELAY_JWKS_MAX_AGE", "RELAY_SHUTDOWN_GRACE", "RELAY_LOG_LEVEL",
	}
	var env []string
	for _, n := range names {
		env = append(env, n+"=x", n+"_FILE=x")
	}
	// The values are invalid and Load fails; only the names are under test.
	if _, unknown, _ := config.Load(env); len(unknown) != 0 {
		t.Errorf("unknown = %v, want none", unknown)
	}
	var tableNames []string
	for _, r := range table(t) {
		tableNames = append(tableNames, r.name)
	}
	if !slices.Equal(tableNames, names) {
		t.Errorf("test table = %v, want %v", tableNames, names)
	}
}

// TestDefaults is the contract fixture for the defaults of PLAN.md §8; a
// change here is a protocol change (PLAN.md §4.6).
func TestDefaults(t *testing.T) {
	c := mustLoad(t, requiredEnv())
	for _, tc := range []struct {
		setting   string
		got, want any
	}{
		{"RELAY_UPSTREAM_AUTH", c.Credential == nil, true},
		{"RELAY_UPSTREAM_CA_FILE", c.UpstreamCAs == nil, true},
		{"RELAY_INSTALLATION_IDS", c.InstallationIDs == nil, true},
		{"RELAY_REQUEST_HEADERS", strings.Join(c.RequestHeaders, ","), "Content-Type,Accept"},
		{"RELAY_RESPONSE_HEADERS", strings.Join(c.ResponseHeaders, ","), "Content-Type,Cache-Control,Pragma"},
		{"RELAY_PORT", c.Port, 8080},
		{"RELAY_TLS_CERT_FILE", c.TLSCertificate == nil, true},
		{"RELAY_UPSTREAM_TIMEOUT", c.UpstreamTimeout, 10 * time.Second},
		{"RELAY_MAX_REQUEST_BYTES", c.MaxRequestBytes, int64(65536)},
		{"RELAY_MAX_RESPONSE_BYTES", c.MaxResponseBytes, int64(65536)},
		{"RELAY_MAX_CONCURRENT", c.MaxConcurrent, 50},
		{"RELAY_CLOCK_SKEW", c.ClockSkew, 10 * time.Second},
		{"RELAY_JWKS_URL", c.JWKSURL, "https://forge.cdn.prod.atlassian-dev.net/.well-known/jwks.json"},
		{"RELAY_JWKS_REFRESH", c.JWKSRefresh, 6 * time.Hour},
		{"RELAY_JWKS_MAX_AGE", c.JWKSMaxAge, 24 * time.Hour},
		{"RELAY_SHUTDOWN_GRACE", c.ShutdownGrace, 15 * time.Second},
		{"RELAY_LOG_LEVEL", c.LogLevel, slog.LevelInfo},
	} {
		if tc.got != tc.want {
			t.Errorf("%s default = %v, want %v", tc.setting, tc.got, tc.want)
		}
	}
}

// TestLimits pins the configuration limits of PLAN.md §6 and §8.
func TestLimits(t *testing.T) {
	if config.MaxSettingFileBytes != 65536 {
		t.Errorf("MaxSettingFileBytes = %d", config.MaxSettingFileBytes)
	}
	if config.MaxCAFileBytes != 1048576 {
		t.Errorf("MaxCAFileBytes = %d", config.MaxCAFileBytes)
	}
	if config.MaxPayloadBudget != 67108864 {
		t.Errorf("MaxPayloadBudget = %d", config.MaxPayloadBudget)
	}
	if config.MaxClockSkew != time.Minute {
		t.Errorf("MaxClockSkew = %v", config.MaxClockSkew)
	}
	if config.DefaultJWKSURL != "https://forge.cdn.prod.atlassian-dev.net/.well-known/jwks.json" {
		t.Errorf("DefaultJWKSURL = %q", config.DefaultJWKSURL)
	}
}

// TestErrorsNameSettingWithoutValue proves for every setting, from the
// environment and from a file, that the error names the setting and contains
// neither the value nor the file's path (PLAN.md §8, §13 Config).
func TestErrorsNameSettingWithoutValue(t *testing.T) {
	rows := table(t)
	for _, src := range sources {
		for _, r := range rows {
			t.Run(src.name+"/"+r.name, func(t *testing.T) {
				m := allValid(rows)
				set(t, m, r.name, r.bad, src.viaFile)
				loadError(t, m, r.name)
			})
		}
	}
}

// TestErrorsFollowTableOrder sets every setting from the k-th on to a bad
// value: the error must name the k-th (PLAN.md §8, R-13).
func TestErrorsFollowTableOrder(t *testing.T) {
	rows := table(t)
	for k := range rows {
		m := map[string]string{}
		for i, r := range rows {
			if i < k {
				m[r.name] = r.valid
			} else {
				m[r.name] = r.bad
			}
		}
		loadError(t, m, rows[k].name)
	}
}

func TestErrorNamesSettingThenReason(t *testing.T) {
	err := &config.Error{Setting: "RELAY_PORT", Reason: "reason"}
	if got := err.Error(); got != "RELAY_PORT: reason" {
		t.Errorf("Error() = %q", got)
	}
}

func TestRequiredSettings(t *testing.T) {
	for _, name := range []string{"RELAY_APP_ID", "RELAY_ENVIRONMENT_ID", "RELAY_CLOUD_IDS", "RELAY_UPSTREAM_URL", "RELAY_ROUTES"} {
		t.Run(name, func(t *testing.T) {
			m := requiredEnv()
			delete(m, name)
			if e := loadError(t, m, name); e.Reason != "required" {
				t.Errorf("reason = %q, want required", e.Reason)
			}
		})
	}
}

// TestEmptyValueIsAnError proves that a present but empty setting never
// silently selects the default (PLAN.md §8).
func TestEmptyValueIsAnError(t *testing.T) {
	for _, r := range table(t) {
		t.Run(r.name, func(t *testing.T) {
			if e := loadError(t, with(requiredEnv(), r.name, ""), r.name); !strings.HasPrefix(e.Reason, "empty") {
				t.Errorf("reason = %q", e.Reason)
			}
			m := requiredEnv()
			delete(m, r.name)
			if e := loadError(t, with(m, r.name+"_FILE", ""), r.name+"_FILE"); !strings.HasPrefix(e.Reason, "empty") {
				t.Errorf("reason = %q", e.Reason)
			}
			for _, content := range []string{"", "\n", "\r\n"} {
				path := writeFile(t, "empty", []byte(content))
				if e := loadError(t, with(m, r.name+"_FILE", path), r.name+"_FILE"); e.Reason != "file is empty" {
					t.Errorf("content %q: reason = %q", content, e.Reason)
				}
			}
		})
	}
}

func TestBothValueAndFileIsAnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), marker)
	for _, r := range table(t) {
		t.Run(r.name, func(t *testing.T) {
			// The file does not exist: the conflict is found before any read.
			e := loadError(t, with(requiredEnv(), r.name, r.valid, r.name+"_FILE", missing), r.name)
			if want := "set only one of " + r.name + " and " + r.name + "_FILE"; e.Reason != want {
				t.Errorf("reason = %q, want %q", e.Reason, want)
			}
		})
	}
}

func TestSettingFileReadFailure(t *testing.T) {
	for name, path := range map[string]string{
		"missing_file": filepath.Join(t.TempDir(), marker),
		"directory":    t.TempDir(),
	} {
		t.Run(name, func(t *testing.T) {
			loadError(t, with(requiredEnv(), "RELAY_PORT_FILE", path), "RELAY_PORT_FILE")
		})
	}
}

func TestSettingFileBound(t *testing.T) {
	const prefix = "X-Api-Key: "
	exact := prefix + strings.Repeat("a", config.MaxSettingFileBytes-len(prefix))
	t.Run("exactly_max_accepted", func(t *testing.T) {
		c := mustLoad(t, with(requiredEnv(), "RELAY_UPSTREAM_AUTH_FILE", writeFile(t, "auth", []byte(exact))))
		if got := len(c.Credential.Value.Reveal()); got != config.MaxSettingFileBytes-len(prefix) {
			t.Errorf("credential length = %d", got)
		}
	})
	t.Run("max_plus_one_rejected", func(t *testing.T) {
		path := writeFile(t, "auth", []byte(exact+"a"))
		e := loadError(t, with(requiredEnv(), "RELAY_UPSTREAM_AUTH_FILE", path), "RELAY_UPSTREAM_AUTH_FILE")
		if e.Reason != "file is larger than 65536 bytes" {
			t.Errorf("reason = %q", e.Reason)
		}
	})
}

func TestPEMFileBound(t *testing.T) {
	p := pemFiles(t)
	pad := func(b []byte, n int) []byte {
		return append(slices.Clone(b), bytes.Repeat([]byte("\n"), n-len(b))...)
	}
	for _, tc := range []struct {
		setting string
		data    []byte
		others  []string
	}{
		{"RELAY_UPSTREAM_CA_FILE", p.cert, nil},
		{"RELAY_TLS_CERT_FILE", p.cert, []string{"RELAY_TLS_KEY_FILE", writeFile(t, "key.pem", p.key)}},
		{"RELAY_TLS_KEY_FILE", p.key, []string{"RELAY_TLS_CERT_FILE", writeFile(t, "cert.pem", p.cert)}},
	} {
		base := with(requiredEnv(), tc.others...)
		t.Run(tc.setting+"/exactly_max_accepted", func(t *testing.T) {
			mustLoad(t, with(base, tc.setting, writeFile(t, "f.pem", pad(tc.data, config.MaxCAFileBytes))))
		})
		t.Run(tc.setting+"/max_plus_one_rejected", func(t *testing.T) {
			loadError(t, with(base, tc.setting, writeFile(t, "f.pem", pad(tc.data, config.MaxCAFileBytes+1))), tc.setting)
		})
	}
}

// TestFileLineEnding proves that exactly one trailing "\n" or "\r\n" is
// removed from a _FILE value and nothing else.
func TestFileLineEnding(t *testing.T) {
	for _, tc := range []struct {
		name, content string
		ok            bool
	}{
		{"no_line_ending", "9090", true},
		{"lf_removed", "9090\n", true},
		{"crlf_removed", "9090\r\n", true},
		{"second_lf_kept", "9090\n\n", false},
		{"lone_cr_kept", "9090\r", false},
		{"leading_space_kept", " 9090", false},
		{"trailing_space_kept", "9090 \n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := with(requiredEnv(), "RELAY_PORT_FILE", writeFile(t, "port", []byte(tc.content)))
			if !tc.ok {
				loadError(t, m, "RELAY_PORT")
				return
			}
			if c := mustLoad(t, m); c.Port != 9090 {
				t.Errorf("Port = %d", c.Port)
			}
		})
	}
}

func TestCredentialFromFile(t *testing.T) {
	const value = "Basic " + marker
	envCfg := mustLoad(t, with(requiredEnv(), "RELAY_UPSTREAM_AUTH", "Authorization: "+value))
	fileCfg := mustLoad(t, with(requiredEnv(), "RELAY_UPSTREAM_AUTH_FILE",
		writeFile(t, "auth", []byte("Authorization: "+value+"\r\n"))))
	for _, tc := range []struct {
		name     string
		c        *config.Config
		fromFile bool
	}{{"env", envCfg, false}, {"file", fileCfg, true}} {
		if tc.c.Credential == nil || tc.c.Credential.Name != "Authorization" || tc.c.Credential.Value.Reveal() != value {
			t.Errorf("%s: credential not parsed", tc.name)
		}
		if tc.c.CredentialFromFile != tc.fromFile {
			t.Errorf("%s: CredentialFromFile = %v", tc.name, tc.c.CredentialFromFile)
		}
	}
}

// TestUnsafeHeaderSettings proves that the mandatory exclusions of PLAN.md §5
// override the allowlists and the credential setting, case-insensitively.
func TestUnsafeHeaderSettings(t *testing.T) {
	request := []string{
		"Authorization", "authorization", "Proxy-Authorization", "Host", "HOST", "Content-Length",
		"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "TE", "Trailer",
		"Transfer-Encoding", "Upgrade", "Forwarded", "X-Forwarded-For", "x-forwarded-host",
		"X-Forge-Oauth-System", "x-forge-oauth-user", "X-B3-TraceId", "x-b3-spanid",
		"Relay-Error", "relay-protocol", "Idempotency-Key", "x-idempotency-key",
		"Bad Header", "Bad:Header", "Bad\x01", "Ünicode", "Accept,accept",
	}
	for _, h := range request {
		t.Run("request/"+h, func(t *testing.T) {
			loadError(t, with(requiredEnv(), "RELAY_REQUEST_HEADERS", "Content-Type,"+h), "RELAY_REQUEST_HEADERS")
		})
	}
	response := []string{
		"Content-Length", "Set-Cookie", "set-cookie", "Connection", "Keep-Alive", "Transfer-Encoding",
		"Upgrade", "Trailer", "Proxy-Authenticate", "Relay-Upstream-Status", "relay-version", "Relay-Error",
	}
	for _, h := range response {
		t.Run("response/"+h, func(t *testing.T) {
			loadError(t, with(requiredEnv(), "RELAY_RESPONSE_HEADERS", "Content-Type,"+h), "RELAY_RESPONSE_HEADERS")
		})
	}
	for rule, v := range map[string]string{
		"host":                "Host: " + marker,
		"content_length":      "content-length: 1",
		"transfer_encoding":   "Transfer-Encoding: chunked",
		"connection":          "Connection: close",
		"proxy_authorization": "Proxy-Authorization: " + marker,
		"forwarded":           "Forwarded: for=" + marker,
		"x_forwarded":         "X-Forwarded-For: " + marker,
		"idempotency_key":     "Idempotency-Key: " + marker,
		"x_idempotency_key":   "X-Idempotency-Key: " + marker,
		"relay_header":        "Relay-Error: " + marker,
		"cr_in_value":         "Authorization: Basic " + marker + "\rX",
		"lf_in_value":         "Authorization: Basic " + marker + "\nX",
		"nul_in_value":        "Authorization: Basic " + marker + "\x00",
		"del_in_value":        "Authorization: Basic " + marker + "\x7f",
		"no_colon":            "Authorization " + marker,
		"no_value":            "Authorization:",
		"blank_value":         "Authorization: \t ",
		"invalid_name":        "Bad Name: " + marker,
	} {
		t.Run("credential/"+rule, func(t *testing.T) {
			loadError(t, with(requiredEnv(), "RELAY_UPSTREAM_AUTH", v), "RELAY_UPSTREAM_AUTH")
		})
	}
	t.Run("credential/authorization_allowed", func(t *testing.T) {
		mustLoad(t, with(requiredEnv(), "RELAY_UPSTREAM_AUTH", "Authorization: Basic synthetic"))
	})
}

func TestJWKSAges(t *testing.T) {
	for _, tc := range []struct {
		name            string
		refresh, maxAge string
		setting         string // "" when accepted
	}{
		{"refresh_below_max_age_accepted", "23h59m59s", "24h", ""},
		{"refresh_equal_to_max_age_rejected", "24h", "", "RELAY_JWKS_REFRESH"},
		{"max_age_equal_to_default_refresh_rejected", "", "6h", "RELAY_JWKS_REFRESH"},
		{"refresh_above_max_age_rejected", "25h", "24h", "RELAY_JWKS_REFRESH"},
		{"zero_refresh_rejected", "0s", "", "RELAY_JWKS_REFRESH"},
		{"negative_refresh_rejected", "-1h", "", "RELAY_JWKS_REFRESH"},
		{"zero_max_age_rejected", "", "0s", "RELAY_JWKS_MAX_AGE"},
		{"negative_max_age_rejected", "", "-24h", "RELAY_JWKS_MAX_AGE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := requiredEnv()
			if tc.refresh != "" {
				m["RELAY_JWKS_REFRESH"] = tc.refresh
			}
			if tc.maxAge != "" {
				m["RELAY_JWKS_MAX_AGE"] = tc.maxAge
			}
			if tc.setting == "" {
				mustLoad(t, m)
				return
			}
			loadError(t, m, tc.setting)
		})
	}
}

func TestDurations(t *testing.T) {
	maxTimeout := time.Duration(math.MaxInt64 - int64(5*time.Second)).String()
	for _, tc := range []struct {
		name, setting, value string
		ok                   bool
	}{
		{"timeout_zero_rejected", "RELAY_UPSTREAM_TIMEOUT", "0s", false},
		{"timeout_negative_rejected", "RELAY_UPSTREAM_TIMEOUT", "-1s", false},
		{"timeout_without_unit_rejected", "RELAY_UPSTREAM_TIMEOUT", "10", false},
		{"timeout_overflowing_duration_rejected", "RELAY_UPSTREAM_TIMEOUT", "9999999999h", false},
		{"timeout_overflowing_write_timeout_rejected", "RELAY_UPSTREAM_TIMEOUT", time.Duration(math.MaxInt64).String(), false},
		{"timeout_largest_without_overflow_accepted", "RELAY_UPSTREAM_TIMEOUT", maxTimeout, true},
		{"timeout_one_nanosecond_accepted", "RELAY_UPSTREAM_TIMEOUT", "1ns", true},
		{"skew_zero_accepted", "RELAY_CLOCK_SKEW", "0", true},
		{"skew_negative_rejected", "RELAY_CLOCK_SKEW", "-1ns", false},
		{"skew_at_maximum_accepted", "RELAY_CLOCK_SKEW", "1m", true},
		{"skew_one_nanosecond_over_maximum_rejected", "RELAY_CLOCK_SKEW", "60.000000001s", false},
		{"skew_of_an_hour_rejected", "RELAY_CLOCK_SKEW", "1h", false},
		{"grace_zero_rejected", "RELAY_SHUTDOWN_GRACE", "0s", false},
		{"grace_negative_rejected", "RELAY_SHUTDOWN_GRACE", "-15s", false},
		{"grace_word_rejected", "RELAY_SHUTDOWN_GRACE", "fifteen", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := with(requiredEnv(), tc.setting, tc.value)
			if tc.ok {
				mustLoad(t, m)
				return
			}
			loadError(t, m, tc.setting)
		})
	}
}

// TestPayloadBudget proves the R-4/R-12 check of PLAN.md §6, including
// values whose naive product or sum overflows int64 into an accepted range.
func TestPayloadBudget(t *testing.T) {
	const budget = "RELAY_MAX_CONCURRENT, RELAY_MAX_REQUEST_BYTES, RELAY_MAX_RESPONSE_BYTES"
	for _, tc := range []struct {
		name                          string
		request, response, concurrent string
		ok                            bool
	}{
		{"defaults_accepted", "65536", "65536", "50", true},
		{"exactly_budget_accepted", "33554432", "33554432", "1", true},
		{"exactly_budget_by_concurrency_accepted", "65536", "65536", "512", true},
		{"one_slot_over_budget_rejected", "65536", "65536", "513", false},
		{"one_byte_over_budget_rejected", "33554432", "33554433", "1", false},
		{"limit_sum_one_over_budget_rejected", "67108864", "1", "1", false},
		{"limit_sum_exactly_budget_accepted", "67108863", "1", "1", true},
		{"max_int64_limits_rejected", "9223372036854775807", "9223372036854775807", "1", false},
		{"sum_overflowing_int64_rejected", "4611686018427387904", "4611686018427387904", "1", false},
		{"max_int64_concurrency_rejected", "1", "1", "9223372036854775807", false},
		{"product_wrapping_to_zero_rejected", "2", "2", "4611686018427387904", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := with(requiredEnv(),
				"RELAY_MAX_REQUEST_BYTES", tc.request,
				"RELAY_MAX_RESPONSE_BYTES", tc.response,
				"RELAY_MAX_CONCURRENT", tc.concurrent)
			if tc.ok {
				mustLoad(t, m)
				return
			}
			loadError(t, m, budget)
		})
	}
}

func TestCounts(t *testing.T) {
	bad := []struct{ rule, value string }{
		{"zero_rejected", "0"},
		{"negative_rejected", "-1"},
		{"sign_prefix_rejected", "+1"},
		{"fraction_rejected", "1.5"},
		{"exponent_form_rejected", "1e3"},
		{"leading_space_rejected", " 1"},
		{"trailing_space_rejected", "1 "},
		{"hex_rejected", "0x10"},
		{"digit_separator_rejected", "1_000"},
		{"int64_overflow_rejected", "99999999999999999999"},
		{"non_ascii_digit_rejected", "١"},
	}
	for _, name := range []string{"RELAY_MAX_REQUEST_BYTES", "RELAY_MAX_RESPONSE_BYTES", "RELAY_MAX_CONCURRENT"} {
		for _, tc := range bad {
			t.Run(name+"/"+tc.rule, func(t *testing.T) {
				loadError(t, with(requiredEnv(), name, tc.value), name)
			})
		}
		t.Run(name+"/leading_zeros_accepted", func(t *testing.T) {
			mustLoad(t, with(requiredEnv(), name, "0001"))
		})
	}
}

func TestPort(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        int // 0: rejected
	}{
		{"lowest_port_accepted", "1", 1},
		{"highest_port_accepted", "65535", 65535},
		{"leading_zero_accepted", "08080", 8080},
		{"zero_rejected", "0", 0},
		{"above_max_port_rejected", "65536", 0},
		{"negative_rejected", "-1", 0},
		{"sign_prefix_rejected", "+80", 0},
		{"trailing_letter_rejected", "80a", 0},
		{"leading_space_rejected", " 80", 0},
		{"trailing_newline_rejected", "80\n", 0},
		{"int64_overflow_rejected", "99999999999999999999", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := with(requiredEnv(), "RELAY_PORT", tc.value)
			if tc.want == 0 {
				loadError(t, m, "RELAY_PORT")
				return
			}
			if c := mustLoad(t, m); c.Port != tc.want {
				t.Errorf("Port = %d, want %d", c.Port, tc.want)
			}
		})
	}
}

func TestAppID(t *testing.T) {
	const uuid = "00000000-0000-4000-8000-000000000001"
	for name, v := range map[string]string{
		"uppercase_uuid":      "ari:cloud:ecosystem::app/00000000-0000-4000-8000-00000000000A",
		"missing_prefix":      uuid,
		"uppercase_prefix":    "ARI:cloud:ecosystem::app/" + uuid,
		"other_resource":      "ari:cloud:ecosystem::extension/" + uuid,
		"trailing_text":       appID + "x",
		"trailing_slash":      appID + "/",
		"leading_space":       " " + appID,
		"uuid_without_dashes": "ari:cloud:ecosystem::app/00000000000040008000000000000001",
		"misplaced_dash":      "ari:cloud:ecosystem::app/0000000-00000-4000-8000-000000000001",
		"braced_uuid":         "ari:cloud:ecosystem::app/{00000000-0000-4000-8000-0000000001}",
		"non_hex":             "ari:cloud:ecosystem::app/0000000g-0000-4000-8000-000000000001",
	} {
		t.Run(name, func(t *testing.T) {
			loadError(t, with(requiredEnv(), "RELAY_APP_ID", v), "RELAY_APP_ID")
		})
	}
}

func TestIDs(t *testing.T) {
	long := strings.Repeat("a", 256)
	t.Run("256_bytes_accepted", func(t *testing.T) {
		mustLoad(t, with(requiredEnv(), "RELAY_ENVIRONMENT_ID", long, "RELAY_CLOUD_IDS", long, "RELAY_INSTALLATION_IDS", long))
	})
	bad := map[string]string{
		"257_bytes": long + "a", "space": "a b", "tab": "a\tb", "non_ascii": "é",
		"control": "a\x01", "del": "a\x7f",
	}
	for _, name := range []string{"RELAY_ENVIRONMENT_ID", "RELAY_CLOUD_IDS", "RELAY_INSTALLATION_IDS"} {
		for rule, v := range bad {
			t.Run(name+"/"+rule, func(t *testing.T) {
				loadError(t, with(requiredEnv(), name, v), name)
			})
		}
	}
	t.Run("environment_id_comma", func(t *testing.T) {
		loadError(t, with(requiredEnv(), "RELAY_ENVIRONMENT_ID", "a,b"), "RELAY_ENVIRONMENT_ID")
	})
	for _, name := range []string{"RELAY_CLOUD_IDS", "RELAY_INSTALLATION_IDS"} {
		for _, tc := range []struct{ rule, value, reason string }{
			{"empty_item", "a,,b", "empty list item"},
			{"trailing_comma", "a,", "empty list item"},
			{"leading_comma", ",a", "empty list item"},
			{"blank_item", "a, \t,b", "empty list item"},
			{"duplicate_item", "a,b,a", "duplicate list item"},
			{"duplicate_after_trim", "a, a", "duplicate list item"},
		} {
			t.Run(name+"/"+tc.rule, func(t *testing.T) {
				if e := loadError(t, with(requiredEnv(), name, tc.value), name); e.Reason != tc.reason {
					t.Errorf("reason = %q, want %q", e.Reason, tc.reason)
				}
			})
		}
	}
}

// TestUpstreamAndRoutes checks that the forward parsers guard both settings;
// their rules are tested in internal/forward.
func TestUpstreamAndRoutes(t *testing.T) {
	for name, v := range map[string]string{
		"http":           "http://provider.example",
		"userinfo":       "https://" + marker + "@provider.example",
		"query":          "https://provider.example/?" + marker,
		"fragment":       "https://provider.example/#" + marker,
		"trailing_slash": "https://provider.example/base/",
		"port_zero":      "https://provider.example:0/" + marker,
		"port_too_large": "https://provider.example:65536/" + marker,
	} {
		t.Run("upstream/"+name, func(t *testing.T) {
			loadError(t, with(requiredEnv(), "RELAY_UPSTREAM_URL", v), "RELAY_UPSTREAM_URL")
		})
	}
	for name, v := range map[string]string{
		"reserved_livez":  "GET /livez",
		"reserved_readyz": "GET /readyz",
		"reserved_info":   "GET /relay/v1/info",
		"duplicate":       "POST /a, POST /a",
		"lowercase":       "post /a",
		"dot_segments":    "POST /a/../" + marker,
		"query":           "POST /a?" + marker,
		"two_spaces":      "POST  /a",
		"no_path":         "POST",
		"head":            "HEAD /a",
	} {
		t.Run("routes/"+name, func(t *testing.T) {
			loadError(t, with(requiredEnv(), "RELAY_ROUTES", v), "RELAY_ROUTES")
		})
	}
}

func TestUpstreamCAFile(t *testing.T) {
	p := pemFiles(t)
	crlf := bytes.ReplaceAll(p.cert, []byte("\n"), []byte("\r\n"))
	for _, tc := range []struct {
		name string
		data []byte
		ok   bool
	}{
		{"single_certificate", p.cert, true},
		{"two_certificates_crlf", slices.Concat(crlf, []byte("\r\n"), crlf), true},
		{"surrounding_whitespace", slices.Concat([]byte("\n \t"), p.cert, []byte("\n\n")), true},
		{"comment_before_block", slices.Concat([]byte("# CA\n"), p.cert), false},
		{"text_after_block", slices.Concat(p.cert, []byte(marker)), false},
		{"text_between_blocks", slices.Concat(p.cert, []byte(marker+"\n"), p.cert), false},
		{"damaged_block_before_valid_block", slices.Concat([]byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"), p.cert), false},
		{"unterminated_block", []byte("-----BEGIN CERTIFICATE-----\nAAAA\n"), false},
		{"private_key_block", p.key, false},
		{"certificate_under_other_type", bytes.ReplaceAll(p.cert, []byte(" CERTIFICATE-----"), []byte(" X509 CRL-----")), false},
		{"certificate_then_key", slices.Concat(p.cert, p.key), false},
		{"invalid_certificate_der", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte(marker)}), false},
		{"empty_file", nil, false},
		{"whitespace_only", []byte("\n\n"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := with(requiredEnv(), "RELAY_UPSTREAM_CA_FILE", writeFile(t, marker+".pem", tc.data))
			if !tc.ok {
				loadError(t, m, "RELAY_UPSTREAM_CA_FILE")
				return
			}
			c := mustLoad(t, m)
			// The pool must hold the certificate, not merely exist.
			block, _ := pem.Decode(p.cert)
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cert.Verify(x509.VerifyOptions{
				Roots:       c.UpstreamCAs,
				DNSName:     "localhost",
				CurrentTime: time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC),
			}); err != nil {
				t.Errorf("certificate not trusted by the pool: %v", err)
			}
		})
	}
}

func TestTLSFiles(t *testing.T) {
	p := pemFiles(t)
	cert := writeFile(t, "cert.pem", p.cert)
	key := writeFile(t, "key.pem", p.key)
	const pair = "RELAY_TLS_CERT_FILE, RELAY_TLS_KEY_FILE"
	t.Run("matching_pair_accepted", func(t *testing.T) {
		c := mustLoad(t, with(requiredEnv(), "RELAY_TLS_CERT_FILE", cert, "RELAY_TLS_KEY_FILE", key))
		if c.TLSCertificate == nil || len(c.TLSCertificate.Certificate) != 1 {
			t.Errorf("TLSCertificate not loaded")
		}
	})
	for _, tc := range []struct {
		name, cert, key, setting, reason string
	}{
		{"cert_without_key", cert, "", "RELAY_TLS_KEY_FILE", "required when RELAY_TLS_CERT_FILE is set"},
		{"key_without_cert", "", key, "RELAY_TLS_CERT_FILE", "required when RELAY_TLS_KEY_FILE is set"},
		{"mismatched_key", cert, writeFile(t, "other.pem", p.otherKey), pair, ""},
		{"swapped_files", key, cert, pair, ""},
		{"cert_not_pem", writeFile(t, marker, []byte(marker)), key, pair, ""},
		{"key_not_pem", cert, writeFile(t, marker, []byte(marker)), pair, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := requiredEnv()
			if tc.cert != "" {
				m["RELAY_TLS_CERT_FILE"] = tc.cert
			}
			if tc.key != "" {
				m["RELAY_TLS_KEY_FILE"] = tc.key
			}
			if e := loadError(t, m, tc.setting); tc.reason != "" && e.Reason != tc.reason {
				t.Errorf("reason = %q, want %q", e.Reason, tc.reason)
			}
		})
	}
}

func TestJWKSURL(t *testing.T) {
	t.Run("port_and_path_accepted", func(t *testing.T) {
		mustLoad(t, with(requiredEnv(), "RELAY_JWKS_URL", "https://keys.example:8443/a/jwks.json"))
	})
	t.Run("highest_port_accepted", func(t *testing.T) {
		mustLoad(t, with(requiredEnv(), "RELAY_JWKS_URL", "https://keys.example:65535/jwks.json"))
	})
	t.Run("query_refused_without_echo", func(t *testing.T) {
		// A query can carry a signature or token, and the startup summary
		// logs the URL. Nothing Load returns may repeat it.
		c, unknown, err := config.Load(environ(with(requiredEnv(), "RELAY_JWKS_URL", "https://keys.example/jwks.json?sig="+marker)))
		ce := checkError(t, err, "RELAY_JWKS_URL")
		if want := "want an https URL with a host and no userinfo, query or fragment"; ce.Reason != want {
			t.Errorf("reason = %q, want %q", ce.Reason, want)
		}
		if c != nil || slices.ContainsFunc(unknown, func(u string) bool { return strings.Contains(u, marker) }) {
			t.Errorf("Load returned a config or unknown names %q with the refused URL", unknown)
		}
	})
	for name, v := range map[string]string{
		"query":            "https://keys.example/jwks.json?" + marker,
		"empty_query":      "https://keys.example/jwks.json?",
		"port_zero":        "https://keys.example:0/jwks.json",
		"port_above_65535": "https://keys.example:65536/jwks.json",
		"port_beyond_int":  "https://keys.example:99999999999999999999/jwks.json",
		"http":             "http://keys.example/jwks.json",
		"uppercase_scheme": "HTTPS://keys.example/jwks.json",
		"no_slashes":       "https:keys.example/jwks.json",
		"no_host":          "https:///jwks.json",
		"port_only":        "https://:443/jwks.json",
		"userinfo":         "https://user:" + marker + "@keys.example/jwks.json",
		"empty_userinfo":   "https://@keys.example/jwks.json",
		"fragment":         "https://keys.example/jwks.json#" + marker,
		"empty_fragment":   "https://keys.example/jwks.json#",
		"control_char":     "https://keys.example/" + marker + "\x7f",
	} {
		t.Run(name, func(t *testing.T) {
			loadError(t, with(requiredEnv(), "RELAY_JWKS_URL", v), "RELAY_JWKS_URL")
		})
	}
}

func TestLogLevel(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        slog.Level
	}{
		{"debug_accepted", "debug", slog.LevelDebug},
		{"info_accepted", "info", slog.LevelInfo},
		{"warn_accepted", "warn", slog.LevelWarn},
		{"error_accepted", "error", slog.LevelError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if c := mustLoad(t, with(requiredEnv(), "RELAY_LOG_LEVEL", tc.value)); c.LogLevel != tc.want {
				t.Errorf("LogLevel = %v, want %v", c.LogLevel, tc.want)
			}
		})
	}
	for _, tc := range []struct{ name, value string }{
		{"uppercase_rejected", "INFO"},
		{"capitalized_rejected", "Info"},
		{"alias_rejected", "warning"},
		{"level_offset_rejected", "info+2"},
		{"unknown_level_rejected", "trace"},
		{"leading_space_rejected", " info"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loadError(t, with(requiredEnv(), "RELAY_LOG_LEVEL", tc.value), "RELAY_LOG_LEVEL")
		})
	}
}

func TestUnknownNames(t *testing.T) {
	ca := writeFile(t, "ca.pem", pemFiles(t).cert)
	m := with(requiredEnv(),
		"RELAY_APPID", marker,
		"RELAY_PORT_FILE_FILE", marker,
		"RELAY_", marker,
		// A known name plus _FILE is the file variant, even for a name
		// that itself ends in _FILE.
		"RELAY_UPSTREAM_CA_FILE_FILE", writeFile(t, "ca-path", []byte(ca+"\n")),
		"OTHER_SETTING", marker,
		"relay_port", marker,
	)
	c, unknown, err := config.Load(environ(m))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if want := []string{"RELAY_", "RELAY_APPID", "RELAY_PORT_FILE_FILE"}; !slices.Equal(unknown, want) {
		t.Errorf("unknown = %v, want %v", unknown, want)
	}
	if c.UpstreamCAs == nil {
		t.Errorf("RELAY_UPSTREAM_CA_FILE_FILE not applied")
	}
	t.Run("reported_when_load_fails", func(t *testing.T) {
		_, unknown, err := config.Load([]string{"RELAY_APPID=" + appID})
		checkError(t, err, "RELAY_APP_ID")
		if !slices.Equal(unknown, []string{"RELAY_APPID"}) {
			t.Errorf("unknown = %v", unknown)
		}
	})
	// A ':' typed for '=' puts the credential into the name, and the caller
	// logs unknown names (PLAN.md §10).
	t.Run("malformed_names_replaced_once", func(t *testing.T) {
		env := append(environ(requiredEnv()),
			"RELAY_UPSTREAM_AUTH: Authorization: Basic "+marker+"==",
			"RELAY_"+marker+"=x",
			"RELAY_PORT-FILE=x")
		_, unknown, err := config.Load(env)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if strings.Contains(strings.Join(unknown, ","), marker) {
			t.Fatalf("unknown = %q shows the rejected value", unknown)
		}
		if want := []string{"RELAY_* (malformed name)"}; !slices.Equal(unknown, want) {
			t.Errorf("unknown = %q, want %q", unknown, want)
		}
	})
	t.Run("name_over_64_bytes_replaced", func(t *testing.T) {
		longest := "RELAY_" + strings.Repeat("A", 58)
		_, unknown, err := config.Load(append(environ(requiredEnv()), longest+"=x", longest+"B=x"))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if want := []string{"RELAY_* (malformed name)", longest}; !slices.Equal(unknown, want) {
			t.Errorf("unknown = %q, want %q", unknown, want)
		}
	})
}

func TestEnvironEntries(t *testing.T) {
	env := append(environ(requiredEnv()), "RELAY_PORT", `=C:=C:\relay`, "RELAY_SHUTDOWN_GRACE=1s=2s")
	_, unknown, err := config.Load(env)
	// "RELAY_PORT" without "=" is not a variable; the value of the last
	// entry is everything after the first "=".
	checkError(t, err, "RELAY_SHUTDOWN_GRACE")
	if len(unknown) != 0 {
		t.Errorf("unknown = %v", unknown)
	}
	c, _, err := config.Load(append(environ(requiredEnv()), "RELAY_PORT", `=C:=C:\relay`))
	if err != nil || c.Port != 8080 {
		t.Errorf("entries without a name changed the result: %v", err)
	}
}

func TestRepeatedVariable(t *testing.T) {
	for _, name := range []string{"RELAY_PORT", "RELAY_PORT_FILE"} {
		t.Run(name, func(t *testing.T) {
			path := writeFile(t, "port", []byte("8081"))
			env := append(environ(requiredEnv()), name+"="+path, name+"="+path)
			_, _, err := config.Load(env)
			if e := checkError(t, err, name); e.Reason != "set more than once" {
				t.Errorf("reason = %q", e.Reason)
			}
		})
	}
}

func TestHealthTarget(t *testing.T) {
	portFile := writeFile(t, "port", []byte("9001\n"))
	certPathFile := writeFile(t, "cert-path", []byte("/run/secrets/cert.pem\n"))
	for _, tc := range []struct {
		name    string
		env     []string
		port    int
		tls     bool
		setting string // "" when accepted
	}{
		{"defaults_need_no_other_setting", nil, 8080, false, ""},
		{"port", []string{"RELAY_PORT=9000"}, 9000, false, ""},
		{"port_file", []string{"RELAY_PORT_FILE=" + portFile}, 9001, false, ""},
		// Only the presence of the certificate setting matters; the file is
		// not read.
		{"tls_cert_set", []string{"RELAY_TLS_CERT_FILE=/run/secrets/cert.pem"}, 8080, true, ""},
		{"tls_cert_file_set", []string{"RELAY_TLS_CERT_FILE_FILE=" + certPathFile}, 8080, true, ""},
		{"bad_port", []string{"RELAY_PORT=0"}, 0, false, "RELAY_PORT"},
		{"port_conflict", []string{"RELAY_PORT=9000", "RELAY_PORT_FILE=" + portFile}, 0, false, "RELAY_PORT"},
		{"empty_tls_cert", []string{"RELAY_TLS_CERT_FILE="}, 0, false, "RELAY_TLS_CERT_FILE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port, useTLS, err := config.HealthTarget(tc.env)
			if tc.setting != "" {
				checkError(t, err, tc.setting)
				return
			}
			if err != nil || port != tc.port || useTLS != tc.tls {
				t.Errorf("HealthTarget = %d, %v, %v; want %d, %v", port, useTLS, err, tc.port, tc.tls)
			}
		})
	}
}

func TestSummary(t *testing.T) {
	rows := table(t)
	var names []string
	for _, r := range rows {
		names = append(names, r.name)
	}
	const secret = "X-Api-Key: " + marker
	defaults := mustLoad(t, requiredEnv())
	fromEnv := mustLoad(t, with(allValid(rows), "RELAY_UPSTREAM_AUTH", secret))
	m := allValid(rows)
	set(t, m, "RELAY_UPSTREAM_AUTH", secret, true)
	fromFile := mustLoad(t, m)

	for _, tc := range []struct {
		name string
		c    *config.Config
		want map[string]string
	}{
		{"defaults", defaults, map[string]string{
			"RELAY_UPSTREAM_AUTH": "not set", "RELAY_UPSTREAM_CA_FILE": "system bundle",
			"RELAY_INSTALLATION_IDS": "any", "RELAY_TLS_CERT_FILE": "off", "RELAY_TLS_KEY_FILE": "off",
			"RELAY_PORT": "8080", "RELAY_LOG_LEVEL": "info", "RELAY_UPSTREAM_TIMEOUT": "10s",
			"RELAY_ROUTES": "POST /oidc/token", "RELAY_REQUEST_HEADERS": "Content-Type,Accept",
		}},
		{"credential_from_env", fromEnv, map[string]string{
			"RELAY_UPSTREAM_AUTH": "set", "RELAY_UPSTREAM_CA_FILE": "set",
			"RELAY_INSTALLATION_IDS": "install-1,install-2", "RELAY_TLS_CERT_FILE": "set",
			"RELAY_LOG_LEVEL": "debug", "RELAY_CLOUD_IDS": cloudID + ",site-2",
		}},
		{"credential_from_file", fromFile, map[string]string{"RELAY_UPSTREAM_AUTH": "set (from file)"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attrs := tc.c.Summary()
			var keys []string
			for _, a := range attrs {
				keys = append(keys, a.Key)
				if want, ok := tc.want[a.Key]; ok && a.Value.String() != want {
					t.Errorf("%s = %q, want %q", a.Key, a.Value.String(), want)
				}
			}
			if !slices.Equal(keys, names) {
				t.Errorf("keys = %v, want every setting in table order", keys)
			}
			var out bytes.Buffer
			slog.New(slog.NewJSONHandler(&out, nil)).LogAttrs(t.Context(), slog.LevelInfo, "startup", attrs...)
			if strings.Contains(out.String(), marker) {
				t.Errorf("summary shows the credential: %s", out.String())
			}
		})
	}
}
