// SPDX-License-Identifier: EUPL-1.2

// Command load is the acceptance load generator for the relay (PLAN.md §11,
// §13 "Before v1.0.0"). It is run by hand against a running relay:
//
//	go run ./test/load -relay http://127.0.0.1:8080
//
// It plays both parties the relay talks to. At start it generates an RSA
// test key and a throwaway CA, serves the JWKS and a fake upstream token
// endpoint over HTTPS, prints the settings the relay needs and waits for the
// relay's /readyz. Then it runs the selected scenarios while probing /livez
// and /readyz, and prints per scenario the outcome counts, latency
// percentiles, errors and health-probe failures.
//
// Nothing is read from disk: every key and token exists only for the run,
// and the CA certificate is the only file written, so the relay can trust
// the fixture. Measuring the relay's memory, CPU and connections is left to
// the container tools; PLAN.md §13 says what to record.
//
// The exit status is 0 when every scenario passed its checks, 1 when one
// failed or the run could not start, and 2 for invalid flags.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	exitOK     = 0
	exitFailed = 1
	exitUsage  = 2
)

// Flag defaults. The body sizes and workers default to the relay's own
// limits and twice its concurrency cap (PLAN.md §8), and the connections to
// twice the proxy's ProxyMaxConnections (§6): the acceptance run must go
// beyond every limit with full-sized bodies (§13).
const (
	defaultRelay         = "http://127.0.0.1:8080"
	defaultListen        = "127.0.0.1:9443"
	defaultCAOut         = "load-ca.pem" // *.pem is in .gitignore
	defaultScenarios     = "full,invalid,unknown-kid,slow-headers,idle"
	defaultDuration      = 30 * time.Second
	defaultWorkers       = 100
	defaultConns         = 200
	defaultBodyBytes     = 64 << 10
	defaultUpstreamDelay = 100 * time.Millisecond
	defaultSlowInterval  = time.Second
	defaultReadyTimeout  = 2 * time.Minute
)

// Flag bounds, so that a mistyped flag cannot make the generator exhaust the
// machine whose relay it measures (CONTRIBUTING.md, bound everything).
const (
	maxWorkers       = 10000
	maxConns         = 10000
	maxBodyBytes     = 16 << 20
	maxDuration      = 72 * time.Hour // the soak in PLAN.md §13
	maxUpstreamDelay = time.Minute
	maxSlowInterval  = time.Minute
	maxReadyTimeout  = time.Hour
	maxHostBytes     = 253 // a DNS name
	caFileMode       = 0o644
)

// errUsage reports a flag error that the flag package has already printed.
var errUsage = errors.New("usage")

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// options are the validated flags.
type options struct {
	relay         target
	probeBase     string
	listen        string
	host          string
	caOut         string
	scenarios     []scenario
	duration      time.Duration
	workers       int
	conns         int
	bodyBytes     int
	responseBytes int
	upstreamDelay time.Duration
	slowInterval  time.Duration
	readyTimeout  time.Duration
}

func run(args []string, stdout, stderr io.Writer) int {
	o, err := parseOptions(args, stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case errors.Is(err, errUsage):
		return exitUsage
	case err != nil:
		fmt.Fprintln(stderr, "load:", err)
		return exitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := load(ctx, o, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "load:", err)
		return exitFailed
	}
	return exitOK
}

var (
	// errFailed reports that a scenario failed a check; its report says which.
	errFailed      = errors.New("a scenario failed its checks")
	errInterrupted = errors.New("interrupted")
)

// load starts the fixture, waits for the relay and runs the scenarios. The
// fixture server's goroutine exits when load returns.
func load(ctx context.Context, o options, stdout, stderr io.Writer) error {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	doc, err := jwksDocument(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	caPEM, cert, err := newCertificates(o.host, time.Now())
	if err != nil {
		return fmt.Errorf("certificates: %w", err)
	}
	caPath, err := filepath.Abs(o.caOut)
	if err != nil {
		return fmt.Errorf("-ca-out: %w", err)
	}
	if err := os.WriteFile(caPath, caPEM, caFileMode); err != nil {
		return fmt.Errorf("-ca-out: %w", err)
	}
	ln, err := net.Listen("tcp", o.listen)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	f := &fixture{
		jwks:         doc,
		requestBody:  fill(o.bodyBytes, "request-body-"),
		responseBody: fill(o.responseBytes, "response-body-"),
		delay:        o.upstreamDelay,
	}
	srv := newFixtureServer(f, cert, stderr)
	served := make(chan error, 1)
	go func() { served <- srv.ServeTLS(ln, "", "") }()
	defer func() {
		// Close only reports the listener's close error; the run is over.
		_ = srv.Close()
		<-served
	}()

	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	printSettings(stdout, "https://"+net.JoinHostPort(o.host, port), caPath)

	pc := probeClient()
	fmt.Fprintf(stderr, "load: waiting up to %s for %s/readyz\n", o.readyTimeout, o.probeBase)
	rctx, cancel := context.WithTimeout(ctx, o.readyTimeout)
	err = waitReady(rctx, pc, o.probeBase)
	cancel()
	switch {
	case ctx.Err() != nil:
		return errInterrupted
	case err != nil:
		return errors.New("the relay did not become ready; check its log and the settings above")
	}

	e := &env{
		relay:        o.relay,
		dial:         relayDialer(o.relay),
		probe:        pc,
		probeBase:    o.probeBase,
		fits:         newMinter(key, time.Now),
		fixture:      f,
		workers:      o.workers,
		conns:        o.conns,
		slowInterval: o.slowInterval,
	}
	if err := preflight(ctx, e); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\nrelay %s, %d workers, %d connections, %d-byte requests, %d-byte responses, upstream delay %s, %s per scenario\n",
		o.relay.base, o.workers, o.conns, o.bodyBytes, o.responseBytes, o.upstreamDelay, o.duration)
	fmt.Fprintf(stdout, "percentiles are histogram bucket bounds, at most 1/%d above the measured value\n", histogramSub)
	var failed []string
	for _, s := range o.scenarios {
		fmt.Fprintf(stderr, "load: running %s for %s\n", s.name, o.duration)
		r := runScenario(ctx, e, s, o.duration)
		printResult(stdout, r)
		if len(r.failures) > 0 {
			failed = append(failed, s.name)
		}
		if ctx.Err() != nil {
			return errInterrupted
		}
	}
	if len(failed) > 0 {
		fmt.Fprintf(stdout, "\nFAILED: %s\n", strings.Join(failed, ", "))
		return errFailed
	}
	fmt.Fprintln(stdout, "\nall scenarios passed")
	return nil
}

// printSettings prints what the relay needs, in env-file form. The site,
// environment and app pins are the synthetic identities the FITs carry
// (PLAN.md D5, §8).
func printSettings(w io.Writer, fixtureURL, caPath string) {
	fmt.Fprintf(w, `Start the relay with these settings (env-file form),
and restart it for every run: the signing key and the CA are new each time.
RELAY_UPSTREAM_CA_FILE and SSL_CERT_FILE make it trust the fixture's CA for the upstream
and the JWKS. Go honours SSL_CERT_FILE on Linux, as in the relay image, but not on macOS
or Windows. Paths are on this machine; mount the file when the relay runs in a container.

RELAY_APP_ID=%s
RELAY_ENVIRONMENT_ID=%s
RELAY_CLOUD_IDS=%s
RELAY_UPSTREAM_URL=%s
RELAY_UPSTREAM_ANY_HOST=true
RELAY_JWKS_URL=%s
RELAY_UPSTREAM_CA_FILE=%s
SSL_CERT_FILE=%s

`, appID, environmentID, cloudID, fixtureURL, fixtureURL+jwksPath, caPath, caPath)
}

func printResult(w io.Writer, r result) {
	fmt.Fprintf(w, "\n== %s\n", r.name)
	row(w, "duration", r.elapsed.Round(time.Millisecond).String())
	row(w, r.unit, strconv.FormatInt(r.count, 10))
	rows(w, "outcomes", r.outcomes)
	if r.timed == 0 {
		row(w, r.timing, "none measured")
	} else {
		row(w, r.timing, fmt.Sprintf("p50 %s  p95 %s  p99 %s", short(r.p50), short(r.p95), short(r.p99)))
	}
	rows(w, "errors", r.errors)
	row(w, "health probes", fmt.Sprintf("%d sent, slowest %s", r.probe.sent, short(r.probe.slowest)))
	rows(w, "probe failures", r.probe.failures)
	row(w, "upstream calls", strconv.FormatInt(r.upstreamCalls, 10))
	row(w, "jwks fetches", strconv.FormatInt(r.jwksFetches, 10))
	if len(r.failures) == 0 {
		row(w, "result", "ok")
	} else {
		row(w, "result", "FAIL: "+strings.Join(r.failures, "; "))
	}
}

// short rounds d to about three significant digits. The percentiles are
// bucket bounds up to 1/histogramSub above the measured value, so more
// digits would claim a precision they lack.
func short(d time.Duration) string {
	switch {
	case d >= time.Second:
		return d.Round(time.Millisecond).String()
	case d >= time.Millisecond:
		return d.Round(10 * time.Microsecond).String()
	}
	return d.String()
}

func row(w io.Writer, label, value string) { fmt.Fprintf(w, "  %-16s %s\n", label, value) }

func rows(w io.Writer, label string, m map[string]int64) {
	if len(m) == 0 {
		row(w, label, "none")
		return
	}
	for _, k := range slices.Sorted(maps.Keys(m)) {
		row(w, label, fmt.Sprintf("%-28s %d", k, m[k]))
		label = ""
	}
}

func parseOptions(args []string, stderr io.Writer) (options, error) {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: go run ./test/load [flags]

Runs the acceptance load scenarios of PLAN.md §13 against a running relay:
  full          -c workers above the concurrency cap, full-sized bodies, valid FITs
  invalid       a flood of FITs with invalid signatures
  unknown-kid   FITs that each name a new unknown key ID
  slow-headers  -conns connections writing headers one byte per -slow-interval;
                -duration must exceed the 5 s header timeout (PLAN.md §6)
  idle          -conns idle keep-alive connections

Flags:
`)
		fs.PrintDefaults()
	}
	relay := fs.String("relay", defaultRelay, "relay `URL`, or the reverse proxy in front of it; https trusts the system CAs")
	probe := fs.String("probe", "", "`URL` for the /livez and /readyz probes (default -relay); point it at the relay\nwhen -relay is the proxy, as orchestrator probes bypass it (PLAN.md §6)")
	listen := fs.String("listen", defaultListen, "`address` of the HTTPS JWKS and fake upstream")
	host := fs.String("host", "", "`name` or IP the relay uses to reach -listen (default its host)")
	caOut := fs.String("ca-out", defaultCAOut, "`file` to write the fixture's CA certificate to, as PEM")
	names := fs.String("scenario", defaultScenarios, "comma-separated `list` of scenarios to run")
	duration := fs.Duration("duration", defaultDuration, "how long each scenario runs")
	workers := fs.Int("c", defaultWorkers, "concurrent `workers` in the request scenarios")
	conns := fs.Int("conns", defaultConns, "`connections` in slow-headers and idle")
	bodyBytes := fs.Int("body-bytes", defaultBodyBytes, "request body `bytes` in full")
	responseBytes := fs.Int("response-bytes", defaultBodyBytes, "fake upstream answer `bytes`")
	upstreamDelay := fs.Duration("upstream-delay", defaultUpstreamDelay, "fake upstream delay, which keeps more requests in flight than the relay's cap")
	slowInterval := fs.Duration("slow-interval", defaultSlowInterval, "time between the bytes of a slow request")
	readyTimeout := fs.Duration("ready-timeout", defaultReadyTimeout, "how long to wait for the relay's /readyz")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return options{}, err
		}
		return options{}, errUsage
	}
	if fs.NArg() > 0 {
		return options{}, errors.New("unexpected arguments")
	}

	o := options{
		listen:        *listen,
		caOut:         *caOut,
		duration:      *duration,
		workers:       *workers,
		conns:         *conns,
		bodyBytes:     *bodyBytes,
		responseBytes: *responseBytes,
		upstreamDelay: *upstreamDelay,
		slowInterval:  *slowInterval,
		readyTimeout:  *readyTimeout,
	}
	var err error
	if o.relay, err = parseTarget(*relay); err != nil {
		return options{}, fmt.Errorf("-relay: %w", err)
	}
	o.probeBase = o.relay.base
	if *probe != "" {
		p, err := parseTarget(*probe)
		if err != nil {
			return options{}, fmt.Errorf("-probe: %w", err)
		}
		o.probeBase = p.base
	}
	if o.host, err = fixtureHost(*listen, *host); err != nil {
		return options{}, err
	}
	if o.scenarios, err = parseScenarios(*names); err != nil {
		return options{}, fmt.Errorf("-scenario: %w", err)
	}
	switch {
	case o.caOut == "":
		return options{}, errors.New("-ca-out is required")
	case o.duration <= 0 || o.duration > maxDuration:
		return options{}, fmt.Errorf("-duration must be above 0 and at most %s", maxDuration)
	case o.workers < 1 || o.workers > maxWorkers:
		return options{}, fmt.Errorf("-c must be 1 to %d", maxWorkers)
	case o.conns < 1 || o.conns > maxConns:
		return options{}, fmt.Errorf("-conns must be 1 to %d", maxConns)
	case o.bodyBytes < 0 || o.bodyBytes > maxBodyBytes:
		return options{}, fmt.Errorf("-body-bytes must be 0 to %d", maxBodyBytes)
	case o.responseBytes < 0 || o.responseBytes > maxBodyBytes:
		return options{}, fmt.Errorf("-response-bytes must be 0 to %d", maxBodyBytes)
	case o.upstreamDelay < 0 || o.upstreamDelay > maxUpstreamDelay:
		return options{}, fmt.Errorf("-upstream-delay must be 0 to %s", maxUpstreamDelay)
	case o.slowInterval <= 0 || o.slowInterval > maxSlowInterval:
		return options{}, fmt.Errorf("-slow-interval must be above 0 and at most %s", maxSlowInterval)
	case o.readyTimeout <= 0 || o.readyTimeout > maxReadyTimeout:
		return options{}, fmt.Errorf("-ready-timeout must be above 0 and at most %s", maxReadyTimeout)
	}
	return o, nil
}

// parseTarget accepts an http or https origin. A path, query or userinfo
// would be silently dropped, so they are refused instead.
func parseTarget(raw string) (target, error) {
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return target{}, errors.New("not a URL")
	case u.Scheme != "http" && u.Scheme != "https", u.Host == "", u.Hostname() == "",
		u.User != nil, u.Opaque != "", u.Path != "" && u.Path != "/",
		u.RawQuery != "", u.ForceQuery, u.Fragment != "":
		return target{}, errors.New("want http:// or https:// with a host and nothing after it")
	}
	port := u.Port()
	switch {
	case port != "":
	case u.Scheme == "https":
		port = "443"
	default:
		port = "80"
	}
	return target{
		base:       u.Scheme + "://" + u.Host,
		host:       u.Host,
		addr:       net.JoinHostPort(u.Hostname(), port),
		tls:        u.Scheme == "https",
		serverName: u.Hostname(),
	}, nil
}

// fixtureHost returns the host the relay's settings name for the fixture,
// which its certificate must also name. A wildcard listen address names no
// host the relay could reach, so -host is then required.
func fixtureHost(listen, host string) (string, error) {
	lh, _, err := net.SplitHostPort(listen)
	if err != nil {
		return "", errors.New("-listen must be host:port")
	}
	if host == "" {
		if lh == "" || net.ParseIP(lh).IsUnspecified() {
			return "", errors.New("-host is required when -listen has no specific host")
		}
		host = lh
	}
	if net.ParseIP(host) == nil && !dnsName(host) {
		return "", errors.New("-host must be an IP address or a DNS name")
	}
	return host, nil
}

func dnsName(s string) bool {
	if s == "" || len(s) > maxHostBytes || s[0] == '-' || s[0] == '.' {
		return false
	}
	for _, c := range []byte(s) {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// parseScenarios returns the named scenarios in the order given.
func parseScenarios(list string) ([]scenario, error) {
	all := allScenarios()
	var picked []scenario
	for name := range strings.SplitSeq(list, ",") {
		i := slices.IndexFunc(all, func(s scenario) bool { return s.name == name })
		switch {
		case i < 0:
			return nil, fmt.Errorf("unknown scenario %q", name)
		case slices.ContainsFunc(picked, func(s scenario) bool { return s.name == name }):
			return nil, fmt.Errorf("scenario %q given twice", name)
		}
		picked = append(picked, all[i])
	}
	return picked, nil
}
