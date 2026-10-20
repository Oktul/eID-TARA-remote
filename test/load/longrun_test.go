// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"bytes"
	"context"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestTimelineFailures(t *testing.T) {
	const (
		refresh  = 30 * time.Second
		maxAge   = 2 * time.Minute
		restored = maxAge + outageOverrun
	)
	type answer struct {
		outcome string
		at      time.Duration
	}
	// healthy is a relay that keeps its keys until 1m45s, refuses until the
	// JWKS is back at 3m and forwards again 20 s later.
	healthy := []answer{
		{outcomeForwarded, time.Second},
		{outcomeForwarded, 105*time.Second - time.Second},
		{outcomeNotReady, 105 * time.Second},
		{outcomeNotReady, restored - time.Second},
		{outcomeNotReady, restored + 10*time.Second},
		{outcomeForwarded, restored + 20*time.Second},
		{outcomeForwarded, restored + 2*time.Minute},
	}
	cases := []struct {
		name    string
		answers []answer
		want    string // a substring of the one failure, or "" for none
	}{
		{"healthy_relay_passes", healthy, ""},
		{"expiry_at_the_earliest_bound_passes", []answer{
			{outcomeNotReady, maxAge - refresh}, {outcomeForwarded, restored + time.Second},
		}, ""},
		{"expiry_at_max_age_passes", []answer{
			{outcomeNotReady, maxAge}, {outcomeForwarded, restored + time.Second},
		}, ""},
		{"keys_never_expire", []answer{
			{outcomeForwarded, time.Second}, {outcomeForwarded, restored - time.Second}, {outcomeForwarded, restored + time.Second},
		}, "never expired"},
		{"keys_expire_early", []answer{
			{outcomeNotReady, time.Minute}, {outcomeForwarded, restored + time.Second},
		}, "before 1m30s"},
		{"keys_trusted_past_max_age", []answer{
			{outcomeForwarded, maxAge + 20*time.Second}, {outcomeNotReady, maxAge + 30*time.Second},
			{outcomeForwarded, restored + time.Second},
		}, "past RELAY_JWKS_MAX_AGE"},
		{"forwarded_after_expiry", []answer{
			{outcomeNotReady, 100 * time.Second}, {outcomeForwarded, 110 * time.Second},
			{outcomeForwarded, restored + time.Second},
		}, "after the keys had expired"},
		{"no_recovery", []answer{
			{outcomeNotReady, 100 * time.Second}, {outcomeNotReady, restored + 2*time.Minute},
		}, "nothing was forwarded"},
		{"slow_recovery", []answer{
			{outcomeNotReady, 100 * time.Second}, {outcomeForwarded, restored + relayRetryMax + 10*time.Second},
		}, "more than the 1m0s retry interval"},
		{"expired_again_after_recovery", []answer{
			{outcomeNotReady, 100 * time.Second}, {outcomeForwarded, restored + time.Second},
			{outcomeNotReady, restored + time.Minute},
		}, "not_ready again"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tl := newTimeline(restored)
			// Concurrent requests finish in any order; record the answers
			// backwards so the timeline cannot rely on their order.
			for i := len(tc.answers) - 1; i >= 0; i-- {
				tl.record(tc.answers[i].outcome, tc.answers[i].at)
			}
			got := tl.failures(refresh, maxAge)
			switch {
			case tc.want == "" && len(got) > 0:
				t.Errorf("failures = %q, want none", got)
			case tc.want != "" && (len(got) != 1 || !strings.Contains(got[0], tc.want)):
				t.Errorf("failures = %q, want one naming %q", got, tc.want)
			}
		})
	}
}

func TestTimelineNotesNameUnseenMoments(t *testing.T) {
	tl := newTimeline(3 * time.Minute)
	tl.record(outcomeNotReady, 105*time.Second)
	want := [][2]string{{"jwks restored", "3m0s"}, {"keys expired", "1m45s"}, {"forwarding back", "never"}}
	got := tl.notes()
	if len(got) != len(want) {
		t.Fatalf("notes = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("note %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestVerdictKeysExpire(t *testing.T) {
	s := scenarioNamed(t, "jwks-outage")
	cases := []struct {
		name     string
		failures map[string]int64
		checks   []string
		fails    bool
	}{
		{"readyz_reporting_expiry_passes", map[string]int64{readyzExpired: 4}, nil, false},
		{"readyz_never_failing_fails", map[string]int64{}, nil, true},
		{"livez_failing_fails", map[string]int64{readyzExpired: 4, "/livez status 503": 1}, nil, true},
		{"readyz_timeout_fails", map[string]int64{readyzExpired: 4, "/readyz timeout": 1}, nil, true},
		{"other_readyz_503_fails", map[string]int64{readyzExpired: 4, "/readyz status 503": 1}, nil, true},
		{"failed_timeline_check_fails", map[string]int64{readyzExpired: 4}, []string{"keys never expired"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := result{
				elapsed:  5 * time.Minute,
				outcomes: map[string]int64{outcomeForwarded: 10, outcomeNotReady: 5},
				errors:   map[string]int64{},
				probe:    probeTally{failures: tc.failures},
				checks:   tc.checks,
			}
			if got := verdict(s, r); (len(got) > 0) != tc.fails {
				t.Errorf("verdict = %q, want failing %v", got, tc.fails)
			}
		})
	}
	// Other scenarios still fail on a /readyz 503, which during them means
	// the relay lost its keys for no reason.
	r := result{
		outcomes: map[string]int64{outcomeForwarded: 1, outcomeTooBusy: 1},
		errors:   map[string]int64{},
		probe:    probeTally{failures: map[string]int64{readyzExpired: 1}},
	}
	if got := verdict(scenarioNamed(t, "full"), r); len(got) == 0 {
		t.Error("full passed with a failed /readyz probe")
	}
}

func TestHealthExpiryRequiresTheRelayNotReadyAnswer(t *testing.T) {
	for _, tc := range []struct {
		name, code, protocol, contentType, body string
		want                                    string
	}{
		{"expiry", "not_ready", "1", "application/json", `{"error":"not_ready"}`, "503 not_ready"},
		{"overload", "too_busy", "1", "application/json", `{"error":"too_busy"}`, "status 503"},
		{"proxy", "", "", "text/html", "unavailable", "status 503"},
		{"wrong_protocol", "not_ready", "2", "application/json", `{"error":"not_ready"}`, "status 503"},
		{"wrong_body", "not_ready", "1", "application/json", `{"error":"internal_error"}`, "status 503"},
		{"wrong_content_type", "not_ready", "1", "text/plain", `{"error":"not_ready"}`, "status 503"},
		{"oversized", "not_ready", "1", "application/json", strings.Repeat("x", maxSmallBody+1), "response_too_large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: 503, Request: r,
					Header: http.Header{"Relay-Error": {tc.code}, "Relay-Protocol": {tc.protocol}, "Content-Type": {tc.contentType}},
					Body:   io.NopCloser(strings.NewReader(tc.body)),
				}, nil
			})}
			if got := healthCheck(t.Context(), c, "http://relay.test/readyz"); got != tc.want {
				t.Errorf("healthCheck = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFixtureAnswers503WhileTheJWKSIsDown(t *testing.T) {
	f := &fixture{jwks: []byte(`{"keys":[]}`)}
	base, c := newTestFixture(t, f)
	get := func() int {
		t.Helper()
		resp, err := c.Get(base + jwksPath)
		if err != nil {
			t.Fatal(err)
		}
		// Only the status matters; a close error cannot change it.
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	f.jwksDown.Store(true)
	if got := get(); got != http.StatusServiceUnavailable {
		t.Errorf("down: status %d, want 503", got)
	}
	f.jwksDown.Store(false)
	if got := get(); got != http.StatusOK {
		t.Errorf("back: status %d, want 200", got)
	}
	if n := f.jwksFetches.Load(); n != 2 {
		t.Errorf("jwks fetches = %d, want 2: a failed fetch counts too", n)
	}
}

func TestTallyWindowsSplitEveryRecordOnce(t *testing.T) {
	tl := newTally()
	tl.add("before the window")
	tl.openWindow()
	tl.addTimed(outcomeForwarded, time.Millisecond)
	tl.fail("timeout")
	first := tl.swapWindow().result()
	tl.addTimed(outcomeForwarded, time.Millisecond)
	tl.flag("body_mismatch")
	second := tl.swapWindow().result()

	if first.count != 2 || first.outcomes[outcomeForwarded] != 1 || first.errors["timeout"] != 1 {
		t.Errorf("first window = %d, %v, %v", first.count, first.outcomes, first.errors)
	}
	if second.count != 1 || second.errors["body_mismatch"] != 1 || second.errors["timeout"] != 0 {
		t.Errorf("second window = %d, %v, %v", second.count, second.outcomes, second.errors)
	}
	if all := tl.result(); all.count != 4 || all.outcomes[outcomeForwarded] != 2 || all.timed != 2 {
		t.Errorf("total = %d, %v, %d timed", all.count, all.outcomes, all.timed)
	}
}

func TestPacedCountsBacklogInsteadOfQueueing(t *testing.T) {
	release := make(chan struct{})
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.Header().Set("Relay-Error", "invalid_token")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer relay.Close()
	defer close(release) // before Close, which waits for the handler
	target, err := parseTarget(relay.URL)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{responseBody: fill(10, "response-body-")}
	e := &env{relay: target, fixture: f, workers: 1, rate: 100}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	tl := newTally()
	var seen atomic.Int64
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		paced(ctx, t.Context(), e, tl, func(int) (string, []byte, error) { return "token", nil, nil },
			func(string, time.Time) { seen.Add(1) })
	}()
	<-ctx.Done()
	release <- struct{}{} // the one request in flight may now finish
	<-stopped
	r := tl.result()
	if r.outcomes[outcomeInvalid] != 1 || seen.Load() != 1 || r.errors["backlog"] == 0 {
		t.Errorf("outcomes %v, errors %v, seen %d; want one answer and the rest backlog", r.outcomes, r.errors, seen.Load())
	}
}

// soakRelay answers like the relay: a body is a valid request, which it
// forwards, and an empty one a bad signature. countUpstream says which of
// them reach the fixture's upstream counter.
func soakRelay(t *testing.T, f *fixture, stopAfter int64, cancel context.CancelFunc, countUpstream func(valid bool) bool) *httptest.Server {
	var served atomic.Int64
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if served.Add(1) >= stopAfter {
			cancel()
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		valid := len(body) > 0
		if countUpstream(valid) {
			f.upstreamCalls.Add(1)
		}
		if !valid {
			w.Header().Set("Relay-Error", "invalid_token")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !bytes.Equal(body, f.requestBody) {
			t.Error("request body differs")
		}
		w.Header().Set("Relay-Upstream-Status", "200")
		_, _ = w.Write(f.responseBody) // a failed write fails the client, which the test checks
	}))
}

func TestSoakMixesInvalidRequestsAndReportsWindows(t *testing.T) {
	const stopAfter = 40
	cases := []struct {
		name          string
		countUpstream func(valid bool) bool
		wantCheck     bool
	}{
		{"rejected_requests_stay_local", func(valid bool) bool { return valid }, false},
		{"rejected_requests_reaching_upstream_fail", func(bool) bool { return true }, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &fixture{requestBody: fill(100, "request-body-"), responseBody: fill(200, "response-body-")}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			relay := soakRelay(t, f, stopAfter, cancel, tc.countUpstream)
			defer relay.Close()
			target, err := parseTarget(relay.URL)
			if err != nil {
				t.Fatal(err)
			}
			var progress bytes.Buffer
			e := &env{
				relay: target, fits: newMinter(key(t), time.Now), fixture: f,
				workers: 4, rate: 200, reportEvery: 50 * time.Millisecond, progress: &progress,
			}
			tl := newTally()
			soak(ctx, t.Context(), e, tl)
			r := tl.result()
			want := map[string]int64{outcomeForwarded: r.outcomes[outcomeForwarded], outcomeInvalid: r.outcomes[outcomeInvalid]}
			if !maps.Equal(r.outcomes, want) || r.outcomes[outcomeInvalid] == 0 || r.outcomes[outcomeForwarded] < 8*r.outcomes[outcomeInvalid] {
				t.Errorf("outcomes = %v, want forwarded and one in ten invalid", r.outcomes)
			}
			if len(r.errors) > 0 {
				t.Errorf("errors = %v", r.errors)
			}
			if !strings.Contains(progress.String(), "requests") || !strings.Contains(progress.String(), "jwks fetches") {
				t.Errorf("no progress line in %q", progress.String())
			}
			if (len(r.checks) > 0) != tc.wantCheck {
				t.Errorf("checks = %q, want failing %v", r.checks, tc.wantCheck)
			}
		})
	}
}

func TestParseOptionsPacedDefaultsAndBounds(t *testing.T) {
	o, err := parseOptions(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if o.rate != 5 || o.reportEvery != 5*time.Minute || o.jwksRefresh != 30*time.Second || o.jwksMaxAge != 2*time.Minute {
		t.Errorf("paced options = %d, %s, %s, %s", o.rate, o.reportEvery, o.jwksRefresh, o.jwksMaxAge)
	}
	for name, args := range map[string][]string{
		"zero_rate":                {"-rate", "0"},
		"rate_over_max":            {"-rate", "1001"},
		"report_every_under_min":   {"-report-every", "500ms"},
		"report_every_over_max":    {"-report-every", "25h"},
		"zero_jwks_refresh":        {"-jwks-refresh", "0s"},
		"refresh_equal_to_max_age": {"-jwks-refresh", "2m", "-jwks-max-age", "2m"},
		"refresh_above_max_age":    {"-jwks-refresh", "3m"},
		"max_age_over_relay_max":   {"-jwks-max-age", "25h"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseOptions(args, io.Discard); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestJWKSSettingsPrintedOnlyForTheOutage(t *testing.T) {
	for _, tc := range []struct {
		scenarios string
		want      bool
	}{
		{"full,soak", false},
		{"soak,jwks-outage", true},
	} {
		t.Run(tc.scenarios, func(t *testing.T) {
			o, err := parseOptions([]string{"-scenario", tc.scenarios, "-jwks-refresh", "1m", "-jwks-max-age", "5m"}, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			var b strings.Builder
			printSettings(&b, "https://127.0.0.1:9443", "/tmp/load-ca.pem", jwksAges(o))
			got := strings.Contains(b.String(), "\nRELAY_JWKS_REFRESH=1m0s\nRELAY_JWKS_MAX_AGE=5m0s\n")
			printed := strings.Contains(b.String(), "RELAY_JWKS_REFRESH") || strings.Contains(b.String(), "RELAY_JWKS_MAX_AGE")
			if got != tc.want || printed != tc.want {
				t.Errorf("JWKS settings printed %v, want %v:\n%s", got, tc.want, b.String())
			}
		})
	}
}
