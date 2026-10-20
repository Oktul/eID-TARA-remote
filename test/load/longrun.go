// SPDX-License-Identifier: EUPL-1.2

package main

import (
	"context"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// The long-running scenarios of PLAN.md §13: a soak at a steady rate, and a
// JWKS outage that runs the relay's keys to their maximum age and back.
// Unlike the others they send at -rate instead of as fast as the workers
// can, so a run of hours stays near the load a site really makes.

const (
	// soakInvalidEvery makes every tenth soak request carry a bad
	// signature, so the rejection path and its log line run as long as the
	// forwarding path.
	soakInvalidEvery = 10

	outcomeNotReady = "503 not_ready"

	// relayRetryMax is the relay's JWKSRetryMax: during an outage it retries
	// the JWKS at least this often, so recovery after the outage takes at
	// most this long (PLAN.md §4.5).
	relayRetryMax = time.Minute
	// outageOverrun keeps the JWKS down this long past the maximum age, so
	// the expiry is observed whatever the snapshot's age at the start.
	outageOverrun = time.Minute
	// recoveryWindow is how long the scenario runs after the JWKS is back:
	// one retry interval to recover, then time to see that it stays so.
	recoveryWindow = relayRetryMax + time.Minute
	// timingSlack absorbs scheduling, the rate's tick and the relay's clock
	// granularity in the outage's timing checks; it is far below every
	// interval checked.
	timingSlack = 5 * time.Second
)

// outageLength is the jwks-outage scenario's own duration; -duration does
// not apply to it.
func outageLength(e *env) time.Duration {
	return e.jwksMaxAge + outageOverrun + recoveryWindow
}

// paced sends one request per 1/e.rate until ctx ends, each on its own
// goroutine. At most e.workers are in flight: a request that would exceed
// that is counted as a "backlog" error instead of queued, so a slow relay
// shows up in the report instead of in the generator's memory. seen, if
// set, gets every answered request's outcome and the time it was sent.
func paced(ctx, abort context.Context, e *env, t *tally,
	pick func(seq int) (token string, body []byte, err error),
	seen func(outcome string, sent time.Time),
) {
	c := e.pacedClient
	defer c.CloseIdleConnections()
	var wg sync.WaitGroup
	defer wg.Wait() // runs before CloseIdleConnections
	limit := readLimit(e.fixture)
	slots := make(chan struct{}, e.workers)
	tick := time.NewTicker(time.Second / time.Duration(e.rate))
	defer tick.Stop()
	for seq := 0; ; seq++ {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		token, body, err := pick(seq)
		if err != nil {
			t.fail("mint")
			return
		}
		select {
		case slots <- struct{}{}:
		default:
			t.fail("backlog")
			continue
		}
		wg.Go(func() {
			defer func() { <-slots }()
			sent := time.Now()
			if o := send(abort, c, e, t, token, body, limit); o != "" && seen != nil {
				seen(o, sent)
			}
		})
	}
}

// soak sends valid requests at -rate, every tenth with a bad signature, and
// prints one line per -report-every so drift over a long run (latency,
// errors, JWKS refreshes) shows in the log. Memory, connections and CPU are
// measured with the container tools (PLAN.md §13).
func soak(ctx, abort context.Context, e *env, t *tally) {
	start := time.Now()
	t.openWindow()
	// The reporter exits when done closes, after the last request.
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		tick := time.NewTicker(e.reportEvery)
		defer tick.Stop()
		jwks := e.fixture.jwksFetches.Load()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
			}
			now := e.fixture.jwksFetches.Load()
			printWindow(e.progress, time.Since(start), t.swapWindow().result(), now-jwks)
			jwks = now
		}
	})
	paced(ctx, abort, e, t, func(seq int) (string, []byte, error) {
		s, err := e.fits.get()
		if seq%soakInvalidEvery == soakInvalidEvery-1 {
			return s.badSignature, nil, err
		}
		return s.valid, e.fixture.requestBody, err
	}, nil)
	close(done)
	wg.Wait()
}

// printWindow prints one soak progress line.
func printWindow(w io.Writer, at time.Duration, r result, jwksFetches int64) {
	var b strings.Builder
	fmt.Fprintf(&b, "  [%s] %d requests", at.Round(time.Second), r.count)
	if r.timed > 0 {
		fmt.Fprintf(&b, ", p50 %s, p99 %s", short(r.p50), short(r.p99))
	}
	for _, k := range slices.Sorted(maps.Keys(r.outcomes)) {
		fmt.Fprintf(&b, ", %s: %d", k, r.outcomes[k])
	}
	for _, k := range slices.Sorted(maps.Keys(r.errors)) {
		fmt.Fprintf(&b, ", error %s: %d", k, r.errors[k])
	}
	fmt.Fprintf(&b, ", jwks fetches %d\n", jwksFetches)
	// Progress is best effort; the final report is what counts.
	_, _ = io.WriteString(w, b.String())
}

// timeline records when the answers of the jwks-outage scenario were sent,
// relative to the start of the outage.
type timeline struct {
	mu       sync.Mutex // guards every field below
	restored time.Duration
	// firstNotReady is the first not_ready and lastForwarded the last
	// forwarded answer sent while the JWKS was down.
	firstNotReady time.Duration
	lastForwarded time.Duration
	// firstRecovered is the first forwarded answer sent after the JWKS was
	// back, and notReadyAfterRecovery the last not_ready sent after it.
	firstRecovered        time.Duration
	notReadyAfterRecovery time.Duration
}

// unset marks a timeline moment that has not happened.
const unset = time.Duration(-1)

func newTimeline(restored time.Duration) *timeline {
	return &timeline{
		restored:              restored,
		firstNotReady:         unset,
		lastForwarded:         unset,
		firstRecovered:        unset,
		notReadyAfterRecovery: unset,
	}
}

// record files one answer sent at, relative to the outage's start.
func (tl *timeline) record(outcome string, at time.Duration) {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	outage := at < tl.restored
	switch {
	case outage && outcome == outcomeNotReady:
		if tl.firstNotReady == unset || at < tl.firstNotReady {
			tl.firstNotReady = at
		}
	case outage && outcome == outcomeForwarded:
		tl.lastForwarded = max(tl.lastForwarded, at)
	case outcome == outcomeForwarded:
		if tl.firstRecovered == unset || at < tl.firstRecovered {
			tl.firstRecovered = at
		}
	case outcome == outcomeNotReady:
		tl.notReadyAfterRecovery = max(tl.notReadyAfterRecovery, at)
	}
}

// failures checks the timeline against PLAN.md §4.5, for a relay started
// with RELAY_JWKS_REFRESH=refresh and RELAY_JWKS_MAX_AGE=maxAge. The
// snapshot is between 0 and refresh old when the outage starts, so its keys
// must expire between maxAge-refresh and maxAge into it: earlier drops
// logins the cache should carry, later trusts keys past the bound the
// operator set.
func (tl *timeline) failures(refresh, maxAge time.Duration) []string {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	var f []string
	switch {
	case tl.firstNotReady == unset:
		f = append(f, fmt.Sprintf("the keys never expired during the %s outage; is RELAY_JWKS_MAX_AGE %s?", tl.restored, maxAge))
	case tl.firstNotReady < maxAge-refresh-timingSlack:
		f = append(f, fmt.Sprintf("the keys expired %s into the outage, before %s (RELAY_JWKS_MAX_AGE - RELAY_JWKS_REFRESH)",
			tl.firstNotReady.Round(time.Second), maxAge-refresh))
	case tl.firstNotReady > maxAge+timingSlack:
		f = append(f, fmt.Sprintf("the keys were trusted until %s into the outage, past RELAY_JWKS_MAX_AGE %s",
			tl.firstNotReady.Round(time.Second), maxAge))
	}
	// Requests sent within the slack of each other may be answered in
	// either order.
	if tl.firstNotReady != unset && tl.lastForwarded > tl.firstNotReady+timingSlack {
		f = append(f, fmt.Sprintf("a request sent %s into the outage was forwarded after the keys had expired",
			tl.lastForwarded.Round(time.Second)))
	}
	switch {
	case tl.firstRecovered == unset:
		f = append(f, "nothing was forwarded after the JWKS was back")
	case tl.firstRecovered > tl.restored+relayRetryMax+timingSlack:
		f = append(f, fmt.Sprintf("forwarding resumed %s after the JWKS was back, more than the %s retry interval",
			(tl.firstRecovered-tl.restored).Round(time.Second), relayRetryMax))
	}
	if tl.firstRecovered != unset && tl.notReadyAfterRecovery > tl.firstRecovered+timingSlack {
		f = append(f, "not_ready again after forwarding had resumed")
	}
	return f
}

// notes returns the timeline for the report.
func (tl *timeline) notes() [][2]string {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	moment := func(d time.Duration) string {
		if d == unset {
			return "never"
		}
		return d.Round(time.Second).String()
	}
	return [][2]string{
		{"jwks restored", moment(tl.restored)},
		{"keys expired", moment(tl.firstNotReady)},
		{"forwarding back", moment(tl.firstRecovered)},
	}
}

// jwksOutage takes the fixture's JWKS down while valid requests go on at
// -rate, and brings it back after the relay's keys must have expired. Its
// checks are the timeline's, plus verdict's: only forwarded and not_ready
// answers, /readyz reporting the expiry and /livez never failing, since an
// orchestrator would restart a relay that is only waiting for its keys
// (PLAN.md §4.5, §6).
func jwksOutage(ctx, abort context.Context, e *env, t *tally) {
	start := time.Now()
	restoreAfter := e.jwksMaxAge + outageOverrun
	tl := newTimeline(restoreAfter)
	e.fixture.jwksDown.Store(true)
	defer e.fixture.jwksDown.Store(false)

	restore := time.NewTimer(restoreAfter)
	defer restore.Stop()
	// The sender exits when ctx ends and its last request has completed;
	// sent tells the scenario so.
	sent := make(chan struct{})
	go func() {
		defer close(sent)
		paced(ctx, abort, e, t, func(int) (string, []byte, error) {
			s, err := e.fits.get()
			return s.valid, e.fixture.requestBody, err
		}, func(o string, at time.Time) { tl.record(o, at.Sub(start)) })
	}()
	select {
	case <-restore.C:
		e.fixture.jwksDown.Store(false)
	case <-ctx.Done():
	}
	<-sent

	for _, n := range tl.notes() {
		t.note(n[0], n[1])
	}
	if abort.Err() != nil {
		return // interrupted; the timeline is incomplete
	}
	for _, f := range tl.failures(e.jwksRefresh, e.jwksMaxAge) {
		t.check(f)
	}
}
