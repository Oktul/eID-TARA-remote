// SPDX-License-Identifier: EUPL-1.2

package fit

import (
	"context"
	"crypto/rsa"
	"errors"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

// The PLAN.md §8 defaults, so the schedule under test is the production one.
const (
	cacheRefresh = 6 * time.Hour
	cacheMaxAge  = 24 * time.Hour
)

var errFakeFetch = errors.New("fake fetch failure")

// fakeJWKS replaces the HTTP fetcher inside synctest bubbles, where network
// I/O would keep fake time from advancing. Tests swap its answer between
// phases and read back when each fetch started.
type fakeJWKS struct {
	origin time.Time
	mu     sync.Mutex // guards answer and starts
	answer func(context.Context) ([]byte, error)
	starts []time.Duration
}

func newFakeJWKS(answer func(context.Context) ([]byte, error)) *fakeJWKS {
	return &fakeJWKS{origin: time.Now(), answer: answer}
}

func (f *fakeJWKS) set(answer func(context.Context) ([]byte, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = answer
}

func (f *fakeJWKS) fetch(ctx context.Context) ([]byte, error) {
	f.mu.Lock()
	f.starts = append(f.starts, time.Since(f.origin))
	answer := f.answer
	f.mu.Unlock()
	return answer(ctx)
}

// fetches returns when each fetch started, measured from the fake's creation.
func (f *fakeJWKS) fetches() []time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.starts)
}

func (f *fakeJWKS) count() int { return len(f.fetches()) }

func answerDoc(doc []byte) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) { return doc, nil }
}

func answerErr(err error) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) { return nil, err }
}

// answerAfter holds each fetch until gate is closed, then answers doc. A
// fetch whose context ends first fails, so a canceled fetch is visible.
func answerAfter(gate <-chan struct{}, doc []byte) func(context.Context) ([]byte, error) {
	return func(ctx context.Context) ([]byte, error) {
		select {
		case <-gate:
			return doc, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// startCache runs a cache around f with the production schedule in the
// current bubble until the test ends, and returns once the startup fetch is
// done.
func startCache(t *testing.T, f *fakeJWKS) (*Cache, *keysLog) {
	t.Helper()
	return startCacheWith(t, f, cacheRefresh, cacheMaxAge)
}

// startCacheWith is startCache with another refresh interval and maximum age.
func startCacheWith(t *testing.T, f *fakeJWKS, refresh, maxAge time.Duration) (*Cache, *keysLog) {
	t.Helper()
	log := new(keysLog)
	c := newCache(f.fetch, refresh, maxAge, log.logger())
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		c.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-stopped
	})
	synctest.Wait()
	return c, log
}

func seconds(s ...int) []time.Duration {
	d := make([]time.Duration, len(s))
	for i, v := range s {
		d[i] = time.Duration(v) * time.Second
	}
	return d
}

func TestCacheRetriesStartupFailureWithBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeJWKS(answerErr(errors.New("dial " + keysSecretMarker)))
		c, log := startCache(t, f)
		synctest.Sleep(5 * time.Minute)
		// 1 s, doubling up to the 1 min cap, never giving up.
		want := seconds(0, 1, 3, 7, 15, 31, 63, 123, 183, 243)
		if got := f.fetches(); !slices.Equal(got, want) {
			t.Fatalf("fetches at %v, want %v", got, want)
		}
		if c.Ready() {
			t.Fatal("ready without a successful fetch")
		}
		if _, err := c.Key(t.Context(), "k1"); err != ErrNotReady {
			t.Fatalf("Key = %v, want ErrNotReady", err)
		}
		if n := log.count(t, "jwks refresh failed", "fetch"); n != len(want) {
			t.Fatalf("failure records = %d, want %d", n, len(want))
		}
		if n := log.count(t, "signing keys ready", ""); n != 0 {
			t.Fatalf("ready records = %d, want 0", n)
		}
		if strings.Contains(log.String(), keysSecretMarker) {
			t.Fatalf("log repeats the fetch error text:\n%s", log)
		}
	})
}

func TestCacheBecomesReadyOnFirstSuccess(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		f := newFakeJWKS(answerErr(errFakeFetch))
		c, log := startCache(t, f)
		synctest.Sleep(2 * time.Second)
		if c.Ready() {
			t.Fatal("ready after failed fetches only")
		}
		f.set(answerDoc(testJWKS(t, testJWK("k1", pub))))
		synctest.Sleep(time.Second)
		if !c.Ready() {
			t.Fatal("not ready after a successful fetch")
		}
		if key, err := c.Key(t.Context(), "k1"); err != nil || !key.Equal(pub) {
			t.Fatalf("Key = %v, want the published key", err)
		}
		if got, want := f.fetches(), seconds(0, 1, 3); !slices.Equal(got, want) {
			t.Fatalf("fetches at %v, want %v", got, want)
		}
		if n := log.count(t, "signing keys ready", ""); n != 1 {
			t.Fatalf("ready records = %d, want 1", n)
		}
	})
}

func TestCacheRefreshesEveryRefreshInterval(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		f := newFakeJWKS(answerDoc(testJWKS(t, testJWK("k1", pub))))
		startCache(t, f)
		synctest.Sleep(cacheRefresh - time.Nanosecond)
		if n := f.count(); n != 1 {
			t.Fatalf("fetches before the refresh interval = %d, want 1", n)
		}
		synctest.Sleep(cacheRefresh + time.Nanosecond)
		if got, want := f.fetches(), []time.Duration{0, cacheRefresh, 2 * cacheRefresh}; !slices.Equal(got, want) {
			t.Fatalf("fetches at %v, want %v", got, want)
		}
	})
}

func TestCacheRefreshReplacesWholeSnapshot(t *testing.T) {
	keys := testPublicKeys()
	synctest.Test(t, func(t *testing.T) {
		k1, k2 := testJWK("k1", keys[0]), testJWK("k2", keys[1])
		f := newFakeJWKS(answerDoc(testJWKS(t, k1)))
		c, _ := startCache(t, f)

		// rotation_added_key_trusted_after_refresh
		f.set(answerDoc(testJWKS(t, k1, k2)))
		synctest.Sleep(cacheRefresh)
		if key, err := c.lookup("k2"); err != nil || !key.Equal(keys[1]) {
			t.Fatalf("lookup(new key) = %v, want the rotated-in key", err)
		}

		// removed_key_rejected_after_refresh
		f.set(answerDoc(testJWKS(t, k2)))
		synctest.Sleep(cacheRefresh)
		if _, err := c.lookup("k1"); err != errKeyUnknown {
			t.Fatalf("lookup(removed key) = %v, want errKeyUnknown", err)
		}
		if _, err := c.Key(t.Context(), "k1"); err != errKeyUnknown {
			t.Fatalf("Key(removed key) = %v, want errKeyUnknown", err)
		}
	})
}

func TestCacheKeepsLastGoodSnapshotOnlyUntilMaxAge(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		doc := testJWKS(t, testJWK("k1", pub))
		f := newFakeJWKS(answerDoc(doc))
		c, log := startCache(t, f)
		good := c.snap.Load()
		f.set(answerErr(errFakeFetch))

		synctest.Sleep(cacheMaxAge - time.Nanosecond)
		if !c.Ready() {
			t.Fatal("last good snapshot dropped before its maximum age")
		}
		if key, err := c.Key(t.Context(), "k1"); err != nil || !key.Equal(pub) {
			t.Fatalf("Key = %v, want the last good key", err)
		}
		if c.snap.Load() != good {
			t.Fatal("a failed refresh replaced the snapshot")
		}

		synctest.Sleep(time.Nanosecond)
		if c.Ready() {
			t.Fatal("ready at the maximum age")
		}
		if _, err := c.Key(t.Context(), "k1"); err != ErrNotReady {
			t.Fatalf("Key(known) at the maximum age = %v, want ErrNotReady", err)
		}
		before := f.count()
		if _, err := c.Key(t.Context(), "k2"); err != ErrNotReady {
			t.Fatalf("Key(unknown) at the maximum age = %v, want ErrNotReady", err)
		}
		synctest.Wait()
		if n := f.count(); n != before {
			t.Fatal("an expired snapshot let an unknown key ID start a fetch")
		}
		if n := log.count(t, "signing keys expired", ""); n != 1 {
			t.Fatalf("expiry records = %d, want 1", n)
		}

		synctest.Sleep(time.Hour)
		if n := log.count(t, "signing keys expired", ""); n != 1 {
			t.Fatalf("expiry records after an hour = %d, want still 1", n)
		}

		// success_restores_readiness
		f.set(answerDoc(doc))
		synctest.Sleep(JWKSRetryMax)
		if !c.Ready() {
			t.Fatal("a successful refresh did not restore readiness")
		}
		if n := log.count(t, "signing keys ready", ""); n != 2 {
			t.Fatalf("ready records = %d, want 2", n)
		}
	})
}

// TestCacheLogsExpiryDuringRunningFetch lets the snapshot reach its maximum
// age while a fetch is held, then lets that fetch succeed. Ready was false
// in between, so both transitions must be logged (PLAN.md §4.5).
func TestCacheLogsExpiryDuringRunningFetch(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		// The periodic fetch starts 5 s before the maximum age and is held
		// past it, within JWKSFetchTimeout.
		const refresh, maxAge = time.Hour, time.Hour + 5*time.Second
		doc := testJWKS(t, testJWK("k1", pub))
		f := newFakeJWKS(answerDoc(doc))
		c, log := startCacheWith(t, f, refresh, maxAge)
		gate := make(chan struct{})
		f.set(answerAfter(gate, doc))

		synctest.Sleep(maxAge + time.Second)
		if n := f.count(); n != 2 {
			t.Fatalf("fetches = %d, want the periodic fetch held", n)
		}
		if c.Ready() {
			t.Fatal("ready past the maximum age")
		}
		close(gate)
		synctest.Wait()
		if !c.Ready() {
			t.Fatal("the held fetch's success did not restore readiness")
		}
		if n := log.count(t, "signing keys expired", ""); n != 1 {
			t.Fatalf("expiry records = %d, want 1", n)
		}
		if n := log.count(t, "signing keys ready", ""); n != 2 {
			t.Fatalf("ready records = %d, want 2", n)
		}
	})
}

func TestCacheFailedRefreshKeepsSnapshot(t *testing.T) {
	keys := testPublicKeys()
	k1, k2 := testJWK("k1", keys[0]), testJWK("k2", keys[1])
	tooMany := []map[string]any{k1, k2}
	for i := len(tooMany); i <= MaxJWKSKeys; i++ {
		tooMany = append(tooMany, testJWK("extra-"+strconv.Itoa(i), keys[1]))
	}
	tests := []struct {
		name   string
		answer func(context.Context) ([]byte, error)
		reason string
	}{
		{"duplicate_kid", answerDoc(testJWKS(t, k1, k2, k2)), "duplicate_kid"},
		{"malformed_document", answerDoc(append(testJWKS(t, k1, k2), '}')), "malformed"},
		{"empty_key_set", answerDoc(testJWKS(t)), "no_usable_keys"},
		{"more_than_max_keys", answerDoc(testJWKS(t, tooMany...)), "too_many_keys"},
		{"invalid_exponent", answerDoc(testJWKS(t, k1, jwkWith(k2, "e", "Ag"))), "key_parameters"},
		{"leading_zero_modulus", answerDoc(testJWKS(t, k1, jwkWith(k2, "n", segment("\x00"+string(keys[1].N.Bytes()))))), "key_parameters"},
		{"use_not_string", answerDoc(testJWKS(t, k1, jwkWith(k2, "use", 1))), "key_parameters"},
		{"oversized_body", answerErr(jwksTooLarge), "too_large"},
		{"status_not_200", answerErr(jwksBadStatus), "status"},
		{"network_error", answerErr(errors.New("dial " + keysSecretMarker)), "fetch"},
		{"panic", func(context.Context) ([]byte, error) { panic(keysSecretMarker) }, "panic"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := newFakeJWKS(answerDoc(testJWKS(t, k1)))
				c, log := startCache(t, f)
				good := c.snap.Load()
				f.set(tt.answer)
				synctest.Sleep(cacheRefresh)
				if c.snap.Load() != good {
					t.Fatal("a failed refresh changed the snapshot or its fetch time")
				}
				if key, err := c.Key(t.Context(), "k1"); err != nil || !key.Equal(keys[0]) {
					t.Fatalf("Key(last good) = %v, want the last good key", err)
				}
				if _, err := c.Key(t.Context(), "k2"); err != errKeyUnknown {
					t.Fatalf("Key(from failed document) = %v, want errKeyUnknown", err)
				}
				if n := log.count(t, "jwks refresh failed", tt.reason); n == 0 {
					t.Fatalf("no failure record with reason %q; log:\n%s", tt.reason, log)
				}
				if strings.Contains(log.String(), keysSecretMarker) {
					t.Fatalf("log repeats error or panic text:\n%s", log)
				}
			})
		})
	}
}

func TestCacheUnknownKeyFloodStartsOneFetch(t *testing.T) {
	keys := testPublicKeys()
	const flood = 1000
	synctest.Test(t, func(t *testing.T) {
		k1 := testJWK("k1", keys[0])
		f := newFakeJWKS(answerDoc(testJWKS(t, k1)))
		c, _ := startCache(t, f)
		gate := make(chan struct{})
		// The shared fetch brings one of the requested IDs.
		f.set(answerAfter(gate, testJWKS(t, k1, testJWK("flood-7", keys[1]))))

		start := time.Now()
		var wg sync.WaitGroup
		found := make([]*rsa.PublicKey, flood)
		errs := make([]error, flood)
		for i := range flood {
			wg.Go(func() { found[i], errs[i] = c.Key(t.Context(), "flood-"+strconv.Itoa(i)) })
		}
		synctest.Wait()
		if n := f.count(); n != 2 {
			t.Fatalf("fetches = %d, want the startup fetch and one shared fetch", n)
		}
		close(gate)
		wg.Wait()
		if d := time.Since(start); d != 0 {
			t.Fatalf("callers returned after %v, want when the shared fetch ended", d)
		}
		for i, err := range errs {
			if i == 7 {
				if err != nil || !found[i].Equal(keys[1]) {
					t.Fatalf("Key(fetched ID) = %v, want the new key", err)
				}
			} else if err != errKeyUnknown {
				t.Fatalf("Key(unknown ID) = %v, want errKeyUnknown", err)
			}
		}

		// A second flood within JWKSUnknownRefreshInterval starts no fetch
		// and is refused at once.
		start = time.Now()
		for i := range flood {
			wg.Go(func() { _, errs[i] = c.Key(t.Context(), "second-"+strconv.Itoa(i)) })
		}
		wg.Wait()
		if d := time.Since(start); d != 0 {
			t.Fatalf("callers in the cooldown waited %v, want 0", d)
		}
		synctest.Wait()
		if n := f.count(); n != 2 {
			t.Fatalf("fetches = %d after a flood in the cooldown, want 2", n)
		}
		for _, err := range errs {
			if err != errKeyUnknown {
				t.Fatalf("Key(unknown ID) in the cooldown = %v, want errKeyUnknown", err)
			}
		}
	})
}

func TestCacheLimitsUnknownKeyFetchesToOnePerInterval(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		f := newFakeJWKS(answerDoc(testJWKS(t, testJWK("k1", pub))))
		c, _ := startCache(t, f)
		if _, err := c.Key(t.Context(), "a"); err != errKeyUnknown {
			t.Fatalf("Key = %v, want errKeyUnknown", err)
		}
		if n := f.count(); n != 2 {
			t.Fatalf("fetches = %d, want an unknown ID to start one", n)
		}

		synctest.Sleep(JWKSUnknownRefreshInterval - time.Nanosecond)
		if _, err := c.Key(t.Context(), "b"); err != errKeyUnknown {
			t.Fatalf("Key = %v, want errKeyUnknown", err)
		}
		synctest.Wait()
		if n := f.count(); n != 2 {
			t.Fatalf("fetches = %d, want none started within the interval", n)
		}

		synctest.Sleep(time.Nanosecond)
		if _, err := c.Key(t.Context(), "c"); err != errKeyUnknown {
			t.Fatalf("Key = %v, want errKeyUnknown", err)
		}
		if n := f.count(); n != 3 {
			t.Fatalf("fetches = %d, want one started once the interval passed", n)
		}
	})
}

func TestCacheKnownKeyDoesNotWaitForFetch(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		doc := testJWKS(t, testJWK("k1", pub))
		f := newFakeJWKS(answerDoc(doc))
		c, _ := startCache(t, f)
		gate := make(chan struct{})
		f.set(answerAfter(gate, doc))
		synctest.Sleep(cacheRefresh) // the periodic fetch starts and hangs
		if n := f.count(); n != 2 {
			t.Fatalf("fetches = %d, want the periodic fetch running", n)
		}
		start := time.Now()
		if key, err := c.Key(t.Context(), "k1"); err != nil || !key.Equal(pub) {
			t.Fatalf("Key = %v, want the known key", err)
		}
		if d := time.Since(start); d != 0 {
			t.Fatalf("known key waited %v for the running fetch", d)
		}
		if !c.Ready() {
			t.Fatal("not ready while a refresh is running")
		}
		close(gate)
	})
}

func TestCacheUnknownKeyWaitIsBounded(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		doc := testJWKS(t, testJWK("k1", pub))
		f := newFakeJWKS(answerDoc(doc))
		c, _ := startCache(t, f)
		f.set(answerAfter(make(chan struct{}), doc)) // the fetch never answers
		start := time.Now()
		if _, err := c.Key(t.Context(), "k2"); err != errKeyUnknown {
			t.Fatalf("Key = %v, want errKeyUnknown", err)
		}
		if d := time.Since(start); d != FITKeyWait {
			t.Fatalf("unknown key waited %v, want FITKeyWait", d)
		}
	})
}

func TestCacheUnknownKeyWaitEndsWithCaller(t *testing.T) {
	keys := testPublicKeys()
	synctest.Test(t, func(t *testing.T) {
		k1, k2 := testJWK("k1", keys[0]), testJWK("k2", keys[1])
		f := newFakeJWKS(answerDoc(testJWKS(t, k1)))
		c, _ := startCache(t, f)
		gate := make(chan struct{})
		f.set(answerAfter(gate, testJWKS(t, k1, k2)))

		const callerGone = 100 * time.Millisecond
		ctx, cancel := context.WithCancel(t.Context())
		time.AfterFunc(callerGone, cancel)
		start := time.Now()
		if _, err := c.Key(ctx, "k2"); err != errKeyUnknown {
			t.Fatalf("Key = %v, want errKeyUnknown", err)
		}
		if d := time.Since(start); d != callerGone {
			t.Fatalf("canceled caller returned after %v, want %v", d, callerGone)
		}

		// worker_fetch_survives_caller_cancel: the fetch that caller started
		// still completes, so the next request finds the key.
		close(gate)
		synctest.Wait()
		if key, err := c.lookup("k2"); err != nil || !key.Equal(keys[1]) {
			t.Fatalf("lookup = %v, want the key from the shared fetch", err)
		}
		if n := f.count(); n != 2 {
			t.Fatalf("fetches = %d, want 2", n)
		}
	})
}

func TestCacheUnknownKeyJoinsRunningFetch(t *testing.T) {
	keys := testPublicKeys()
	synctest.Test(t, func(t *testing.T) {
		k1, k2 := testJWK("k1", keys[0]), testJWK("k2", keys[1])
		f := newFakeJWKS(answerDoc(testJWKS(t, k1)))
		c, _ := startCache(t, f)
		gate := make(chan struct{})
		f.set(answerAfter(gate, testJWKS(t, k1, k2)))
		synctest.Sleep(cacheRefresh) // the periodic fetch starts and hangs

		var key *rsa.PublicKey
		var err error
		var wg sync.WaitGroup
		wg.Go(func() { key, err = c.Key(t.Context(), "k2") })
		synctest.Wait()
		close(gate)
		wg.Wait()
		if err != nil || !key.Equal(keys[1]) {
			t.Fatalf("Key = %v, want the key from the running fetch", err)
		}
		if n := f.count(); n != 2 {
			t.Fatalf("fetches = %d, want the caller to join the running fetch", n)
		}

		// Joining started nothing, so the cooldown is unused.
		f.set(answerDoc(testJWKS(t, k1, k2)))
		if _, err := c.Key(t.Context(), "k3"); err != errKeyUnknown {
			t.Fatalf("Key = %v, want errKeyUnknown", err)
		}
		if n := f.count(); n != 3 {
			t.Fatalf("fetches = %d, want the next unknown ID to start one", n)
		}
	})
}

func TestCacheIgnoresStaleWake(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		f := newFakeJWKS(answerDoc(testJWKS(t, testJWK("k1", pub))))
		c, _ := startCache(t, f)
		// A wake whose fetch already ran via the timer: nobody is waiting.
		c.wake <- struct{}{}
		synctest.Wait()
		if n := f.count(); n != 1 {
			t.Fatalf("fetches = %d, want a wake without waiting callers to start none", n)
		}
	})
}

func TestCacheBoundsFetchByTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newFakeJWKS(func(ctx context.Context) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		_, log := startCache(t, f)
		synctest.Sleep(JWKSFetchTimeout + JWKSRetryInitial)
		if got, want := f.fetches(), []time.Duration{0, JWKSFetchTimeout + JWKSRetryInitial}; !slices.Equal(got, want) {
			t.Fatalf("fetches at %v, want %v", got, want)
		}
		if n := log.count(t, "jwks refresh failed", "fetch"); n != 1 {
			t.Fatalf("failure records = %d, want 1", n)
		}
	})
}

func TestCacheRecoversFromPanicAndKeepsBackoff(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		doc := testJWKS(t, testJWK("k1", pub))
		calls := 0 // only the worker goroutine fetches
		f := newFakeJWKS(func(context.Context) ([]byte, error) {
			calls++
			if calls <= 3 {
				panic(keysSecretMarker)
			}
			return doc, nil
		})
		c, log := startCache(t, f)
		synctest.Sleep(7 * time.Second)
		if got, want := f.fetches(), seconds(0, 1, 3, 7); !slices.Equal(got, want) {
			t.Fatalf("fetches at %v, want %v", got, want)
		}
		if !c.Ready() {
			t.Fatal("not ready after the fetch that followed the panics")
		}
		if n := log.count(t, "jwks refresh failed", "panic"); n != 3 {
			t.Fatalf("panic records = %d, want 3", n)
		}
		if strings.Contains(log.String(), keysSecretMarker) {
			t.Fatalf("log repeats the panic value:\n%s", log)
		}
	})
}

func TestCacheBackoffRestartsAfterSuccess(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		good := answerDoc(testJWKS(t, testJWK("k1", pub)))
		f := newFakeJWKS(good)
		startCache(t, f)
		f.set(answerErr(errFakeFetch))
		synctest.Sleep(cacheRefresh + 3*time.Second) // fails at 6h, +1 s, +3 s
		f.set(good)
		synctest.Sleep(4 * time.Second) // succeeds at 6h+7s
		f.set(answerErr(errFakeFetch))
		synctest.Sleep(cacheRefresh + time.Second) // fails at 12h+7s, retries 1 s later
		h := cacheRefresh
		want := []time.Duration{0, h, h + time.Second, h + 3*time.Second, h + 7*time.Second,
			2*h + 7*time.Second, 2*h + 8*time.Second}
		if got := f.fetches(); !slices.Equal(got, want) {
			t.Fatalf("fetches at %v, want %v", got, want)
		}
	})
}

func TestCacheRunStopsWithContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		log := new(keysLog)
		f := newFakeJWKS(answerAfter(make(chan struct{}), nil)) // the fetch never answers
		c := newCache(f.fetch, cacheRefresh, cacheMaxAge, log.logger())
		ctx, cancel := context.WithCancel(t.Context())
		stopped := make(chan struct{})
		go func() {
			defer close(stopped)
			c.Run(ctx)
		}()
		synctest.Wait()
		start := time.Now()
		cancel()
		<-stopped
		if d := time.Since(start); d != 0 {
			t.Fatalf("Run returned %v after cancellation, want at once", d)
		}
		if n := log.count(t, "jwks refresh failed", ""); n != 0 {
			t.Fatalf("shutdown logged as a refresh failure:\n%s", log)
		}
	})
}

func TestCacheKeyBeforeFirstSnapshotIsNotReady(t *testing.T) {
	c := newCache(answerErr(errFakeFetch), cacheRefresh, cacheMaxAge, discardLogger())
	if c.Ready() {
		t.Fatal("ready without a snapshot")
	}
	if _, err := c.Key(t.Context(), "k1"); err != ErrNotReady {
		t.Fatalf("Key = %v, want ErrNotReady", err)
	}
	if len(c.wake) != 0 || c.inflight != nil {
		t.Fatal("Key without a snapshot asked for a fetch")
	}
}

func TestCacheStartsNoGoroutineOutsideRun(t *testing.T) {
	pub := testPublicKeys()[0]
	// synctest.Test fails if any goroutine the cache started is still
	// blocked when the test function returns.
	synctest.Test(t, func(t *testing.T) {
		c := newCache(func(context.Context) ([]byte, error) {
			t.Error("fetched without Run")
			return nil, errFakeFetch
		}, cacheRefresh, cacheMaxAge, discardLogger())
		c.snap.Store(&snapshot{keys: map[string]*rsa.PublicKey{"k1": pub}, fetchedAt: time.Now()})
		if key, err := c.Key(t.Context(), "k1"); err != nil || !key.Equal(pub) {
			t.Fatalf("Key = %v, want the known key", err)
		}
		start := time.Now()
		if _, err := c.Key(t.Context(), "k2"); err != errKeyUnknown {
			t.Fatalf("Key = %v, want errKeyUnknown", err)
		}
		if d := time.Since(start); d != FITKeyWait {
			t.Fatalf("unknown key without a worker waited %v, want FITKeyWait", d)
		}
	})
}

func TestCacheLogsNoKeyIDsOrErrorText(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		f := newFakeJWKS(answerDoc(testJWKS(t, testJWK(keysSecretMarker+"-k1", pub))))
		c, log := startCache(t, f)
		f.set(answerErr(errors.New("dial tcp " + keysSecretMarker)))
		if _, err := c.Key(t.Context(), keysSecretMarker+"-unknown"); err != errKeyUnknown {
			t.Fatalf("Key = %v, want errKeyUnknown", err)
		}
		synctest.Sleep(time.Minute)
		if n := log.count(t, "jwks refresh failed", "fetch"); n == 0 {
			t.Fatal("no failure records")
		}
		if strings.Contains(log.String(), keysSecretMarker) {
			t.Fatalf("log repeats a key ID or error text:\n%s", log)
		}
	})
}

func TestCacheRunTwicePanics(t *testing.T) {
	pub := testPublicKeys()[0]
	synctest.Test(t, func(t *testing.T) {
		c, _ := startCache(t, newFakeJWKS(answerDoc(testJWKS(t, testJWK("k1", pub)))))
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // without the guard, the second Run returns at once
		defer func() {
			if recover() == nil {
				t.Fatal("a second Run did not panic; two workers could fetch at once")
			}
		}()
		c.Run(ctx)
	})
}
