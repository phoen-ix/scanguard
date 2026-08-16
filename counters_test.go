package scanguard

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func key(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

// The defining property of the distinct-bad-path detector: N distinct failing
// paths trip a capacity of N. Getting this wrong by one, or making it depend on
// floating-point drift, is how the detector silently stops working.
func TestBadPathBucketTripsAtCapacity(t *testing.T) {
	c := newCounters(1000)
	k := key("203.0.113.1/32")
	now := time.Now()

	for i := 1; i < 5; i++ {
		if c.noteBadPath(k, fmt.Sprintf("/probe-%d", i), now, 5, time.Minute) {
			t.Fatalf("tripped early, on distinct path %d of 5", i)
		}
		now = now.Add(time.Millisecond)
	}
	if !c.noteBadPath(k, "/probe-5", now, 5, time.Minute) {
		t.Fatal("did not trip on the 5th distinct failing path")
	}
}

// A legitimate client hammering one broken link produces hundreds of 404s. It
// must never be banned; only distinct paths count.
func TestBadPathBucketIgnoresRepeatsOfOnePath(t *testing.T) {
	c := newCounters(1000)
	k := key("203.0.113.2/32")
	now := time.Now()

	for i := 0; i < 200; i++ {
		if c.noteBadPath(k, "/one-broken-link", now, 5, time.Minute) {
			t.Fatalf("repeating a single path tripped the detector after %d requests", i+1)
		}
		now = now.Add(10 * time.Millisecond)
	}
}

func TestBadPathBucketLeaks(t *testing.T) {
	c := newCounters(1000)
	k := key("203.0.113.3/32")
	now := time.Now()

	// Four distinct paths, then a long gap that drains the bucket completely.
	for i := 0; i < 4; i++ {
		c.noteBadPath(k, fmt.Sprintf("/slow-%d", i), now, 5, 10*time.Second)
	}
	now = now.Add(2 * time.Minute)

	// The bucket drained, so a single new path must not trip it.
	if c.noteBadPath(k, "/slow-after-gap", now, 5, 10*time.Second) {
		t.Fatal("the bucket did not leak: a slow scanner should never accumulate")
	}
}

// Draining the bucket must also clear the remembered paths, or a source that
// returns later could never trip the detector again.
func TestBadPathBucketForgetsHistoryWhenDrained(t *testing.T) {
	c := newCounters(1000)
	k := key("203.0.113.4/32")
	now := time.Now()

	// Three distinct paths, well under a capacity of five.
	seen := []string{"/a", "/b", "/c"}
	for _, p := range seen {
		if c.noteBadPath(k, p, now, 5, 10*time.Second) {
			t.Fatal("tripped early")
		}
	}

	// Long enough for the bucket to drain completely.
	now = now.Add(5 * time.Minute)

	// Replaying the same three paths plus two new ones is five distinct paths, so
	// it must trip. If the drain had not cleared the path history, the first three
	// would be deduplicated away and this source could never be caught again.
	replay := append(append([]string{}, seen...), "/d", "/e")
	tripped := false
	for i, p := range replay {
		if c.noteBadPath(k, p, now, 5, 10*time.Second) {
			if i != len(replay)-1 {
				t.Fatalf("tripped on path %d of %d, want the last one", i+1, len(replay))
			}
			tripped = true
		}
		now = now.Add(time.Millisecond)
	}
	if !tripped {
		t.Fatal("previously-seen paths did not count again after the bucket drained")
	}
}

func TestAuthFailureWindow(t *testing.T) {
	c := newCounters(1000)
	k := key("203.0.113.5/32")
	now := time.Now()

	for i := 1; i < 3; i++ {
		if c.noteAuthFailure(k, now, 3, time.Minute) {
			t.Fatalf("tripped early, on failure %d of 3", i)
		}
		now = now.Add(time.Second)
	}
	if !c.noteAuthFailure(k, now, 3, time.Minute) {
		t.Fatal("did not trip on the 3rd failure inside the window")
	}

	// Spread far enough apart, the same number of failures must not trip.
	k2 := key("203.0.113.6/32")
	now = time.Now()
	for i := 0; i < 10; i++ {
		if c.noteAuthFailure(k2, now, 3, time.Minute) {
			t.Fatal("failures spread beyond the window should never accumulate")
		}
		now = now.Add(2 * time.Minute)
	}
}

func TestRateBucket(t *testing.T) {
	c := newCounters(1000)
	k := key("203.0.113.7/32")
	now := time.Now()

	// A burst of exactly the allowance is fine.
	for i := 0; i < 10; i++ {
		if c.noteRequest(k, now, 5, 10) {
			t.Fatalf("tripped inside the burst allowance, at request %d", i+1)
		}
	}
	// One more in the same instant exhausts it.
	if !c.noteRequest(k, now, 5, 10) {
		t.Fatal("did not trip once the burst allowance was exhausted")
	}

	// After enough time to refill, traffic is accepted again.
	now = now.Add(3 * time.Second)
	if c.noteRequest(k, now, 5, 10) {
		t.Fatal("the bucket did not refill over time")
	}
}

func TestEscalationLadderAndDecay(t *testing.T) {
	c := newCounters(1000)
	k := key("203.0.113.8/32")
	now := time.Now()

	if got := c.recordOffence(k, now, time.Hour); got != 1 {
		t.Fatalf("first offence = %d, want 1", got)
	}
	if got := c.recordOffence(k, now, time.Hour); got != 2 {
		t.Fatalf("second offence = %d, want 2", got)
	}

	// Behaving for two decay periods drops two rungs, then this offence adds one.
	if got := c.recordOffence(k, now.Add(2*time.Hour+time.Minute), time.Hour); got != 1 {
		t.Fatalf("offence after decay = %d, want 1", got)
	}
}

func TestBanDurationLadder(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.Enforcement.Escalation = []string{"1h", "24h", "0"}
	})

	cases := map[int]time.Duration{
		1: time.Hour,
		2: 24 * time.Hour,
		3: permanent,
		9: permanent, // beyond the ladder stays on the last rung
	}
	for offence, want := range cases {
		if got := s.banDuration(offence); got != want {
			t.Errorf("offence %d -> %v, want %v", offence, got, want)
		}
	}
}

// An unbounded per-source table is a memory-exhaustion vector, and it is the
// known unfixed bug in the comparable plugins.
func TestCounterTableIsCapped(t *testing.T) {
	c := newCounters(100)
	now := time.Now()

	for i := 0; i < 5000; i++ {
		k := netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
		c.noteBadPath(k, "/x", now, 10, time.Minute)
		now = now.Add(time.Millisecond)
	}
	if size := c.size(); size > 100 {
		t.Fatalf("table holds %d entries, want at most 100", size)
	}
	if c.evicted() == 0 {
		t.Error("evictions were never counted")
	}
}

func TestForgetClearsLadder(t *testing.T) {
	c := newCounters(100)
	k := key("203.0.113.9/32")
	now := time.Now()

	c.recordOffence(k, now, time.Hour)
	c.recordOffence(k, now, time.Hour)
	c.forget(k)

	if got := c.offences(k); got != 0 {
		t.Fatalf("offences after forget = %d, want 0 — an unbanned source would be "+
			"re-banned at the next rung on its very next request", got)
	}
}
