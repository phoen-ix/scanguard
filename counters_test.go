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
	// Every rung is a one-hour ban; decay is one hour, measured from the ban end.
	hour := func(int) time.Duration { return time.Hour }

	if got, _ := c.recordOffence(k, now, time.Hour, hour); got != 1 {
		t.Fatalf("first offence = %d, want 1", got)
	}
	// Back a minute after the ban ran out: no decay yet, one rung up.
	now = now.Add(time.Hour + time.Minute)
	if got, _ := c.recordOffence(k, now, time.Hour, hour); got != 2 {
		t.Fatalf("second offence = %d, want 2", got)
	}

	// Behaving for two decay periods after that ban ends drops two rungs, then
	// this offence adds one.
	now = now.Add(time.Hour + 2*time.Hour + time.Minute)
	if got, _ := c.recordOffence(k, now, time.Hour, hour); got != 1 {
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

	hour := func(int) time.Duration { return time.Hour }
	_, _ = c.recordOffence(k, now, time.Hour, hour)
	_, _ = c.recordOffence(k, now.Add(90*time.Minute), time.Hour, hour)
	c.forget(k)

	if got := c.offences(k); got != 0 {
		t.Fatalf("offences after forget = %d, want 0 — an unbanned source would be "+
			"re-banned at the next rung on its very next request", got)
	}
}

// The user-agent bucket counts DISTINCT user-agents: one repeated never trips,
// N distinct ones arriving faster than the leak trip on the Nth, slower ones
// never do, and the remembered set stays bounded.
func TestUserAgentBucket(t *testing.T) {
	cases := []struct {
		name     string
		distinct bool
		gap      time.Duration
		sends    int
		tripAt   int // 1-based send that must trip; 0 means never
	}{
		{"one user-agent repeated", false, time.Millisecond, 20, 0},
		{"distinct, faster than the leak", true, time.Millisecond, 5, 5},
		{"distinct, slower than the leak", true, 2 * time.Minute, 20, 0},
	}
	for _, tc := range cases {
		c := newCounters(1000)
		k := key("203.0.113.20/32")
		now := time.Now()
		for i := 1; i <= tc.sends; i++ {
			ua := "same"
			if tc.distinct {
				ua = fmt.Sprintf("ua-%d", i)
			}
			tripped := c.noteUserAgent(k, ua, now, 5, time.Minute)
			if tripped != (i == tc.tripAt) {
				t.Errorf("%s: send %d tripped=%v, want trip at %d", tc.name, i, tripped, tc.tripAt)
			}
			now = now.Add(tc.gap)
		}
	}

	// A capacity the set can never reach still leaves it bounded.
	c := newCounters(1000)
	k := key("203.0.113.21/32")
	now := time.Now()
	for i := 0; i < 1000; i++ {
		c.noteUserAgent(k, fmt.Sprintf("ua-%d", i), now, 100000, time.Hour)
	}
	if n := len(c.tbl[k].ua.seen); n > maxDistinctPaths {
		t.Errorf("the remembered set grew to %d, want at most %d", n, maxDistinctPaths)
	}
}

// Range escalation counts distinct banned members of a range within the window.
func TestSubnetMembers(t *testing.T) {
	rng := key("198.51.100.0/24")
	m := func(i int) netip.Prefix { return key(fmt.Sprintf("198.51.100.%d/32", i)) }
	const window = time.Hour
	start := time.Now()

	cases := []struct {
		name  string
		steps func(c *counters) (int, bool)
		wantN int
		trip  bool
	}{
		{"the threshold-th member trips", func(c *counters) (int, bool) {
			c.noteSubnetBan(rng, m(1), start, 3, window, false)
			c.noteSubnetBan(rng, m(2), start, 3, window, false)
			return c.noteSubnetBan(rng, m(3), start, 3, window, false)
		}, 3, true},
		{"a repeated member counts once", func(c *counters) (int, bool) {
			c.noteSubnetBan(rng, m(1), start, 3, window, false)
			c.noteSubnetBan(rng, m(1), start, 3, window, false)
			return c.noteSubnetBan(rng, m(2), start, 3, window, false)
		}, 2, false},
		{"members older than the window drop", func(c *counters) (int, bool) {
			c.noteSubnetBan(rng, m(1), start, 3, window, false)
			c.noteSubnetBan(rng, m(2), start, 3, window, false)
			return c.noteSubnetBan(rng, m(3), start.Add(window+time.Second), 3, window, false)
		}, 1, false},
		{"switching dry run starts over", func(c *counters) (int, bool) {
			c.noteSubnetBan(rng, m(1), start, 3, window, true)
			c.noteSubnetBan(rng, m(2), start, 3, window, true)
			return c.noteSubnetBan(rng, m(3), start, 3, window, false)
		}, 1, false},
		{"a trip starts the count over", func(c *counters) (int, bool) {
			for i := 1; i <= 3; i++ {
				c.noteSubnetBan(rng, m(i), start, 3, window, false)
			}
			return c.noteSubnetBan(rng, m(4), start, 3, window, false)
		}, 1, false},
	}
	for _, tc := range cases {
		n, trip := tc.steps(newCounters(1000))
		if n != tc.wantN || trip != tc.trip {
			t.Errorf("%s: got (%d, %v), want (%d, %v)", tc.name, n, trip, tc.wantN, tc.trip)
		}
	}
}

// A smaller cap applied at runtime evicts at once: a reload that lowers
// store.maxEntries used to resize the ban list and leave this table alone.
func TestCounterCapFollowsSetMax(t *testing.T) {
	c := newCounters(100)
	now := time.Now()
	for i := 0; i < 60; i++ {
		key := netip.MustParsePrefix(fmt.Sprintf("10.2.0.%d/32", i))
		c.noteBadPath(key, "/x", now.Add(time.Duration(i)*time.Second), 20, time.Minute)
	}
	c.setMax(10)
	if got := c.size(); got > 10 {
		t.Fatalf("table holds %d sources after setMax(10), want at most 10", got)
	}
	if c.evicted() == 0 {
		t.Error("the eviction counter did not record the shrink")
	}
}

// At the cap, the record created for a new source must survive the eviction its
// own arrival triggers. Inserted with a zero lastSeen it sorted as the oldest
// entry in the table and was evicted at once, so the observation went to an
// orphan and the source's first offence, bucket entry and banRecorded flag were
// all lost.
func TestCounterCapKeepsTheRecordJustCreated(t *testing.T) {
	c := newCounters(10)
	now := time.Now()
	for i := 0; i <= 10; i++ {
		k := netip.MustParsePrefix(fmt.Sprintf("10.3.0.%d/32", i))
		c.noteBadPath(k, "/x", now.Add(time.Duration(i)*time.Second), 20, time.Minute)
	}
	newest := netip.MustParsePrefix("10.3.0.10/32")
	c.mu.Lock()
	st, ok := c.tbl[newest]
	c.mu.Unlock()
	if !ok {
		t.Fatal("the source whose arrival filled the table was evicted instead of the oldest")
	}
	if st.lastSeen.IsZero() || len(st.bad.seen) != 1 {
		t.Errorf("the surviving record is empty: lastSeen=%v badPaths=%d", st.lastSeen, len(st.bad.seen))
	}
	if c.evicted() == 0 {
		t.Error("nothing was evicted at the cap")
	}
}

// A manual ban reaches the ladder two ways: in-process through noteManualBan,
// and after a restart through seed() replaying the persisted ban. The source
// must come back at the same rung either way; it used to climb after a restart
// and decay without one, because only seed moved the ban window.
func TestManualBanMovesTheLadderWindowLikeSeedDoes(t *testing.T) {
	k := key("203.0.113.30/32")
	const decay = 24 * time.Hour
	ladder := func(offence int) time.Duration {
		switch offence {
		case 1:
			return time.Hour
		case 2:
			return 24 * time.Hour
		}
		return 168 * time.Hour
	}
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	live := newCounters(100)
	if got, _ := live.recordOffence(k, t0, decay, ladder); got != 1 {
		t.Fatalf("first offence = %d", got)
	}
	if got, _ := live.recordOffence(k, t0.Add(2*time.Hour), decay, ladder); got != 2 {
		t.Fatalf("second offence = %d", got)
	}
	// An hour after the 24h ban ran out, the operator bans the source for 48h.
	banned, expires := t0.Add(27*time.Hour), t0.Add(75*time.Hour)
	live.noteManualBan(k, expires, banned)

	// The same ban as a restarted process sees it: replayed from the store.
	restarted := newCounters(100)
	restarted.seed(k, 2, banned, expires, banned)

	after := expires.Add(time.Hour)
	gotLive, _ := live.recordOffence(k, after, decay, ladder)
	gotRestarted, _ := restarted.recordOffence(k, after, decay, ladder)
	if gotLive != 3 || gotRestarted != 3 {
		t.Errorf("an hour after the manual ban the source is at rung %d live and %d after a restart, want 3 and 3",
			gotLive, gotRestarted)
	}

	// Like seed, a manual ban on a source with no ladder position records nothing.
	live.noteManualBan(key("203.0.113.31/32"), expires, banned)
	if live.offences(key("203.0.113.31/32")) != 0 || live.banRecorded(key("203.0.113.31/32")) {
		t.Error("a manual ban on a clean source created a ladder record")
	}
}

// Exactly one caller wins the re-issue ticket; the flag is off until the put
// marks it again.
func TestClaimReissueIsOneShot(t *testing.T) {
	c := newCounters(100)
	k := key("203.0.113.32/32")
	hour := func(int) time.Duration { return time.Hour }
	_, _ = c.recordOffence(k, time.Now(), 0, hour)
	if c.claimReissue(k) {
		t.Fatal("claimed before the ban was ever recorded")
	}
	c.markBanRecorded(k)
	if !c.claimReissue(k) {
		t.Fatal("the first claim after a recorded ban was refused")
	}
	if c.claimReissue(k) || c.banRecorded(k) {
		t.Error("a second claim succeeded, or the flag stayed on")
	}
	c.markBanRecorded(k)
	if !c.banRecorded(k) {
		t.Error("the put did not close the window again")
	}
}
