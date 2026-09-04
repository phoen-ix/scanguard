package scanguard

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// maxDistinctPaths bounds the per-source set of remembered error paths. Without
// it, one source walking a large wordlist would grow this map without limit.
const maxDistinctPaths = 128

// sourceState is the per-source counter record. It is always process-local, even
// when the ban list is shared through Redis: counters are high-frequency and
// disposable, bans are low-frequency and worth agreeing about.
type sourceState struct {
	lastSeen time.Time

	// Leaky bucket over DISTINCT error paths.
	badSeen  map[string]struct{}
	badLevel float64
	badAt    time.Time

	// Sliding window of authentication failures.
	bruteHits []time.Time

	// Token bucket for request-rate abuse.
	tokens   float64
	tokensAt time.Time

	// Escalation ladder position.
	offences    int
	lastOffence time.Time
	// banUntil is when the ban issued for the last offence ran out. Decay is
	// measured from it rather than from lastOffence; see recordOffence.
	banUntil time.Time
}

// counters is the local per-source counter table, hard-capped and LRU-evicted.
//
// The cap is not an optimisation. An unbounded per-IP map inside a reverse proxy
// is a memory-exhaustion vector that any distributed scan will find, and it is
// the known unfixed bug in the most popular comparable plugin. Keys are already
// aggregated to a prefix before they get here, so the table is bounded by prefix
// count rather than by address count.
type counters struct {
	mu  sync.Mutex
	tbl map[netip.Prefix]*sourceState
	max int
	// evictions counts how many records the cap has discarded, so an operator can
	// see when the table is too small for their traffic.
	evictions int64
}

func newCounters(max int) *counters {
	if max <= 0 {
		max = 50000
	}
	return &counters{tbl: make(map[netip.Prefix]*sourceState), max: max}
}

// getLocked returns the record for key, creating it if needed. The caller holds mu.
func (c *counters) getLocked(key netip.Prefix, now time.Time) *sourceState {
	st, ok := c.tbl[key]
	if !ok {
		st = &sourceState{}
		c.tbl[key] = st
		if len(c.tbl) > c.max {
			c.evictLocked()
		}
	}
	st.lastSeen = now
	return st
}

// evictLocked drops the least-recently-seen tenth of the table. Batching keeps
// the amortised cost of the cap near zero: a full scan happens once per
// max/10 insertions rather than on every insertion.
func (c *counters) evictLocked() {
	type entry struct {
		key  netip.Prefix
		seen time.Time
	}
	all := make([]entry, 0, len(c.tbl))
	for k, st := range c.tbl {
		all = append(all, entry{key: k, seen: st.lastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })

	drop := len(c.tbl) - c.max + c.max/10
	for i := 0; i < drop && i < len(all); i++ {
		delete(c.tbl, all[i].key)
		c.evictions++
	}
}

// noteBadPath feeds the distinct-bad-path leaky bucket and reports whether it
// overflowed.
//
// Counting DISTINCT paths rather than raw error volume is the single most
// important detail in this file. A legitimate client hammering one broken link
// produces hundreds of 404s and must never be banned; a scanner produces one 404
// each across hundreds of different paths and must be. Only the distinct count
// separates them.
func (c *counters) noteBadPath(key netip.Prefix, path string, now time.Time, capacity int, leak time.Duration) bool {
	if capacity <= 0 || leak <= 0 {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	st := c.getLocked(key, now)
	if !st.badAt.IsZero() {
		st.badLevel -= float64(now.Sub(st.badAt)) / float64(leak)
		if st.badLevel <= 0 {
			// The bucket drained: forget the path history too, so a source that
			// returns much later starts from a clean slate rather than being unable
			// to ever trip the detector again.
			st.badLevel = 0
			st.badSeen = nil
		}
	}
	st.badAt = now

	if st.badSeen == nil {
		st.badSeen = make(map[string]struct{}, 8)
	}
	if _, seen := st.badSeen[path]; seen {
		return false
	}
	if len(st.badSeen) >= maxDistinctPaths {
		st.badSeen = make(map[string]struct{}, 8)
	}
	st.badSeen[path] = struct{}{}

	st.badLevel++
	if st.badLevel >= float64(capacity)-halfEvent {
		st.badLevel = 0
		st.badSeen = nil
		return true
	}
	return false
}

// halfEvent rounds the continuous bucket level to the nearest whole event when
// deciding whether the bucket has overflowed.
//
// Without it the detector is off by one in a way that depends on timing. The
// level after N distinct paths is N minus the leak accrued between them, so it
// approaches N from below and never reaches it: a capacity of 10 would quietly
// require an 11th path, and exactly when it fired would depend on floating-point
// drift. Comparing at half-event resolution makes "capacity N trips on the Nth
// distinct failing path" true whenever those paths arrive faster than the leak,
// and still lets a genuinely slow source drain the bucket as intended.
const halfEvent = 0.5

// noteAuthFailure feeds the brute-force sliding window and reports whether it filled.
func (c *counters) noteAuthFailure(key netip.Prefix, now time.Time, capacity int, window time.Duration) bool {
	if capacity <= 0 || window <= 0 {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	st := c.getLocked(key, now)
	cutoff := now.Add(-window)
	kept := st.bruteHits[:0]
	for _, t := range st.bruteHits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	st.bruteHits = append(kept, now)

	if len(st.bruteHits) >= capacity {
		st.bruteHits = nil
		return true
	}
	// Bound the slice even when the window is long and the capacity is high.
	if len(st.bruteHits) > capacity*4 {
		st.bruteHits = st.bruteHits[len(st.bruteHits)-capacity:]
	}
	return false
}

// noteRequest feeds the request-rate token bucket and reports whether it was exhausted.
func (c *counters) noteRequest(key netip.Prefix, now time.Time, rps, burst int) bool {
	if rps <= 0 || burst <= 0 {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	st := c.getLocked(key, now)
	if st.tokensAt.IsZero() {
		st.tokens = float64(burst)
	} else {
		st.tokens += now.Sub(st.tokensAt).Seconds() * float64(rps)
		if st.tokens > float64(burst) {
			st.tokens = float64(burst)
		}
	}
	st.tokensAt = now

	st.tokens--
	if st.tokens < 0 {
		st.tokens = 0
		return true
	}
	return false
}

// recordOffence advances the escalation ladder for a source and returns its new
// offence count, one-based.
//
// Decay is applied first: a source that has behaved for a full decay period drops
// one rung, so a single bad day does not permanently poison an address that later
// gets reassigned to somebody else by their ISP.
//
// "Behaved" is measured from the moment the previous ban RAN OUT, not from the
// offence that caused it, and the difference is not academic. A banned source
// cannot re-offend while it is banned, so measuring from the offence charges the
// ban's own duration against the decay period. With the shipped ladder that is
// self-defeating: rung 2 is 24h and the default decay is 24h, so every source
// released from a 24h ban has by definition been "quiet" for 24h and drops
// straight back to rung 1. Rungs 3 and 4 are then unreachable no matter how
// persistent the offender is — observed on a real source that oscillated 1h,
// 24h, 1h, 24h for nine days across fourteen bans without ever reaching 7d.
//
// Measuring from expiry makes the ladder behave the way its own configuration
// reads, at any combination of rungs and decay, instead of silently requiring
// decay to exceed the longest rung.
func (c *counters) recordOffence(key netip.Prefix, now time.Time, decay time.Duration) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	st := c.getLocked(key, now)
	if decay > 0 {
		if since := st.quietSince(); !since.IsZero() {
			if steps := int(now.Sub(since) / decay); steps > 0 {
				st.offences -= steps
				if st.offences < 0 {
					st.offences = 0
				}
			}
		}
	}
	st.offences++
	st.lastOffence = now
	return st.offences
}

// quietSince reports the instant from which this source has had the opportunity
// to behave: the end of its last ban, or the last offence when that ban has not
// expired yet or there was none.
func (st *sourceState) quietSince() time.Time {
	if st.banUntil.After(st.lastOffence) {
		return st.banUntil
	}
	return st.lastOffence
}

// noteBan records when the ban just issued for a source will expire, so the next
// offence can measure decay from the end of it. A permanent ban (zero expiry)
// records nothing: the source can never come back to re-offend.
func (c *counters) noteBan(key netip.Prefix, expires time.Time) {
	if expires.IsZero() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if st, ok := c.tbl[key]; ok {
		st.banUntil = expires
	}
}

// seed restores a ladder position from a ban that outlived the process.
//
// Bans persist and counters do not, so without this every restart hands the most
// persistent offenders a clean slate — and installing or upgrading the plugin
// REQUIRES a restart, so it happens routinely rather than rarely. A source whose
// stored ban says "offence 7" must come back at rung 7.
//
// Takes the maximum rather than overwriting, so replaying the ban list can never
// walk a live ladder backwards.
func (c *counters) seed(key netip.Prefix, offences int, created, expires, now time.Time) {
	if offences <= 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	st := c.getLocked(key, now)
	if offences > st.offences {
		st.offences = offences
	}
	if created.After(st.lastOffence) {
		st.lastOffence = created
	}
	if expires.After(st.banUntil) {
		st.banUntil = expires
	}
}

// offences reports the current ladder position without advancing it.
func (c *counters) offences(key netip.Prefix) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if st, ok := c.tbl[key]; ok {
		return st.offences
	}
	return 0
}

// forget drops all counters for a source. Used when an operator unbans by hand:
// leaving the ladder position behind would re-ban them at the next rung on the
// very next probe, which is not what "unblock" means to the person clicking it.
func (c *counters) forget(key netip.Prefix) {
	c.mu.Lock()
	delete(c.tbl, key)
	c.mu.Unlock()
}

// sweep drops records untouched for longer than idle, and returns how many went.
func (c *counters) sweep(now time.Time, idle time.Duration) int {
	if idle <= 0 {
		idle = time.Hour
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := now.Add(-idle)
	removed := 0
	for k, st := range c.tbl {
		if st.lastSeen.Before(cutoff) {
			delete(c.tbl, k)
			removed++
		}
	}
	return removed
}

// size reports how many sources are being tracked.
// SourceEntry is one row of the tracked-source table, safe to hand to the admin
// API. A NAMED struct, and it carries copies of the scalars rather than the
// internal *sourceState: the caller must never hold a pointer into the table it
// no longer has the lock for, and Yaegi mangles structs that reach a response
// through an interface{}.
type SourceEntry struct {
	Key      string    `json:"key"`
	LastSeen time.Time `json:"lastSeen"`
	Offences int       `json:"offences"`
	BadPaths int       `json:"badPaths"`
}

// recent returns at most n tracked sources, most recently seen first.
//
// mu is the same lock every inbound request takes, so it is held ONLY for the
// scalar copy — never across the sort, and never across JSON encoding. That is
// also why this is a dedicated endpoint rather than part of the state payload the
// console polls every three seconds: at the default cap of 50000 sources, doing
// this on every poll would stall the proxy for as long as the console is open.
func (c *counters) recent(n int) ([]SourceEntry, int) {
	if n <= 0 {
		n = 50
	}

	c.mu.Lock()
	total := len(c.tbl)
	out := make([]SourceEntry, 0, total)
	for k, st := range c.tbl {
		out = append(out, SourceEntry{
			Key:      k.String(),
			LastSeen: st.lastSeen.UTC(),
			Offences: st.offences,
			BadPaths: len(st.badSeen),
		})
	}
	c.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].Key < out[j].Key
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if len(out) > n {
		out = out[:n]
	}
	return out, total
}

func (c *counters) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.tbl)
}

// evicted reports how many records the cap has discarded.
func (c *counters) evicted() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evictions
}
