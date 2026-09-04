package scanguard

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Ban is one active or expired block against a source prefix.
type Ban struct {
	Key      string    `json:"key"`
	Reason   string    `json:"reason"`
	Detector string    `json:"detector"`
	Rule     string    `json:"rule,omitempty"`
	Created  time.Time `json:"created"`
	// Expires is zero for a permanent ban.
	Expires  time.Time `json:"expires"`
	Offences int       `json:"offences"`
	Manual   bool      `json:"manual"`
	Actor    string    `json:"actor,omitempty"`
	LastPath string    `json:"lastPath,omitempty"`
	LastUA   string    `json:"lastUA,omitempty"`
	Country  string    `json:"country,omitempty"`
	// Hits counts requests rejected since this ban was created.
	Hits int64 `json:"hits"`
}

// active reports whether the ban is still in force at now.
func (b Ban) active(now time.Time) bool {
	return b.Expires.IsZero() || b.Expires.After(now)
}

// Permanent reports whether the ban never expires.
func (b Ban) Permanent() bool { return b.Expires.IsZero() }

// banStore holds the ban list. Only the ban list is abstracted: per-source
// counters deliberately stay process-local in every backend, because shipping a
// counter increment to Redis on every request would put a network round trip on
// the hot path to save state nobody needs to share. Bans are the only thing a
// second replica, or a restart, actually has to agree about.
type banStore interface {
	// get returns the ban for key if one is in force.
	get(key netip.Prefix, now time.Time) (Ban, bool)
	// put records or replaces a ban.
	put(b Ban) error
	// delete removes a ban and reports whether one was present.
	delete(key netip.Prefix) (bool, error)
	// list returns every ban currently held, expired ones excluded.
	list(now time.Time) []Ban
	// countHit records that a request was rejected by an existing ban.
	countHit(key netip.Prefix)
	// sweep drops expired bans and returns the ones that were removed.
	sweep(now time.Time) []Ban
	// flush persists state, where the backend has any.
	flush() error
	// backend names the implementation, for the admin API.
	backend() string
	// setKeyWidths tells the store how wide the detector aggregates a source
	// before it reaches the ban table, so it can tell an operator's range ban from
	// an ordinary one.
	//
	// On the interface rather than reached through a type assertion: Yaegi cannot
	// reliably assert to an anonymous interface type, and doing so segfaulted the
	// plugin at load time under the interpreter while compiling and testing
	// perfectly. Every backend embeds *memStore, so all three satisfy this for
	// free.
	setKeyWidths(v4, v6 int)
	// loadOverrides returns the console's saved rule edits, or nil if there are none.
	loadOverrides() *Overrides
	// saveOverrides records the console's rule edits.
	saveOverrides(ov *Overrides) error
}

// newBanStore builds the configured backend.
func newBanStore(s *settings) (banStore, error) {
	switch s.storeBackend {
	case "memory":
		return newMemStore(s.maxEntries), nil
	case "file":
		return newFileStore(s)
	case "redis":
		return newRedisStore(s)
	default:
		return nil, fmt.Errorf("store.backend: unsupported backend %q", s.storeBackend)
	}
}

// memStore is the in-memory ban list shared by every backend. The file backend
// snapshots it; the redis backend uses it as a local read cache.
type memStore struct {
	mu   sync.RWMutex
	bans map[netip.Prefix]*Ban
	// max caps the ban table. A distributed scan across a /16 can otherwise create
	// hundreds of thousands of entries inside the reverse proxy's heap, which turns
	// a defence into a memory-exhaustion vector.
	max int
	// dirty records whether anything changed since the last flush, so the file
	// backend can skip rewriting an unchanged snapshot.
	dirty bool
	// overrides are the console's live rule edits. They sit beside the ban list
	// because they share its lifecycle exactly: both are runtime state that has to
	// outlive a restart, and neither belongs in Traefik's configuration.
	overrides *Overrides

	// v4Bits and v6Bits are the widths the detector aggregates a source to before
	// it ever reaches this table, so every automatic ban is keyed at exactly one
	// of them. A stored ban WIDER than that can only have come from an operator
	// typing a CIDR into the console, and is the only kind that a plain map lookup
	// on the request key cannot find.
	v4Bits, v6Bits int
	// wide lists exactly those operator-entered prefixes, so the containment test
	// on lookup walks a handful of hand-typed entries rather than the whole ban
	// table. It stays empty on a deployment that never bans a range, which is the
	// common case and the one the hot path is written for.
	wide []netip.Prefix
}

func newMemStore(max int) *memStore {
	if max <= 0 {
		max = 50000
	}
	return &memStore{
		bans: make(map[netip.Prefix]*Ban),
		max:  max,
		// Full-length until the runtime says otherwise, so nothing is treated as a
		// range ban before the configured widths are known.
		v4Bits: 32,
		v6Bits: 128,
	}
}

func (m *memStore) backend() string { return "memory" }

// setKeyWidths tells the store how wide the detector's own ban keys are, so it
// can tell an operator's range ban apart from an ordinary one. Called on every
// configuration apply, because clientIP.ipv4Prefix and ipv6Prefix are editable.
func (m *memStore) setKeyWidths(v4, v6 int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if v4 == m.v4Bits && v6 == m.v6Bits {
		return
	}
	m.v4Bits, m.v6Bits = v4, v6
	m.rebuildWideLocked()
}

// isWideLocked reports whether a stored prefix is broader than the keys requests
// arrive under, and therefore needs a containment test rather than a map lookup.
func (m *memStore) isWideLocked(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() < m.v4Bits
	}
	return p.Bits() < m.v6Bits
}

func (m *memStore) rebuildWideLocked() {
	m.wide = m.wide[:0]
	for k := range m.bans {
		if m.isWideLocked(k) {
			m.wide = append(m.wide, k)
		}
	}
}

func (m *memStore) dropWideLocked(p netip.Prefix) {
	for i, w := range m.wide {
		if w == p {
			m.wide = append(m.wide[:i], m.wide[i+1:]...)
			return
		}
	}
}

// matchWideLocked finds an operator-entered range ban covering key. Ties are
// broken towards the most specific prefix, so a /24 ban and a /16 ban over the
// same address report the one the operator would expect to see named.
func (m *memStore) matchWideLocked(key netip.Prefix) (*Ban, bool) {
	var best *Ban
	bestBits := -1
	for _, w := range m.wide {
		if w.Bits() > bestBits && w.Contains(key.Addr()) {
			if b, ok := m.bans[w]; ok {
				best, bestBits = b, w.Bits()
			}
		}
	}
	return best, best != nil
}

func (m *memStore) get(key netip.Prefix, now time.Time) (Ban, bool) {
	m.mu.RLock()
	b, ok := m.bans[key]
	if !ok && len(m.wide) > 0 {
		// Only an operator's range ban can be missed by the exact lookup, and only
		// when one exists at all — so the scan is skipped entirely on the ordinary
		// path, and walks a hand-typed list when it is not.
		b, ok = m.matchWideLocked(key)
	}
	if !ok {
		m.mu.RUnlock()
		return Ban{}, false
	}
	out := *b
	m.mu.RUnlock()

	if !out.active(now) {
		return Ban{}, false
	}
	return out, true
}

func (m *memStore) put(b Ban) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, err := netip.ParsePrefix(b.Key)
	if err != nil {
		return fmt.Errorf("ban key %q is not a valid prefix: %w", b.Key, err)
	}
	stored := b
	_, existed := m.bans[key]
	m.bans[key] = &stored
	if !existed && m.isWideLocked(key) {
		m.wide = append(m.wide, key)
	}
	m.dirty = true
	m.evictLocked()
	return nil
}

func (m *memStore) delete(key netip.Prefix) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, ok := m.bans[key]
	if ok {
		delete(m.bans, key)
		m.dropWideLocked(key)
		m.dirty = true
	}
	return ok, nil
}

func (m *memStore) list(now time.Time) []Ban {
	m.mu.RLock()
	out := make([]Ban, 0, len(m.bans))
	for _, b := range m.bans {
		if b.active(now) {
			out = append(out, *b)
		}
	}
	m.mu.RUnlock()

	// Newest first: that is what an operator watching an attack wants to see.
	sort.Slice(out, func(i, j int) bool { return out[i].Created.After(out[j].Created) })
	return out
}

func (m *memStore) countHit(key netip.Prefix) {
	m.mu.Lock()
	b, ok := m.bans[key]
	if !ok && len(m.wide) > 0 {
		b, ok = m.matchWideLocked(key)
	}
	if ok {
		b.Hits++
	}
	m.mu.Unlock()
}

func (m *memStore) sweep(now time.Time) []Ban {
	m.mu.Lock()
	defer m.mu.Unlock()

	var removed []Ban
	for k, b := range m.bans {
		if !b.active(now) {
			removed = append(removed, *b)
			delete(m.bans, k)
			m.dropWideLocked(k)
		}
	}
	if len(removed) > 0 {
		m.dirty = true
	}
	return removed
}

func (m *memStore) flush() error { return nil }

func (m *memStore) loadOverrides() *Overrides {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.overrides.clone()
}

func (m *memStore) saveOverrides(ov *Overrides) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrides = ov.clone()
	m.dirty = true
	return nil
}

// evictLocked enforces the ban-table cap. Permanent and manual bans are kept in
// preference to automatic timed ones, then the soonest-expiring go first — those
// are the ones the system was about to forget anyway.
//
// Eviction runs in batches rather than one entry per insert: a full scan of a
// 50k-entry map is cheap when it happens once per 5000 inserts, and expensive if
// it happens on every one.
func (m *memStore) evictLocked() {
	if len(m.bans) <= m.max {
		return
	}
	target := len(m.bans) - m.max + m.max/10

	type candidate struct {
		key netip.Prefix
		ban *Ban
	}
	cands := make([]candidate, 0, len(m.bans))
	for k, b := range m.bans {
		cands = append(cands, candidate{key: k, ban: b})
	}
	sort.Slice(cands, func(i, j int) bool {
		a, b := cands[i].ban, cands[j].ban
		if a.Manual != b.Manual {
			return !a.Manual
		}
		if a.Permanent() != b.Permanent() {
			return !a.Permanent()
		}
		if a.Permanent() {
			return a.Created.Before(b.Created)
		}
		return a.Expires.Before(b.Expires)
	})

	for i := 0; i < target && i < len(cands); i++ {
		delete(m.bans, cands[i].key)
	}
	if len(m.wide) > 0 {
		m.rebuildWideLocked()
	}
	m.dirty = true
}

// snapshot copies the ban table for persistence.
func (m *memStore) snapshot() []Ban {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]Ban, 0, len(m.bans))
	for _, b := range m.bans {
		out = append(out, *b)
	}
	return out
}

// restore replaces the ban table, dropping entries that already expired.
func (m *memStore) restore(bans []Ban, now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	loaded := 0
	for i := range bans {
		b := bans[i]
		if !b.active(now) {
			continue
		}
		key, err := netip.ParsePrefix(b.Key)
		if err != nil {
			continue
		}
		stored := b
		m.bans[key] = &stored
		loaded++
	}
	// The map was written behind put()'s back, so the range-ban index has to be
	// derived again rather than maintained incrementally.
	m.rebuildWideLocked()
	m.dirty = false
	return loaded
}

func (m *memStore) isDirty() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dirty
}

func (m *memStore) clearDirty() {
	m.mu.Lock()
	m.dirty = false
	m.mu.Unlock()
}

func (m *memStore) size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.bans)
}
