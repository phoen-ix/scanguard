package scanguard

import (
	"sort"
	"sync"
	"time"
)

// Event kinds.
const (
	eventBan    = "ban"
	eventUnban  = "unban"
	eventReject = "reject"
)

// Event is one entry in the live activity log shown by the admin UI and pushed
// to webhooks. Everything here is derived from a request that has already been
// judged, so it is safe to render — but the UI must still escape it, because
// Path and UA are attacker-controlled text.
type Event struct {
	Seq      uint64    `json:"seq"`
	Time     time.Time `json:"time"`
	Kind     string    `json:"kind"`
	Key      string    `json:"key"`
	Client   string    `json:"client,omitempty"`
	Detector string    `json:"detector,omitempty"`
	Rule     string    `json:"rule,omitempty"`
	Method   string    `json:"method,omitempty"`
	Host     string    `json:"host,omitempty"`
	Path     string    `json:"path,omitempty"`
	UA       string    `json:"ua,omitempty"`
	Status   int       `json:"status,omitempty"`
	BanFor   string    `json:"banFor,omitempty"`
	DryRun   bool      `json:"dryRun,omitempty"`
	Actor    string    `json:"actor,omitempty"`
	Country  string    `json:"country,omitempty"`
}

// eventLog holds the recent activity shown by the admin UI. Fixed size is the
// point: an event log that grows with attack volume is a memory leak with a
// friendly name.
//
// It is TWO rings, not one. Rejections of already-banned sources are recorded per
// request, and a banned scanner keeps hammering: measured on a live deployment,
// one source sent 433 requests a minute for days, and the single 500-entry ring
// held ten seconds of history, all of it rejects. Every ban had been pushed out
// within a minute of being issued, so the console's Bans filter was empty on open
// and there was no way to review what had been banned, or why. The second ring
// holds only bans and unbans — the events that carry a rule, a path and a
// user-agent worth acting on — so they survive any volume of rejects. Both rings
// share one sequence counter, so incremental polling works across them.
type eventLog struct {
	mu   sync.Mutex
	all  eventRing
	bans eventRing
	seq  uint64
}

// eventRing is one fixed-size buffer. The caller holds eventLog.mu.
type eventRing struct {
	buf    []Event
	next   int
	filled bool
}

func newEventLog(size int) *eventLog {
	if size <= 0 {
		size = 500
	}
	return &eventLog{
		all:  eventRing{buf: make([]Event, size)},
		bans: eventRing{buf: make([]Event, size)},
	}
}

func (r *eventRing) add(e Event) {
	r.buf[r.next] = e
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.filled = true
	}
}

// count reports how many events the ring holds.
func (r *eventRing) count() int {
	if r.filled {
		return len(r.buf)
	}
	return r.next
}

// at returns the i-th newest event, 0 being the newest. The caller bounds i by count.
func (r *eventRing) at(i int) Event {
	idx := r.next - 1 - i
	for idx < 0 {
		idx += len(r.buf)
	}
	return r.buf[idx]
}

// add stamps and stores an event, returning it with its sequence number set.
func (l *eventLog) add(e Event) Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	e.Seq = l.seq
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	// Attacker-controlled strings are truncated here rather than at render time, so
	// a multi-megabyte URI cannot bloat the ring buffer.
	e.Path = truncate(e.Path, 512)
	e.UA = truncate(e.UA, 256)
	e.Host = truncate(e.Host, 253)
	e.Rule = truncate(e.Rule, 256)

	l.all.add(e)
	if e.Kind != eventReject {
		l.bans.add(e)
	}
	return e
}

// recent returns up to n events of every kind, newest first.
func (l *eventLog) recent(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	total := l.all.count()
	if n <= 0 || n > total {
		n = total
	}
	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, l.all.at(i))
	}
	return out
}

// since returns events newer than seq, oldest first, for incremental polling by
// the admin UI. Events already overwritten in the ring are simply gone; the UI
// notices because the oldest returned sequence jumps.
func (l *eventLog) since(seq uint64, limit int) []Event {
	return l.sinceKind(seq, limit, "")
}

// sinceKind is since restricted to one event kind, or every kind when kind is
// empty.
//
// Bans and unbans are read from their own ring, which is what makes the filter
// useful: on a busy instance the shared ring is overwhelmingly rejects — 92% when
// this was first measured, 100% on a later reading — and a ban filter over it
// returned whichever bans happened to fall inside the last few seconds. The limit
// is applied AFTER the kind filter for the same reason: filtering a limited page
// would return a page of rejects with the handful of bans in it dropped.
func (l *eventLog) sinceKind(seq uint64, limit int, kind string) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	ring := &l.all
	if kind == eventBan || kind == eventUnban {
		ring = &l.bans
	}
	if limit <= 0 {
		limit = len(ring.buf)
	}

	out := make([]Event, 0, 32)
	for i := ring.count() - 1; i >= 0; i-- {
		e := ring.at(i)
		if e.Seq > seq && (kind == "" || e.Kind == kind) {
			out = append(out, e)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// lastSeq reports the newest sequence number issued.
func (l *eventLog) lastSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.seq
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

// tally counts occurrences of a string key with a hard cap on distinct keys, for
// the "top offenders" and "most-probed paths" panels.
//
// The cap matters: the set of probed paths is attacker-controlled and unbounded.
// Once full, the tally stops admitting new keys until the next prune, which keeps
// the ranking useful without letting it become an attack surface.
type tally struct {
	mu     sync.Mutex
	counts map[string]int64
	max    int
}

func newTally(max int) *tally {
	if max <= 0 {
		max = 1000
	}
	return &tally{counts: make(map[string]int64), max: max}
}

func (t *tally) add(key string) {
	if key == "" {
		return
	}
	key = truncate(key, 256)

	t.mu.Lock()
	defer t.mu.Unlock()

	if _, exists := t.counts[key]; !exists {
		if len(t.counts) >= t.max {
			t.pruneLocked()
		}
		if len(t.counts) >= t.max {
			return
		}
	}
	t.counts[key]++
}

// pruneLocked halves the table by dropping the least-frequent half. Counts are
// kept for survivors, so a persistently-probed path keeps its rank.
func (t *tally) pruneLocked() {
	type entry struct {
		key   string
		count int64
	}
	all := make([]entry, 0, len(t.counts))
	for k, c := range t.counts {
		all = append(all, entry{key: k, count: c})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].count < all[j].count })

	for i := 0; i < len(all)/2; i++ {
		delete(t.counts, all[i].key)
	}
}

// TopEntry is one row of a ranking.
type TopEntry struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}

func (t *tally) top(n int) []TopEntry {
	t.mu.Lock()
	out := make([]TopEntry, 0, len(t.counts))
	for k, c := range t.counts {
		out = append(out, TopEntry{Key: k, Count: c})
	}
	t.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}
