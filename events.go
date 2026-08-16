package scanguard

import (
	"sort"
	"sync"
	"time"
)

// Event kinds.
const (
	eventDetect = "detect"
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

// eventLog is a fixed-size ring buffer of recent events. Fixed size is the point:
// an event log that grows with attack volume is a memory leak with a friendly name.
type eventLog struct {
	mu     sync.Mutex
	buf    []Event
	next   int
	filled bool
	seq    uint64
}

func newEventLog(size int) *eventLog {
	if size <= 0 {
		size = 500
	}
	return &eventLog{buf: make([]Event, size)}
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

	l.buf[l.next] = e
	l.next = (l.next + 1) % len(l.buf)
	if l.next == 0 {
		l.filled = true
	}
	return e
}

// recent returns up to n events, newest first.
func (l *eventLog) recent(n int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	total := l.next
	if l.filled {
		total = len(l.buf)
	}
	if n <= 0 || n > total {
		n = total
	}

	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		idx := l.next - 1 - i
		for idx < 0 {
			idx += len(l.buf)
		}
		out = append(out, l.buf[idx])
	}
	return out
}

// since returns events newer than seq, oldest first, for incremental polling by
// the admin UI. Events already overwritten in the ring are simply gone; the UI
// notices because the oldest returned sequence jumps.
func (l *eventLog) since(seq uint64, limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	total := l.next
	if l.filled {
		total = len(l.buf)
	}
	if limit <= 0 {
		limit = len(l.buf)
	}

	out := make([]Event, 0, 32)
	for i := total - 1; i >= 0; i-- {
		idx := l.next - 1 - i
		for idx < 0 {
			idx += len(l.buf)
		}
		e := l.buf[idx]
		if e.Seq > seq {
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
