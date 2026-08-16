package scanguard

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func ban(keyStr string, expires time.Time) Ban {
	return Ban{
		Key:      keyStr,
		Detector: detectorSignature,
		Rule:     "/wp-login\\.php",
		Created:  time.Now().UTC(),
		Expires:  expires,
		Offences: 1,
	}
}

func TestMemStoreLifecycle(t *testing.T) {
	s := newMemStore(100)
	now := time.Now()
	k := netip.MustParsePrefix("203.0.113.1/32")

	if _, found := s.get(k, now); found {
		t.Fatal("an empty store must not report a ban")
	}

	if err := s.put(ban(k.String(), now.Add(time.Hour))); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, found := s.get(k, now); !found {
		t.Fatal("the ban was not stored")
	}

	// Expiry is evaluated lazily on read, so a ban is inert the moment it lapses
	// even if the janitor has not run.
	if _, found := s.get(k, now.Add(2*time.Hour)); found {
		t.Fatal("an expired ban must not be reported as active")
	}

	removed, err := s.delete(k)
	if err != nil || !removed {
		t.Fatalf("delete: removed=%v err=%v", removed, err)
	}
	if removed, _ = s.delete(k); removed {
		t.Fatal("deleting twice must report that nothing was there")
	}
}

func TestMemStorePermanentBan(t *testing.T) {
	s := newMemStore(100)
	k := netip.MustParsePrefix("203.0.113.2/32")

	if err := s.put(ban(k.String(), time.Time{})); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, found := s.get(k, time.Now().Add(100*365*24*time.Hour)); !found {
		t.Fatal("a permanent ban must never expire")
	}
}

func TestMemStoreSweepReturnsRemoved(t *testing.T) {
	s := newMemStore(100)
	now := time.Now()

	_ = s.put(ban("203.0.113.3/32", now.Add(-time.Minute)))
	_ = s.put(ban("203.0.113.4/32", now.Add(time.Hour)))

	removed := s.sweep(now)
	if len(removed) != 1 || removed[0].Key != "203.0.113.3/32" {
		t.Fatalf("sweep removed %v, want just the expired ban", removed)
	}
	if s.size() != 1 {
		t.Fatalf("store holds %d bans after sweep, want 1", s.size())
	}
}

// An unbounded ban table inside a reverse proxy is a memory-exhaustion vector.
// Manual and permanent bans must be the last things discarded.
func TestMemStoreCapPrefersKeepingManualBans(t *testing.T) {
	s := newMemStore(50)
	now := time.Now()

	manual := ban("203.0.113.99/32", time.Time{})
	manual.Manual = true
	_ = s.put(manual)

	for i := 0; i < 500; i++ {
		b := ban(fmt.Sprintf("10.0.%d.%d/32", i/256, i%256), now.Add(time.Duration(i)*time.Second))
		_ = s.put(b)
	}

	if s.size() > 50 {
		t.Fatalf("store holds %d bans, want at most 50", s.size())
	}
	if _, found := s.get(netip.MustParsePrefix("203.0.113.99/32"), now); !found {
		t.Error("the manual ban was evicted before automatic ones")
	}
}

func TestFileStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := mustSettings(t, func(c *Config) {
		c.InstanceName = "file-test"
		c.Store.Backend = "file"
		c.Store.Path = path
	})

	store, err := newFileStore(s)
	if err != nil {
		t.Fatalf("newFileStore: %v", err)
	}
	if !store.writable {
		t.Fatal("a writable temp directory must be detected as writable")
	}

	now := time.Now()
	_ = store.put(ban("203.0.113.10/32", now.Add(time.Hour)))
	_ = store.put(ban("203.0.113.11/32", now.Add(-time.Hour))) // already expired
	if err := store.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	reopened, err := newFileStore(s)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, found := reopened.get(netip.MustParsePrefix("203.0.113.10/32"), now); !found {
		t.Error("an active ban did not survive the round trip")
	}
	if _, found := reopened.get(netip.MustParsePrefix("203.0.113.11/32"), now); found {
		t.Error("an expired ban was restored")
	}
}

// A hardened Traefik runs with a read-only root filesystem. That must degrade to
// memory-only operation, never take the whole configuration down.
func TestFileStoreDegradesWhenNotWritable(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.InstanceName = "readonly-test"
		c.Store.Backend = "file"
		c.Store.Path = "/proc/definitely-not-writable/state.json"
	})

	store, err := newFileStore(s)
	if err != nil {
		t.Fatalf("an unwritable state path must not be a fatal error, got: %v", err)
	}
	if store.writable {
		t.Error("an unwritable path must not be reported as writable")
	}
	if err := store.put(ban("203.0.113.12/32", time.Now().Add(time.Hour))); err != nil {
		t.Errorf("the store must still work in memory: %v", err)
	}
	if err := store.flush(); err != nil {
		t.Errorf("flush must be a no-op when not writable, got: %v", err)
	}
}

func TestFileStoreSurvivesCorruptSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not json at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := mustSettings(t, func(c *Config) {
		c.InstanceName = "corrupt-test"
		c.Store.Backend = "file"
		c.Store.Path = path
	})

	store, err := newFileStore(s)
	if err != nil {
		t.Fatalf("a corrupt snapshot must not stop Traefik from starting: %v", err)
	}
	if store.size() != 0 {
		t.Error("a corrupt snapshot should yield an empty ban list")
	}
}

func TestFileStoreWritesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s := mustSettings(t, func(c *Config) {
		c.InstanceName = "atomic-test"
		c.Store.Backend = "file"
		c.Store.Path = path
	})
	store, _ := newFileStore(s)
	_ = store.put(ban("203.0.113.13/32", time.Now().Add(time.Hour)))
	if err := store.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// The temporary file must not be left behind: a stale .tmp beside the snapshot
	// means a write was interrupted and never cleaned up.
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error("the temporary file was left behind after a successful write")
	}

	// A second flush with nothing changed must not rewrite the file.
	before, _ := os.Stat(path)
	time.Sleep(10 * time.Millisecond)
	if err := store.flush(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("an unchanged store was rewritten; under a flood this burns IOPS for nothing")
	}
}

func TestEventRingBufferIsBounded(t *testing.T) {
	l := newEventLog(10)
	for i := 0; i < 100; i++ {
		l.add(Event{Kind: eventBan, Key: fmt.Sprintf("10.0.0.%d/32", i)})
	}

	recent := l.recent(0)
	if len(recent) != 10 {
		t.Fatalf("ring holds %d events, want 10", len(recent))
	}
	if recent[0].Key != "10.0.0.99/32" {
		t.Errorf("newest event is %s, want the last one added", recent[0].Key)
	}
	if l.lastSeq() != 100 {
		t.Errorf("lastSeq = %d, want 100", l.lastSeq())
	}

	since := l.since(95, 0)
	if len(since) != 5 {
		t.Fatalf("since(95) returned %d events, want 5", len(since))
	}
	if since[0].Seq != 96 {
		t.Errorf("since(95) starts at seq %d, want 96", since[0].Seq)
	}
}

func TestEventLogTruncatesAttackerText(t *testing.T) {
	l := newEventLog(4)
	huge := make([]byte, 100000)
	for i := range huge {
		huge[i] = 'A'
	}

	e := l.add(Event{Kind: eventBan, Path: string(huge), UA: string(huge)})
	if len(e.Path) > 600 || len(e.UA) > 300 {
		t.Fatalf("attacker-controlled text was not truncated: path=%d ua=%d", len(e.Path), len(e.UA))
	}
}

func TestTallyIsCappedAndRanked(t *testing.T) {
	tl := newTally(50)
	for i := 0; i < 1000; i++ {
		tl.add(fmt.Sprintf("/path-%d", i))
	}
	tl.add("/hot")
	for i := 0; i < 20; i++ {
		tl.add("/hot")
	}

	top := tl.top(3)
	if len(top) == 0 {
		t.Fatal("the tally returned nothing")
	}
	if top[0].Key != "/hot" {
		t.Errorf("top entry is %s, want /hot", top[0].Key)
	}
	if len(tl.counts) > 50 {
		t.Errorf("the tally holds %d keys, want at most 50", len(tl.counts))
	}
}

// writeFile is a small helper for tests that need to plant a state snapshot on
// disk before the store opens it.
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
