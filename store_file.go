package scanguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// snapshotFile is the on-disk format. The version field exists so a future
// change can migrate instead of silently misreading.
type snapshotFile struct {
	Version int       `json:"version"`
	Written time.Time `json:"written"`
	Bans    []Ban     `json:"bans"`
	// Overrides is optional, so a snapshot written before rule editing existed
	// still reads cleanly and one written after is still readable by anything that
	// ignores the field. That two-way compatibility is why the version does not
	// need bumping for it.
	Overrides *Overrides `json:"overrides,omitempty"`
}

const snapshotVersion = 1

// fileStore is the memory store plus a JSON snapshot, so bans survive a Traefik
// restart. Treat the file as a cache rather than a ledger: it is not fsynced.
// (*os.File).Sync is plain os and would work under Yaegi, but a sync per ban
// under a scan is the IOPS cost the snapshot design avoids, and losing the last
// few bans to a power cut costs one re-detection each. Temp-write plus rename
// gives atomic replacement, which is the property that actually matters here.
type fileStore struct {
	*memStore
	path     string
	instance string
	// writable records whether persistence is actually available. A hardened
	// Traefik deployment may run with a read-only root filesystem and no volume;
	// that must degrade to in-memory operation, not take the whole config down.
	writable bool
	// detached is set when another instance took over this snapshot path
	// (claimStateFileLocked); the store keeps working in memory and stops
	// writing.
	detached atomic.Bool
	writeMu  sync.Mutex

	// pendingMu guards pending, the one deferred flush scheduleFlush may have
	// outstanding at a time.
	pendingMu sync.Mutex
	pending   bool
}

// scheduleFlush writes the snapshot within delay, folding every change made in
// the meantime into one write; delay 0 writes now. The deferred write runs on a
// timer goroutine, so it carries its own recover.
func (f *fileStore) scheduleFlush(delay time.Duration) {
	if delay <= 0 {
		if err := f.flush(); err != nil {
			logWarn(f.instance, "could not persist state", map[string]interface{}{"error": err.Error()})
		}
		return
	}
	f.pendingMu.Lock()
	if f.pending {
		f.pendingMu.Unlock()
		return
	}
	f.pending = true
	f.pendingMu.Unlock()
	time.AfterFunc(delay, func() {
		defer recoverPanic(f.instance, "snapshot flush")
		f.pendingMu.Lock()
		f.pending = false
		f.pendingMu.Unlock()
		if err := f.flush(); err != nil {
			logWarn(f.instance, "could not persist state", map[string]interface{}{"error": err.Error()})
		}
	})
}

func newFileStore(s *settings) (*fileStore, error) {
	fs := &fileStore{
		memStore: newMemStore(s.maxEntries),
		path:     s.storePath,
		instance: s.instanceName,
	}

	// store.failOpen applies here as it does to Redis: false means "a store I
	// cannot persist to is a startup error, not something to carry on quietly
	// without". It used to be read only by the Redis backend, so a deployment that
	// set failOpen: false and a file backend got the opposite of what it asked for
	// — silently, since the degraded mode logs a warning and serves normally.
	dir := filepath.Dir(fs.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		if !s.failOpen {
			return nil, fmt.Errorf("store.path: %s could not be created and store.failOpen is false: %w", dir, err)
		}
		warnOnce(fs.instance, "state-dir-unwritable",
			"state directory could not be created; scanguard will run in memory only and bans will not survive a restart",
			map[string]interface{}{"dir": dir, "error": err.Error()})
		return fs, nil
	}
	if err := fs.probeWritable(dir); err != nil {
		if !s.failOpen {
			return nil, fmt.Errorf("store.path: %s is not writable and store.failOpen is false: %w", dir, err)
		}
		warnOnce(fs.instance, "state-dir-unwritable",
			"state directory is not writable; scanguard will run in memory only and new bans will not survive a restart",
			map[string]interface{}{"dir": dir, "error": err.Error()})
		// A read-only volume can still hold a snapshot worth enforcing: the
		// load used to be skipped along with the writes, so it restored nothing.
		if loaded, lerr := fs.load(); lerr == nil && loaded > 0 {
			logInfo(fs.instance, "restored bans from a read-only state snapshot",
				map[string]interface{}{"path": fs.path, "bans": loaded})
		}
		return fs, nil
	}
	fs.writable = true

	loaded, err := fs.load()
	if err != nil {
		if !s.failOpen {
			return nil, fmt.Errorf("store.path: %s could not be read and store.failOpen is false: %w", fs.path, err)
		}
		// A corrupt or unreadable snapshot must not stop Traefik from starting.
		// Losing the ban list is recoverable; refusing to serve traffic is not.
		logWarn(fs.instance, "could not read state snapshot; starting with an empty ban list",
			map[string]interface{}{"path": fs.path, "error": err.Error()})
		return fs, nil
	}
	if loaded > 0 {
		logInfo(fs.instance, "restored bans from state snapshot",
			map[string]interface{}{"path": fs.path, "bans": loaded})
	}
	return fs, nil
}

func (f *fileStore) backend() string { return "file" }

func (f *fileStore) probeWritable(dir string) error {
	probe := filepath.Join(dir, ".scanguard-write-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return err
	}
	return os.Remove(probe)
}

func (f *fileStore) load() (int, error) {
	buf, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	if len(buf) == 0 {
		return 0, nil
	}

	var snap snapshotFile
	if err := json.Unmarshal(buf, &snap); err != nil {
		return 0, fmt.Errorf("snapshot is not valid JSON: %w", err)
	}
	if snap.Version != snapshotVersion {
		return 0, fmt.Errorf("snapshot version %d is not supported (want %d)", snap.Version, snapshotVersion)
	}
	if snap.Overrides != nil {
		f.mu.Lock()
		f.overrides = snap.Overrides
		f.mu.Unlock()
	}
	return f.restore(snap.Bans, time.Now()), nil
}

// flush writes the snapshot if anything changed. Callers may invoke it on every
// ban-list change and on a timer; an unchanged table costs one atomic bool read.
//
// The dirty flag is cleared BEFORE the table is copied, not after the file is
// written. Clearing it afterwards lost updates: a ban recorded between the copy
// and the clear was in memory, marked dirty, and then un-marked by a flush that
// had never seen it — so it stayed off disk until something else changed the
// table, and a restart in that window forgot it. Clearing first means such a ban
// re-dirties the table and the next flush carries it. A failed write puts the
// flag back so nothing is lost on the error path either.
func (f *fileStore) flush() error {
	if !f.writable || f.detached.Load() || !f.clearDirtyIfSet() {
		return nil
	}

	f.writeMu.Lock()
	defer f.writeMu.Unlock()

	snap := snapshotFile{
		Version:   snapshotVersion,
		Written:   time.Now().UTC(),
		Bans:      f.snapshot(),
		Overrides: f.loadOverrides(),
	}
	buf, err := json.Marshal(snap)
	if err != nil {
		f.markDirty()
		return fmt.Errorf("could not encode snapshot: %w", err)
	}

	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		f.markDirty()
		return fmt.Errorf("could not write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		f.markDirty()
		return fmt.Errorf("could not replace %s: %w", f.path, err)
	}
	return nil
}
