package scanguard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
// restart. Treat the file as a cache rather than a ledger: durably fsyncing it
// would need the syscall package, which Traefik gates behind the useUnsafe flag
// and which marks a plugin as unsafe in the catalog. Temp-write plus rename gives
// atomic replacement, which is the property that actually matters here.
type fileStore struct {
	*memStore
	path     string
	instance string
	// writable records whether persistence is actually available. A hardened
	// Traefik deployment may run with a read-only root filesystem and no volume;
	// that must degrade to in-memory operation, not take the whole config down.
	writable bool
	writeMu  sync.Mutex
}

func newFileStore(s *settings) (*fileStore, error) {
	fs := &fileStore{
		memStore: newMemStore(s.maxEntries),
		path:     s.storePath,
		instance: s.instanceName,
	}

	dir := filepath.Dir(fs.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		warnOnce(fs.instance, "state-dir-unwritable",
			"state directory could not be created; scanguard will run in memory only and bans will not survive a restart",
			map[string]interface{}{"dir": dir, "error": err.Error()})
		return fs, nil
	}
	if err := fs.probeWritable(dir); err != nil {
		warnOnce(fs.instance, "state-dir-unwritable",
			"state directory is not writable; scanguard will run in memory only and bans will not survive a restart",
			map[string]interface{}{"dir": dir, "error": err.Error()})
		return fs, nil
	}
	fs.writable = true

	loaded, err := fs.load()
	if err != nil {
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
func (f *fileStore) flush() error {
	if !f.writable || !f.isDirty() {
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
		return fmt.Errorf("could not encode snapshot: %w", err)
	}

	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, buf, 0o600); err != nil {
		return fmt.Errorf("could not write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("could not replace %s: %w", f.path, err)
	}

	f.clearDirty()
	return nil
}
