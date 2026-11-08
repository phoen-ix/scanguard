package scanguard

// Request-path branches that had no handler-level test: inverting any of them
// left the suite green. Each case drives New() and ServeHTTP the way Traefik
// does.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignatureExclusionsAreHonoured(t *testing.T) {
	h := build(t, func(c *Config) { c.Detectors.Signatures.Exclude = []string{`^/wp-login\.php$`} })
	if got := send(h, "GET", "/wp-login.php", "203.0.113.120:1", nil).Code; got != 200 {
		t.Errorf("an excluded path was refused: %d", got)
	}
	if got := send(h, "GET", "/wp-config.php", "203.0.113.121:1", nil).Code; got != 403 {
		t.Errorf("a signature beside the exclusion stopped firing: %d", got)
	}
}

// Body scanning reads the body and must put it back: the backend has to see
// the full request whether or not anything matched.
func TestBodyScanBlocksAPayloadAndRewindsTheBody(t *testing.T) {
	cfg := CreateConfig()
	cfg.InstanceName = t.Name()
	cfg.Detectors.Payload = PayloadConfig{Enabled: true, UseDefaults: true, ScanBody: true, MaxBodyBytes: 4096}
	var seen string
	echo := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		seen = string(b)
		_, _ = rw.Write([]byte("ok"))
	})
	h, err := New(context.Background(), echo, cfg, "scanguard@test")
	if err != nil {
		t.Fatal(err)
	}
	post := func(remote, body string) int {
		req := httptest.NewRequest("POST", "/form", strings.NewReader(body))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := post("203.0.113.122:1", "q=1 UNION SELECT password FROM users"); got != 403 {
		t.Errorf("an injection payload in the body was passed: %d", got)
	}
	if got := post("203.0.113.123:1", "name=hello+world"); got != 200 || seen != "name=hello+world" {
		t.Errorf("an ordinary body returned %d and reached the backend as %q", got, seen)
	}
}

func TestEmptyUserAgentIsBannedOnlyWhenConfigured(t *testing.T) {
	off := build(t, nil)
	if got := send(off, "GET", "/", "203.0.113.124:1", nil).Code; got != 200 {
		t.Errorf("an empty user-agent was banned with banEmptyUA off: %d", got)
	}
	on := buildOn(t, t.Name()+"-on", "scanguard@test", func(c *Config) { c.Detectors.UserAgent.BanEmptyUA = true })
	if got := send(on, "GET", "/", "203.0.113.125:1", nil).Code; got != 403 {
		t.Errorf("an empty user-agent passed with banEmptyUA on: %d", got)
	}
}

func TestRejectBodyIsSentToBannedSources(t *testing.T) {
	h := build(t, func(c *Config) { c.Enforcement.RejectBody = "go away" })
	rec := send(h, "GET", "/wp-login.php", "203.0.113.126:1", nil)
	if rec.Code != 403 || strings.TrimSpace(rec.Body.String()) != "go away" {
		t.Errorf("reject returned %d %q, want 403 \"go away\"", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("a rejection may be cached")
	}
}

// bruteForce.paths narrows the detector to real login endpoints.
func TestBruteForcePathsNarrowTheDetector(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Detectors.Signatures.Enabled = false
		c.Detectors.BadPaths.Enabled = false
		c.Detectors.BruteForce = BruteForceConfig{Enabled: true, Capacity: 2, Window: "60s", Statuses: []int{401}, Paths: []string{"^/admin-login$"}}
	})
	for i := 0; i < 4; i++ {
		send(h, "POST", "/login", "203.0.113.127:1", nil)
	}
	if got := send(h, "GET", "/", "203.0.113.127:1", nil).Code; got != 200 {
		t.Errorf("401s on a path outside bruteForce.paths banned the source: %d", got)
	}
}

// store.failOpen: false makes an unusable file store a startup error. The
// comment in newFileStore says this regressed once; nothing tested it.
func TestFileStoreFailClosed(t *testing.T) {
	failClosed := func(path string) *settings {
		return mustSettings(t, func(c *Config) {
			c.InstanceName = t.Name()
			c.Store.Backend = "file"
			c.Store.Path = path
			c.Store.FailOpen = false
		})
	}

	// The directory cannot be created: a path under a regular file.
	file := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileStore(failClosed(filepath.Join(file, "state.json"))); err == nil {
		t.Error("an uncreatable state directory was accepted with failOpen false")
	}

	// The snapshot cannot be read.
	corrupt := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(corrupt, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newFileStore(failClosed(corrupt)); err == nil {
		t.Error("an unreadable snapshot was accepted with failOpen false")
	}

	// The directory is not writable. Root writes anywhere, so this needs a
	// non-root test run.
	if os.Geteuid() != 0 {
		ro := t.TempDir()
		if err := os.Chmod(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(ro, 0o700) }()
		if _, err := newFileStore(failClosed(filepath.Join(ro, "state.json"))); err == nil {
			t.Error("an unwritable state directory was accepted with failOpen false")
		}
	}

	// And the same three with failOpen true degrade instead of failing.
	if _, err := newFileStore(mustSettings(t, func(c *Config) {
		c.InstanceName = t.Name()
		c.Store.Backend = "file"
		c.Store.Path = corrupt
	})); err != nil {
		t.Errorf("failOpen true still failed on a corrupt snapshot: %v", err)
	}
}

// A snapshot on a read-only volume is still enforced; the load used to be
// skipped along with the writes.
func TestReadOnlySnapshotIsStillRestored(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere; a read-only directory needs a non-root run")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s := mustSettings(t, func(c *Config) {
		c.InstanceName = t.Name()
		c.Store.Backend = "file"
		c.Store.Path = path
	})
	w, err := newFileStore(s)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.put(ban("203.0.113.128/32", time.Now().Add(time.Hour)))
	if err := w.flush(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	r, err := newFileStore(s)
	if err != nil {
		t.Fatal(err)
	}
	if r.writable {
		t.Fatal("a read-only directory was reported writable")
	}
	if _, ok := r.get(key("203.0.113.128/32"), time.Now()); !ok {
		t.Error("the snapshot on a read-only volume was not restored")
	}
}
