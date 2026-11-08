package scanguard

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pretendOrphaned makes rt look like a runtime that the latest reload did not
// rebuild and that has been quiet for an hour.
func pretendOrphaned(rt *runtime) {
	now := time.Now()
	rt.lastAcquired.Store(now.Add(-2 * time.Hour).UnixNano())
	lastAcquireAny.Store(now.UnixNano())
	rt.lastRequests = rt.stats.Requests.Load()
	rt.quietSince = now.Add(-time.Hour)
}

func registered(name string) *runtime {
	registryMu.Lock()
	defer registryMu.Unlock()
	return registry[name]
}

func TestOrphanedRuntimeIsRetired(t *testing.T) {
	h := build(t, nil)
	rt := registered(t.Name())
	send(h, "GET", "/wp-login.php", "203.0.113.150:1", nil)
	pretendOrphaned(rt)
	lines := captureLog(t, rt.tick)
	if registered(t.Name()) != nil {
		t.Fatal("an orphaned, quiet runtime was not retired")
	}
	if !rt.retired.Load() || fieldsOf(lines, "instance retired: the configuration no longer contains it") == nil {
		t.Error("the retirement was not flagged and logged")
	}
	// A later New builds a fresh runtime under the same name.
	build(t, nil)
	if fresh := registered(t.Name()); fresh == nil || fresh == rt {
		t.Error("New after a retirement did not build a fresh runtime")
	}
}

func TestLiveRuntimesAreNotRetired(t *testing.T) {
	cases := map[string]func(rt *runtime){
		"rebuilt by the latest reload": func(rt *runtime) { rt.lastAcquired.Store(lastAcquireAny.Load()) },
		"still serving":                func(rt *runtime) { rt.stats.Requests.Add(1) },
		"retirement switched off":      func(rt *runtime) {},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			build(t, func(c *Config) {
				if name == "retirement switched off" {
					c.RetireAfter = "0"
				}
			})
			rt := registered(t.Name())
			pretendOrphaned(rt)
			mutate(rt)
			rt.tick()
			if registered(t.Name()) != rt || rt.retired.Load() {
				t.Errorf("%s: the runtime was retired", name)
			}
		})
	}
}

// Two instances on one state file overwrote each other's snapshot. The newer
// one takes the file; the other stops writing and says so.
func TestTwoInstancesDoNotShareAStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	file := func(c *Config) {
		c.Store.Backend = "file"
		c.Store.Path = path
		c.Store.FlushDebounce = "0"
	}
	old := buildOn(t, t.Name()+"-old", "scanguard@test", file)
	var lines []logLine
	var renamed http.Handler
	lines = captureLog(t, func() { renamed = buildOn(t, t.Name()+"-new", "scanguard@test", file) })
	found := false
	for _, l := range lines {
		if strings.Contains(l.Msg, "same store.path") {
			found = true
		}
	}
	if !found {
		t.Error("the shared state file was not reported")
	}
	send(old, "GET", "/wp-login.php", "203.0.113.151:1", nil)
	send(renamed, "GET", "/wp-login.php", "203.0.113.152:1", nil)
	buf, _ := os.ReadFile(path)
	if strings.Contains(string(buf), "203.0.113.151/32") || !strings.Contains(string(buf), "203.0.113.152/32") {
		t.Errorf("the snapshot holds the wrong instance's bans: %s", buf)
	}
}
