package scanguard

// Regression tests from the second audit round, runtime lifecycle: the janitor
// period, how a reload publishes, what a backend change carries, and what the
// rule editor says when saved edits stop applying.

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// reloadDetector rebuilds the detection middleware for instance, the way a
// Traefik reload does, and returns the handler.
func reloadDetector(t *testing.T, instance string, mutate func(*Config)) http.Handler {
	t.Helper()
	cfg := CreateConfig()
	cfg.InstanceName = instance
	cfg.Admin.Enabled = true
	cfg.Admin.Token = ruleToken
	if mutate != nil {
		mutate(cfg)
	}
	h, err := New(context.Background(), okBackend(), cfg, "scanguard@test")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	return h
}

// The janitor used to read store.snapshotInterval once, when its goroutine
// started, from whichever middleware Traefik happened to build first. With the
// console first the detector's value was ignored for the life of the process,
// a reload changing it did nothing, and values under the floor were raised to
// it silently.
func TestJanitorIntervalFollowsTheDetectorAndTheReload(t *testing.T) {
	resetRuntime(t.Name())
	defer resetRuntime(t.Name())
	instance := t.Name()
	console := CreateConfig()
	console.InstanceName = instance
	console.UIMode = true
	console.Admin.Enabled = true
	console.Admin.Token = ruleToken
	if _, err := New(context.Background(), okBackend(), console, "console@test"); err != nil {
		t.Fatalf("console: %v", err)
	}
	rt := registry[instance]
	if got := rt.janitorInterval(); got != janitorFloor {
		t.Fatalf("console alone: interval %v, want the %v default", got, janitorFloor)
	}

	reloadDetector(t, instance, func(c *Config) { c.Store.SnapshotInterval = "2m" })
	if got := rt.janitorInterval(); got != 2*time.Minute {
		t.Errorf("after the detector was built: interval %v, want 2m", got)
	}
	reloadDetector(t, instance, func(c *Config) { c.Store.SnapshotInterval = "5m" })
	if got := rt.janitorInterval(); got != 5*time.Minute {
		t.Errorf("after a reload: interval %v, want 5m", got)
	}

	lines := captureLog(t, func() {
		reloadDetector(t, instance, func(c *Config) { c.Store.SnapshotInterval = "10s" })
		if got := rt.janitorInterval(); got != janitorFloor {
			t.Errorf("10s was not floored: %v", got)
		}
		rt.janitorInterval()
	})
	floored := 0
	for _, l := range lines {
		if strings.Contains(l.Msg, "below the 30s minimum") {
			floored++
		}
	}
	if floored != 1 {
		t.Errorf("flooring was logged %d times, want once", floored)
	}
}

// A detector reload used to publish the plain file configuration and then,
// a few statements later, the one with the console's edits re-layered. Requests
// in between ran without the console's rules — including a console-set dryRun,
// so real bans were written in what the console showed as a dry run. The
// effective configuration is now worked out first and published once, so a
// reader can never observe the file's dryRun.
func TestReloadNeverPublishesTheFileConfigurationUnderneathConsoleEdits(t *testing.T) {
	resetRuntime(t.Name())
	defer resetRuntime(t.Name())
	_, rt := consoleHandler(t, nil)
	dry := true
	if err := rt.setOverrides(&Overrides{Version: overridesVersion, DryRun: &dry}, "test"); err != nil {
		t.Fatalf("setOverrides: %v", err)
	}

	var stop atomic.Bool
	var flickers atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if s := rt.settings(); s != nil && !s.dryRun {
				flickers.Add(1)
			}
		}
	}()
	for i := 0; i < 30; i++ {
		trap := fmt.Sprintf("/trap-%d", i)
		reloadDetector(t, t.Name(), func(c *Config) { c.Detectors.Honeypots.Paths = []string{trap} })
	}
	stop.Store(true)
	wg.Wait()

	if n := flickers.Load(); n != 0 {
		t.Errorf("the file configuration (dryRun off) was observable %d times during reloads", n)
	}
	if !rt.settings().dryRun {
		t.Error("the console's dryRun did not survive the reloads")
	}
}

// rt.cfg had two writers under two different locks: the console's admin block
// was published under registryMu, a rule save under rt.mu. Read, merge, store
// on both sides, so a token rotation racing a rule save lost one of the two.
func TestConsoleReloadAndRuleSaveDoNotLoseEachOther(t *testing.T) {
	resetRuntime(t.Name())
	defer resetRuntime(t.Name())
	// The detector declares no admin block, as in a real deployment: the token
	// is the console's to set, and a rule save inherits it.
	build(t, nil)
	instance := t.Name()
	rt := registry[instance]

	const rounds = 40
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			console := CreateConfig()
			console.InstanceName = instance
			console.UIMode = true
			console.Admin.Enabled = true
			console.Admin.Token = fmt.Sprintf("rotated-token-%04d-0123456789", i)
			if _, err := New(context.Background(), okBackend(), console, "console@test"); err != nil {
				t.Errorf("console reload %d: %v", i, err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			dry := i%2 == 0
			if err := rt.setOverrides(&Overrides{Version: overridesVersion, DryRun: &dry}, "test"); err != nil {
				t.Errorf("setOverrides %d: %v", i, err)
				return
			}
		}
	}()
	wg.Wait()

	s := rt.settings()
	wantToken := fmt.Sprintf("rotated-token-%04d-0123456789", rounds-1)
	if s.adminToken != wantToken {
		t.Errorf("the console's last token was lost: running with %q", s.adminToken)
	}
	// The last rule save set dryRun to (rounds-1)%2 == 0, i.e. false.
	if s.dryRun != ((rounds-1)%2 == 0) {
		t.Errorf("the last rule save was lost: dryRun=%v", s.dryRun)
	}
}

// A reload that changes the store backend carried the live bans into the new
// store but not the console's saved rules. The file backend's next snapshot then
// wrote `overrides: null`, and the edits were gone on the next restart.
func TestBackendChangeCarriesTheConsoleRules(t *testing.T) {
	resetRuntime(t.Name())
	defer resetRuntime(t.Name())
	h, rt := consoleHandler(t, nil)
	instance := t.Name()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.Detectors.Honeypots.Enabled = true
	edit.Detectors.Honeypots.Paths = []string{"/carried-trap"}
	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", rec.Code, rec.Body.String())
	}
	if got := send(h, "GET", "/wp-login.php", "203.0.113.190:1", nil).Code; got != 403 {
		t.Fatalf("probe returned %d", got)
	}

	// The operator moves from memory to a file store in the dynamic configuration.
	h2 := reloadDetector(t, instance, func(c *Config) {
		c.Store.Backend = "file"
		c.Store.Path = path
	})
	if rt.store().backend() != "file" {
		t.Fatalf("store is %q after the reload, want file", rt.store().backend())
	}
	if _, ok := rt.store().get(key("203.0.113.190/32"), time.Now()); !ok {
		t.Error("the live ban was not carried to the new store")
	}
	if stored := rt.store().loadOverrides(); stored.empty() || stored.Detectors == nil {
		t.Fatal("the console's rules were not carried to the new store")
	}
	if err := rt.store().flush(); err != nil {
		t.Fatal(err)
	}
	buf, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(buf), "/carried-trap") {
		t.Fatalf("the snapshot does not hold the console's rules: %v %s", err, buf)
	}
	if got := send(h2, "GET", "/carried-trap", "203.0.113.191:1", nil).Code; got != 403 {
		t.Errorf("the console honeypot is not in force after the backend change, got %d", got)
	}

	// And they survive the restart the file store exists for.
	resetRuntime(instance)
	h3 := reloadDetector(t, instance, func(c *Config) {
		c.Store.Backend = "file"
		c.Store.Path = path
	})
	if got := send(h3, "GET", "/carried-trap", "203.0.113.192:1", nil).Code; got != 403 {
		t.Errorf("the console honeypot was lost across the restart, got %d", got)
	}
}

// When a reload brings a file configuration the saved console edits no longer
// apply to, the file configuration runs. The rule editor used to show the
// layered set as effective anyway, so rules were listed as in force that were
// not; it now says the edits are stale and shows what actually runs.
func TestStaleConsoleRulesAreReportedNotListedAsEffective(t *testing.T) {
	resetRuntime(t.Name())
	defer resetRuntime(t.Name())
	h, rt := consoleHandler(t, nil)
	instance := t.Name()

	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.Enforcement.Subnet = SubnetConfig{Enabled: true, IPv4Prefix: 24, IPv6Prefix: 48, Threshold: 3, Window: "1h"}
	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", rec.Code, rec.Body.String())
	}
	if !rt.settings().subnet.Enabled {
		t.Fatal("the subnet edit did not apply")
	}

	// The file now keys bans at /24, so a /24 range escalation is no longer
	// wider than the ban key and the saved enforcement section fails to parse.
	h2 := reloadDetector(t, instance, func(c *Config) { c.ClientIP.IPv4Prefix = 24 })
	if rt.settings().subnet.Enabled {
		t.Fatal("an invalid override stayed in force after the reload")
	}
	payload := fetchRules(t, h2)
	stale, _ := payload["stale"].(string)
	if stale == "" {
		t.Fatal("the rules payload does not say the saved edits are stale")
	}
	if effective := editableOf(t, payload, "effective"); effective.Enforcement.Subnet.Enabled {
		t.Error("stale edits are reported as the effective configuration")
	}
	if owned, _ := payload["overridden"].([]interface{}); len(owned) == 0 {
		t.Error("the saved sections are no longer listed, so the operator cannot see what was saved")
	}

	// Saving a set that applies clears the flag.
	edit = editableOf(t, payload, "fromFile")
	edit.Detectors.Honeypots.Enabled = true
	edit.Detectors.Honeypots.Paths = []string{"/fresh-trap"}
	if rec := ruleRequest(t, h2, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT after the reload returned %d: %s", rec.Code, rec.Body.String())
	}
	if again := fetchRules(t, h2); again["stale"] != nil {
		t.Errorf("stale still reported after a successful save: %v", again["stale"])
	}
}

// store.maxEntries used to be part of the store fingerprint, so changing it
// rebuilt the whole backend and re-put every ban into the new one. The cap is
// applied in place now, and the notifier and geo cache — which hold the
// AbuseIPDB dedupe and a week of lookups — survive a reload that does not
// touch their settings.
func TestUnrelatedReloadsKeepTheStoreNotifierAndGeoCache(t *testing.T) {
	resetRuntime(t.Name())
	defer resetRuntime(t.Name())
	h, rt := consoleHandler(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: "https://hooks.example.test/a"}}
	})
	instance := t.Name()
	if got := send(h, "GET", "/wp-login.php", "203.0.113.193:1", nil).Code; got != 403 {
		t.Fatalf("probe returned %d", got)
	}
	store, notifier, geo := rt.store(), rt.notifier(), rt.geo()

	reloadDetector(t, instance, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: "https://hooks.example.test/a"}}
		c.Store.MaxEntries = 777
		c.Detectors.Honeypots.Paths = []string{"/unrelated"}
	})
	if rt.store() != store {
		t.Error("a maxEntries change rebuilt the store")
	}
	if ms, ok := rt.store().(*memStore); !ok || ms.max != 777 {
		t.Errorf("the new cap was not applied in place: %+v", rt.store())
	}
	if _, ok := rt.store().get(key("203.0.113.193/32"), time.Now()); !ok {
		t.Error("the ban did not survive the reload")
	}
	if rt.notifier() != notifier {
		t.Error("a reload that left notify alone rebuilt the notifier")
	}
	if rt.geo() != geo {
		t.Error("a reload that left geo alone rebuilt the geo cache")
	}

	reloadDetector(t, instance, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: "https://hooks.example.test/b"}}
		c.Geo.Enabled = true
		c.Store.MaxEntries = 777
		c.Detectors.Honeypots.Paths = []string{"/unrelated"}
	})
	if rt.notifier() == notifier {
		t.Error("a webhook change did not rebuild the notifier")
	}
	if rt.geo() == geo {
		t.Error("enabling geo did not rebuild the geo cache")
	}
}
