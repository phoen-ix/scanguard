package scanguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const ruleToken = "test-token-0123456789"

// resetRuntime forgets an instance so a test can simulate a Traefik restart:
// runtime state is a process-global registry, which is the whole reason bans and
// rule edits survive a configuration reload.
func resetRuntime(name string) {
	registryMu.Lock()
	delete(registry, name)
	registryMu.Unlock()
}

func consoleHandler(t *testing.T, mutate func(*Config)) (http.Handler, *runtime) {
	t.Helper()
	cfg := CreateConfig()
	cfg.InstanceName = t.Name()
	cfg.Admin.Enabled = true
	cfg.Admin.Token = ruleToken
	if mutate != nil {
		mutate(cfg)
	}
	h, err := New(context.Background(), okBackend(), cfg, "scanguard@test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	registryMu.Lock()
	rt := registry[cfg.InstanceName]
	registryMu.Unlock()
	return h, rt
}

func ruleRequest(t *testing.T, h http.Handler, method string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = strings.NewReader(string(buf))
	} else {
		reader = strings.NewReader("")
	}

	req := httptest.NewRequest(method, "/__scanguard/api/rules", reader)
	req.RemoteAddr = "203.0.113.200:1"
	req.Header.Set("X-Scanguard-Token", ruleToken)
	req.Header.Set("Content-Type", "application/json")
	if method != http.MethodGet {
		req.Header.Set("X-Scanguard-Action", "1")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func fetchRules(t *testing.T, h http.Handler) map[string]interface{} {
	t.Helper()
	rec := ruleRequest(t, h, http.MethodGet, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET rules returned %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	return out
}

// editableOf reads the effective section out of a rules response and returns it
// as the struct the console would send back.
func editableOf(t *testing.T, payload map[string]interface{}, field string) editableConfig {
	t.Helper()
	buf, err := json.Marshal(payload[field])
	if err != nil {
		t.Fatalf("marshal %s: %v", field, err)
	}
	var out editableConfig
	if err := json.Unmarshal(buf, &out); err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	return out
}

// The point of the whole feature: an edit made through the API changes what the
// middleware does on the very next request, with no restart and no reload.
func TestRuleEditAppliesImmediately(t *testing.T) {
	h, _ := consoleHandler(t, nil)

	if got := send(h, "GET", "/secret-trap", "203.0.113.30:1", nil).Code; got != 200 {
		t.Fatalf("the path is not a trap yet, got %d", got)
	}

	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.Detectors.Honeypots.Enabled = true
	edit.Detectors.Honeypots.Paths = []string{"/secret-trap"}

	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT rules returned %d: %s", rec.Code, rec.Body.String())
	}

	if got := send(h, "GET", "/secret-trap", "203.0.113.31:1", nil).Code; got != 403 {
		t.Fatalf("the new honeypot did not take effect, got %d", got)
	}
}

// A bad edit must be refused with a reason, and must leave the running
// configuration exactly as it was. Rejecting it after it has already been applied
// would mean a typo in a browser silently stops detection.
func TestInvalidRuleEditChangesNothing(t *testing.T) {
	h, rt := consoleHandler(t, nil)
	before := rt.settings()

	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.Detectors.Signatures.Patterns = []string{"([unclosed"}

	rec := ruleRequest(t, h, http.MethodPut, edit)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an invalid pattern returned %d, want 422", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "not a valid regular expression") {
		t.Errorf("the error should explain what is wrong, got: %s", rec.Body.String())
	}
	if rt.settings() != before {
		t.Error("the running configuration was replaced despite the edit being rejected")
	}
	if got := send(h, "GET", "/wp-login.php", "203.0.113.32:1", nil).Code; got != 403 {
		t.Errorf("detection stopped working after a rejected edit, got %d", got)
	}
}

func TestRuleEditPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	configure := func(c *Config) {
		c.Store.Backend = "file"
		c.Store.Path = path
	}

	h, _ := consoleHandler(t, configure)
	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.Detectors.Honeypots.Enabled = true
	edit.Detectors.Honeypots.Paths = []string{"/persisted-trap"}
	edit.DryRun = true
	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", rec.Code, rec.Body.String())
	}

	// Drop the process-global runtime and rebuild from the same state file.
	resetRuntime(t.Name())
	h2, rt2 := consoleHandler(t, configure)

	s := rt2.settings()
	if !s.dryRun {
		t.Error("the saved dryRun setting was not restored")
	}
	if _, ok := s.honeyPaths["/persisted-trap"]; !ok {
		t.Error("the saved honeypot was not restored")
	}
	after := fetchRules(t, h2)
	owned, _ := after["overridden"].([]interface{})
	if len(owned) == 0 {
		t.Error("the restored rules are not reported as console-managed")
	}
}

// A Traefik configuration reload rebuilds every middleware. Console edits must
// be re-layered onto the new file configuration rather than silently discarded.
func TestRuleEditSurvivesConfigReload(t *testing.T) {
	h, _ := consoleHandler(t, nil)

	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.Detectors.Honeypots.Enabled = true
	edit.Detectors.Honeypots.Paths = []string{"/survives-reload"}
	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", rec.Code, rec.Body.String())
	}

	// Traefik rebuilds the middleware with a changed file configuration.
	cfg := CreateConfig()
	cfg.InstanceName = t.Name()
	cfg.Admin.Enabled = true
	cfg.Admin.Token = ruleToken
	cfg.Enforcement.RejectStatus = 404
	h2, err := New(context.Background(), okBackend(), cfg, "scanguard@test")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	// The file's new reject status is in force...
	if got := send(h2, "GET", "/survives-reload", "203.0.113.33:1", nil).Code; got != 404 {
		t.Errorf("the reloaded file configuration did not apply, got %d", got)
	}
	// ...and so is the console's honeypot, which is what made that request a hit.
	rec := send(h2, "GET", "/", "203.0.113.33:1", nil)
	if rec.Code != 404 {
		t.Errorf("the console honeypot was lost across the reload, got %d", rec.Code)
	}
}

func TestRevertRestoresFileConfiguration(t *testing.T) {
	h, rt := consoleHandler(t, nil)

	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.Detectors.Signatures.Enabled = false
	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d", rec.Code)
	}
	if got := send(h, "GET", "/wp-login.php", "203.0.113.34:1", nil).Code; got != 200 {
		t.Fatalf("signatures should be disabled, got %d", got)
	}

	if rec := ruleRequest(t, h, http.MethodDelete, nil); rec.Code != http.StatusOK {
		t.Fatalf("DELETE returned %d: %s", rec.Code, rec.Body.String())
	}
	if !rt.overrides.empty() {
		t.Error("overrides were not cleared")
	}
	if got := send(h, "GET", "/wp-login.php", "203.0.113.35:1", nil).Code; got != 403 {
		t.Fatalf("the file configuration was not restored, got %d", got)
	}
}

// The console and the detector are separate middleware definitions sharing one
// runtime. A rule edit must not take the console's own authentication with it.
func TestRuleEditPreservesAdminSettings(t *testing.T) {
	h, rt := consoleHandler(t, nil)

	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.DryRun = true
	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d", rec.Code)
	}

	s := rt.settings()
	if !s.adminEnabled || s.adminToken != ruleToken {
		t.Fatal("the admin surface was lost when rules were saved; the console would have locked itself out")
	}
	if rec := ruleRequest(t, h, http.MethodGet, nil); rec.Code != http.StatusOK {
		t.Fatalf("the console is no longer reachable after saving rules: %d", rec.Code)
	}
}

func TestReadOnlyRefusesRuleEdits(t *testing.T) {
	h, _ := consoleHandler(t, func(c *Config) { c.Admin.ReadOnly = true })

	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.DryRun = true

	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only mode returned %d for a rule write, want 403", rec.Code)
	}
	if rec := ruleRequest(t, h, http.MethodDelete, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("read-only mode returned %d for a revert, want 403", rec.Code)
	}
	if rec := ruleRequest(t, h, http.MethodGet, nil); rec.Code != http.StatusOK {
		t.Errorf("read-only mode must still allow reading, got %d", rec.Code)
	}
}

// A rule write must not be able to reach the settings the console is not allowed
// to touch — the ones holding secrets, or the ones that must agree with Traefik's
// static configuration.
func TestRuleEditCannotReachProtectedSettings(t *testing.T) {
	h, rt := consoleHandler(t, func(c *Config) {
		c.ClientIP.TrustedProxies = []string{"10.0.0.0/8"}
		c.ClientIP.Header = "Cf-Connecting-Ip"
		c.Notify.AbuseIPDB.Enabled = true
		c.Notify.AbuseIPDB.APIKey = "secret-key-value"
	})

	// Fields outside the editable set are rejected outright rather than ignored,
	// so nobody can believe they changed something they did not.
	req := httptest.NewRequest(http.MethodPut, "/__scanguard/api/rules",
		strings.NewReader(`{"dryRun":true,"clientIP":{"trustedProxies":["0.0.0.0/0"]}}`))
	req.RemoteAddr = "203.0.113.36:1"
	req.Header.Set("X-Scanguard-Token", ruleToken)
	req.Header.Set("X-Scanguard-Action", "1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a submission naming a protected section returned %d, want 400", rec.Code)
	}

	s := rt.settings()
	if len(s.trustedProxies) != 1 || s.trustedProxies[0].String() != "10.0.0.0/8" {
		t.Errorf("trustedProxies changed to %v", s.trustedProxies)
	}
	if s.clientIPHeader != "Cf-Connecting-Ip" {
		t.Errorf("the client-IP header changed to %q", s.clientIPHeader)
	}

	// And the secrets never appear in what the console can read.
	body := fetchRules(t, h)
	buf, _ := json.Marshal(body)
	if strings.Contains(string(buf), "secret-key-value") {
		t.Error("the AbuseIPDB key leaked through the rules endpoint")
	}
}

// The tarpit semaphore is sized from configuration, and a channel cannot be
// resized in place. Changing the cap from the console must not lose the limit.
func TestTarpitCapacityFollowsRuleEdits(t *testing.T) {
	h, rt := consoleHandler(t, nil)

	if sem, _ := rt.tarpitSem.Load().(chan struct{}); sem == nil || cap(sem) != 50 {
		t.Fatalf("initial tarpit capacity is wrong: %v", sem)
	}

	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.Enforcement.Tarpit.Enabled = true
	edit.Enforcement.Tarpit.MaxConcurrent = 7
	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", rec.Code, rec.Body.String())
	}

	sem, _ := rt.tarpitSem.Load().(chan struct{})
	if sem == nil || cap(sem) != 7 {
		t.Fatalf("tarpit capacity did not follow the edit, got %v", sem)
	}
}

// Persisted state that a newer build rejects must never stop Traefik starting.
// The operator would have no console left to fix it from.
func TestUnusableSavedRulesAreIgnoredNotFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	broken := `{"version":1,"bans":[],"overrides":{"updated":"2026-01-01T00:00:00Z",` +
		`"detectors":{"signatures":{"enabled":true,"patterns":["([unclosed"]}}}}`
	if err := writeFile(path, broken); err != nil {
		t.Fatal(err)
	}

	h, rt := consoleHandler(t, func(c *Config) {
		c.Store.Backend = "file"
		c.Store.Path = path
	})

	if rt.settings() == nil {
		t.Fatal("the middleware failed to start because of unusable saved rules")
	}
	// The file configuration is in force, so detection still works.
	if got := send(h, "GET", "/wp-login.php", "203.0.113.37:1", nil).Code; got != 403 {
		t.Fatalf("the file configuration did not take over, got %d", got)
	}
	if !rt.overrides.empty() {
		t.Error("unusable overrides were adopted anyway")
	}
}

// Traefik builds middleware in map-iteration order, so on any given startup the
// console instance may be constructed BEFORE the detector. That order used to
// lose every saved rule edit: restoring one requires re-validating it against the
// file configuration, which only the detector supplies, and nothing retried once
// it arrived. It failed on roughly half of all restarts, and only CI's version
// matrix — three runners, three coin flips — made it visible.
func TestSavedRulesRestoreWhenConsoleIsBuiltFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	instance := t.Name()

	detectorCfg := func() *Config {
		c := CreateConfig()
		c.InstanceName = instance
		c.Store.Backend = "file"
		c.Store.Path = path
		return c
	}
	consoleCfg := func() *Config {
		c := CreateConfig()
		c.InstanceName = instance
		c.UIMode = true
		c.Admin.Enabled = true
		c.Admin.Token = ruleToken
		c.Store.Backend = "file"
		c.Store.Path = path
		return c
	}

	// Save a rule edit the ordinary way.
	h, err := New(context.Background(), okBackend(), detectorCfg(), "detector@test")
	if err != nil {
		t.Fatalf("New detector: %v", err)
	}
	if _, err = New(context.Background(), okBackend(), consoleCfg(), "console@test"); err != nil {
		t.Fatalf("New console: %v", err)
	}
	rules := fetchRules(t, h)
	edit := editableOf(t, rules, "effective")
	edit.Detectors.Honeypots.Enabled = true
	edit.Detectors.Honeypots.Paths = []string{"/order-trap"}
	if rec := ruleRequest(t, h, http.MethodPut, edit); rec.Code != http.StatusOK {
		t.Fatalf("PUT returned %d: %s", rec.Code, rec.Body.String())
	}

	// Restart, and this time let Traefik build the CONSOLE first.
	resetRuntime(instance)
	if _, err = New(context.Background(), okBackend(), consoleCfg(), "console@test"); err != nil {
		t.Fatalf("New console after restart: %v", err)
	}
	h2, err := New(context.Background(), okBackend(), detectorCfg(), "detector@test")
	if err != nil {
		t.Fatalf("New detector after restart: %v", err)
	}

	registryMu.Lock()
	rt := registry[instance]
	registryMu.Unlock()

	if rt.overrides.empty() {
		t.Fatal("saved rule edits were lost because the console was constructed first")
	}
	if _, ok := rt.settings().honeyPaths["/order-trap"]; !ok {
		t.Fatal("the restored honeypot is not in the effective settings")
	}
	if got := send(h2, "GET", "/order-trap", "203.0.113.90:1", nil).Code; got != 403 {
		t.Fatalf("the restored honeypot does not block, got %d", got)
	}
}
