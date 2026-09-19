package scanguard

// Regression tests from the 2026-09 audit. Each test names the defect it pins
// down; the comments in the code under test carry the full story.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// The janitor used to sweep a source's ladder record on idleness alone, and a
// banned source is idle by construction — it never reaches the counters. On a
// live deployment 86 of 87 sources that came back after a 24h ban came back at
// offence 1.
func TestLadderSurvivesTheJanitorWhileBanned(t *testing.T) {
	c := newCounters(100)
	key := netip.MustParsePrefix("203.0.113.61/32")
	const decay = 24 * time.Hour
	ladder := func(offence int) time.Duration {
		switch offence {
		case 1:
			return time.Hour
		case 2:
			return 24 * time.Hour
		case 3:
			return 168 * time.Hour
		}
		return 720 * time.Hour
	}
	// tick() derives idle as max(decay, 1h), which is decay here.
	tick := func(at time.Time) { c.sweep(at, decay, decay) }

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if got, _ := c.recordOffence(key, now, decay, ladder); got != 1 {
		t.Fatalf("first offence recorded as %d, want 1", got)
	}
	now = now.Add(2 * time.Hour)
	if got, _ := c.recordOffence(key, now, decay, ladder); got != 2 {
		t.Fatalf("second offence recorded as %d, want 2", got)
	}

	// The janitor runs throughout the 24h ban and for an hour after it. Before
	// the fix the record was gone at the first tick past 24h of idleness — the
	// very moment the ban expired.
	for h := 1; h <= 25; h++ {
		tick(now.Add(time.Duration(h) * time.Hour))
	}
	now = now.Add(25 * time.Hour)
	if got, _ := c.recordOffence(key, now, decay, ladder); got != 3 {
		t.Fatalf("came back at rung %d after a 24h ban, want 3 — the janitor swept the ladder", got)
	}

	// Rung 3 is a 7-day ban. Ticks throughout it, and for a day after release,
	// must keep the record: the ladder still has three rungs to decay.
	for h := 1; h <= 168+24; h++ {
		tick(now.Add(time.Duration(h) * time.Hour))
	}
	if got := c.offences(key); got != 3 {
		t.Fatalf("ladder position is %d after a 7-day ban, want 3", got)
	}

	// Three rungs times one decay period after release the ladder is empty, so
	// the record may go on the ordinary idle rule.
	tick(now.Add(168*time.Hour + 3*decay + time.Minute))
	if got := c.offences(key); got != 0 {
		t.Errorf("record kept a ladder position of %d after it had fully decayed", got)
	}

	// Pure bucket state still goes once idle.
	other := netip.MustParsePrefix("203.0.113.62/32")
	c.noteBadPath(other, "/x", now, 20, time.Minute)
	tick(now.Add(25 * time.Hour))
	if c.size() != 0 {
		t.Errorf("%d records left after every source went idle, want 0", c.size())
	}

	// With decay disabled a ladder position is meant to be kept, and it is.
	if got, _ := c.recordOffence(key, now, 0, ladder); got != 1 {
		t.Fatalf("offence after a clean slate recorded as %d, want 1", got)
	}
	c.sweep(now.Add(400*24*time.Hour), time.Hour, 0)
	if got := c.offences(key); got != 1 {
		t.Errorf("decay is off but the sweep dropped the ladder (position %d)", got)
	}
}

// The burst guard keys off banUntil, and a permanent rung used to leave the
// previous rung's expiry there — already in the past — so every request in the
// burst counted as a fresh offence.
func TestPermanentRungKeepsTheBurstGuard(t *testing.T) {
	c := newCounters(10)
	key := netip.MustParsePrefix("203.0.113.63/32")
	perm := func(int) time.Duration { return permanent }
	now := time.Now()

	if got, fresh := c.recordOffence(key, now, 0, perm); got != 1 || !fresh {
		t.Fatalf("first offence: got %d fresh=%v", got, fresh)
	}
	if got, fresh := c.recordOffence(key, now.Add(time.Millisecond), 0, perm); fresh || got != 1 {
		t.Errorf("a second request in the same burst counted as offence %d (fresh=%v)", got, fresh)
	}
}

func TestABurstAtThePermanentRungIsOneBan(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Detectors.Signatures.Enabled = true
		c.Detectors.Signatures.UseDefaults = true
		c.Enforcement.Escalation = []string{"0"}
	})
	rt := registry[t.Name()]

	const conns = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			send(h, "GET", fmt.Sprintf("/wp-admin/%d.php", i), "203.0.113.151:1", nil)
		}(i)
	}
	close(start)
	wg.Wait()

	bans := rt.store().list(time.Now())
	if len(bans) != 1 {
		t.Fatalf("a %d-connection burst produced %d ban records, want 1", conns, len(bans))
	}
	if bans[0].Offences != 1 {
		t.Errorf("a first-time offender reached offence %d in one burst", bans[0].Offences)
	}
	if !bans[0].Permanent() {
		t.Errorf("the only rung is permanent, but the ban expires at %v", bans[0].Expires)
	}
	var banEvents int
	for _, e := range rt.events.recent(0) {
		if e.Kind == eventBan {
			banEvents++
		}
	}
	if banEvents != 1 {
		t.Errorf("a %d-connection burst emitted %d ban events, want 1", conns, banEvents)
	}
}

// seedLadder ran only when the runtime was created. When Traefik built the
// console first — memory store, no store block of its own, exactly as the README
// shows it — the file store arrived later on the backend-swap path, and every
// persisted offence count was silently dropped.
func TestLadderIsSeededWhenTheConsoleIsBuiltFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	instance := t.Name()
	defer resetRuntime(instance)

	created := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	expires := time.Now().Add(6 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	snap := fmt.Sprintf(`{"version":1,"bans":[{"key":"203.0.113.9/32","detector":"signature",`+
		`"rule":"/wp-login\\.php","created":%q,"expires":%q,"offences":3}]}`, created, expires)
	if err := writeFile(path, snap); err != nil {
		t.Fatal(err)
	}

	consoleCfg := CreateConfig()
	consoleCfg.InstanceName = instance
	consoleCfg.UIMode = true
	consoleCfg.Admin.Enabled = true
	consoleCfg.Admin.Token = ruleToken

	detectorCfg := CreateConfig()
	detectorCfg.InstanceName = instance
	detectorCfg.Store.Backend = "file"
	detectorCfg.Store.Path = path

	if _, err := New(context.Background(), okBackend(), consoleCfg, "console@test"); err != nil {
		t.Fatalf("New console: %v", err)
	}
	if _, err := New(context.Background(), okBackend(), detectorCfg, "detector@test"); err != nil {
		t.Fatalf("New detector: %v", err)
	}

	registryMu.Lock()
	rt := registry[instance]
	registryMu.Unlock()
	if got := rt.counters.offences(netip.MustParsePrefix("203.0.113.9/32")); got != 3 {
		t.Fatalf("persisted offence count restored as %d, want 3", got)
	}
}

// One ring for every kind meant a banned scanner hammering at 7 requests a
// second pushed every ban out of the console within a minute.
func TestBanEventsSurviveARejectFlood(t *testing.T) {
	l := newEventLog(10)
	for i := 0; i < 5; i++ {
		l.add(Event{Kind: eventBan, Key: fmt.Sprintf("203.0.113.%d/32", i)})
	}
	for i := 0; i < 1000; i++ {
		l.add(Event{Kind: eventReject, Key: "203.0.113.1/32"})
	}

	bans := l.sinceKind(0, 500, eventBan)
	if len(bans) != 5 {
		t.Fatalf("the ban filter returned %d events after a reject flood, want 5", len(bans))
	}
	if bans[0].Seq != 1 || bans[4].Seq != 5 {
		t.Errorf("ban events are not oldest-first: seq %d..%d", bans[0].Seq, bans[4].Seq)
	}
	if all := l.recent(0); len(all) != 10 || all[0].Kind != eventReject {
		t.Errorf("the unfiltered ring should hold the 10 newest rejects, got %d events", len(all))
	}
	if got := l.sinceKind(bans[4].Seq, 0, eventBan); len(got) != 0 {
		t.Errorf("polling from the newest ban returned %d events, want 0", len(got))
	}
	l.add(Event{Kind: eventUnban, Key: "203.0.113.1/32"})
	if got := l.sinceKind(0, 0, eventUnban); len(got) != 1 {
		t.Errorf("unbans share the ban ring; filter returned %d, want 1", len(got))
	}
	if got := l.since(0, 0); len(got) != 10 {
		t.Errorf("unfiltered since returned %d, want the ring size 10", len(got))
	}
}

// url.QueryUnescape refuses the whole query at the first malformed escape, which
// switched the decoded scan off with three characters.
func TestPayloadDecodedScanSurvivesAMalformedEscape(t *testing.T) {
	if got := unescapeLenient("a%20b+c%zz%2"); got != "a b c%zz%2" {
		t.Errorf("unescapeLenient = %q", got)
	}
	if got := unescapeLenient("plain"); got != "plain" {
		t.Errorf("unescapeLenient(plain) = %q", got)
	}

	h := build(t, func(c *Config) {
		c.Detectors.Payload.Enabled = true
		c.Detectors.Payload.UseDefaults = true
		c.Detectors.Payload.ScanQuery = true
	})
	rec := send(h, "GET", "/search?z=%zz&id=1%20UNION%20SELECT%20pw%20FROM%20users", "203.0.113.77:1", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a malformed escape elsewhere in the query bypassed the payload detector: %d", rec.Code)
	}
}

// X-Forwarded-For was walked line by line, first line first, returning on the
// first untrusted address — so a duplicate header the client sent beat the
// proxy's; and an unparseable entry was skipped, moving toward the client's.
func TestForwardedChainIsWalkedFromTheFarEnd(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.ClientIP.TrustedProxies = []string{"10.0.0.0/8"}
	})

	dup := httptest.NewRequest(http.MethodGet, "/", nil)
	dup.RemoteAddr = "10.0.0.5:1234"
	dup.Header.Add(headerXFF, "9.9.9.9")
	dup.Header.Add(headerXFF, "203.0.113.77")
	if res := s.resolve(dup); res.client.String() != "203.0.113.77" {
		t.Errorf("duplicate header lines: client = %s, want the proxy's line 203.0.113.77", res.client)
	}

	port := request("10.0.0.5:1234", map[string]string{headerXFF: "9.9.9.9, 203.0.113.77:54321"})
	if res := s.resolve(port); res.client.String() != "203.0.113.77" {
		t.Errorf("ip:port entry: client = %s, want 203.0.113.77", res.client)
	}

	v6 := request("10.0.0.5:1234", map[string]string{headerXFF: "9.9.9.9, [2001:db8::1]:443"})
	if res := s.resolve(v6); res.client.String() != "2001:db8::1" {
		t.Errorf("bracketed IPv6 entry: client = %s, want 2001:db8::1", res.client)
	}

	garbage := request("10.0.0.5:1234", map[string]string{headerXFF: "9.9.9.9, not-an-address"})
	res := s.resolve(garbage)
	if res.bannable || res.client.String() == "9.9.9.9" {
		t.Errorf("an unreadable entry must stop the walk, got client=%s bannable=%v source=%s",
			res.client, res.bannable, res.source)
	}

	empty := request("10.0.0.5:1234", map[string]string{headerXFF: "203.0.113.77, "})
	if res := s.resolve(empty); res.client.String() != "203.0.113.77" {
		t.Errorf("a trailing empty entry is noise, not a stop: client = %s", res.client)
	}
}

// The manual-ban guard tested only the range's network address, so 0.0.0.0/0
// was accepted — and a permanent one refused every IPv4 client on earth.
func TestManualBanRefusesRangesThatSwallowProtectedAddresses(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Admin.Enabled = true
		c.Admin.Token = ruleToken
		c.Allowlist.CIDRs = []string{"198.51.100.0/24"}
		c.ClientIP.TrustedProxies = []string{"10.0.0.0/8"}
	})
	post := func(key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/__scanguard/api/bans",
			strings.NewReader(fmt.Sprintf(`{"key":%q,"duration":"0"}`, key)))
		req.RemoteAddr = "203.0.113.11:1"
		req.Header.Set(headerToken, ruleToken)
		req.Header.Set(headerAction, "1")
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	for key, want := range map[string]int{
		"0.0.0.0/0":       http.StatusBadRequest,
		"::/0":            http.StatusBadRequest,
		"1.2.3.4/4":       http.StatusBadRequest,
		"10.0.0.0/8":      http.StatusConflict, // overlaps the trusted proxy
		"10.20.0.0/16":    http.StatusConflict,
		"198.51.0.0/16":   http.StatusConflict, // swallows the allowlist
		"198.51.100.7/32": http.StatusConflict,
	} {
		if rec := post(key); rec.Code != want {
			t.Errorf("banning %s returned %d, want %d: %s", key, rec.Code, want, rec.Body.String())
		}
	}
	if rec := post("203.0.113.0/24"); rec.Code >= 300 {
		t.Errorf("an ordinary range ban returned %d: %s", rec.Code, rec.Body.String())
	}
	// And nothing dangerous was recorded along the way.
	if rec := send(h, "GET", "/", "8.8.8.8:1", nil); rec.Code != http.StatusOK {
		t.Errorf("an unrelated client is refused (%d): a wide ban slipped through", rec.Code)
	}
}

// An empty escalation entry parsed as "0", and "0" is permanent.
func TestEmptyEscalationEntryIsRejected(t *testing.T) {
	cfg := CreateConfig()
	cfg.InstanceName = t.Name()
	cfg.Enforcement.Escalation = []string{"1h", "", "24h"}
	if _, err := cfg.parse(); err == nil {
		t.Fatal(`escalation ["1h", "", "24h"] parsed cleanly; the empty rung used to mean permanent`)
	}
}

// The "Rejected" tile counted requests a dry run had passed to the backend.
func TestDryRunDoesNotCountRejections(t *testing.T) {
	h := build(t, func(c *Config) {
		c.DryRun = true
		c.Detectors.Signatures.Enabled = true
		c.Detectors.Signatures.UseDefaults = true
	})
	rt := registry[t.Name()]

	if rec := send(h, "GET", "/wp-login.php", "203.0.113.50:1", nil); rec.Code != http.StatusOK {
		t.Fatalf("dry run blocked a request: %d", rec.Code)
	}
	if rec := send(h, "GET", "/anything", "203.0.113.50:1", nil); rec.Code != http.StatusOK {
		t.Fatalf("dry run blocked a shadow-banned source: %d", rec.Code)
	}
	if got := rt.stats.Rejected.Load(); got != 0 {
		t.Errorf("a dry run counted %d rejections; it rejected nothing", got)
	}
	var rejects int
	for _, e := range rt.events.recent(0) {
		if e.Kind == eventReject && e.DryRun {
			rejects++
		}
	}
	if rejects != 1 {
		t.Errorf("the shadow-ban hit should still be recorded as a dry-run reject event, got %d", rejects)
	}
}

// admin.pathPrefix "/admin" captured "/administrator" on every protected route.
func TestAdminPrefixNeedsAPathBoundary(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Admin.Enabled = true
		c.Admin.Token = ruleToken
		c.Admin.PathPrefix = "/admin"
	})
	if rec := send(h, "GET", "/administrator", "203.0.113.51:1", nil); rec.Header().Get("X-Backend") != "reached" {
		t.Errorf("/administrator was swallowed by the admin prefix: %d", rec.Code)
	}
	if rec := send(h, "GET", "/admin/api/health", "203.0.113.51:1", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("/admin/api/health without a token returned %d, want 401", rec.Code)
	}
	if rec := send(h, "GET", "/admin", "203.0.113.51:1", nil); !strings.Contains(rec.Body.String(), "gate-form") {
		t.Errorf("the bare prefix no longer serves the console: %d", rec.Code)
	}
}

func TestWhichReportsTheMatchingPatternFromThePrecompiledList(t *testing.T) {
	m, err := newMatcher("test", []string{`/wp-login\.php`, `/xmlrpc\.php`})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.each) != 2 {
		t.Fatalf("%d compiled patterns, want 2", len(m.each))
	}
	if got := m.which("/XMLRPC.php"); got != `/xmlrpc\.php` {
		t.Errorf("which = %q, want the case-insensitive xmlrpc pattern", got)
	}
	if got := m.which("/index.html"); got != "" {
		t.Errorf("which matched %q for a clean path", got)
	}
}

// The Redis refresh emptied the table and refilled it in two critical sections,
// serving every banned source in between; and it returned early on an empty
// keyspace, so the last unban never propagated.
func TestReplaceAllSwapsTheTableAndHonoursAnEmptyList(t *testing.T) {
	m := newMemStore(10)
	key := netip.MustParsePrefix("203.0.113.12/32")
	if err := m.put(ban("203.0.113.12/32", time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	m.countHit(key)
	m.countHit(key)
	before, ok := m.get(key, time.Now())
	if !ok {
		t.Fatal("ban not found after put")
	}

	if n := m.replaceAll([]Ban{ban("203.0.113.12/32", time.Now().Add(time.Hour))}, time.Now()); n != 1 {
		t.Fatalf("replaceAll kept %d bans, want 1", n)
	}
	after, ok := m.get(key, time.Now())
	if !ok {
		t.Fatal("ban lost across a refresh")
	}
	if after.Hits != before.Hits {
		t.Errorf("local hit count %d was reset to %d by a refresh", before.Hits, after.Hits)
	}

	if n := m.replaceAll(nil, time.Now()); n != 0 {
		t.Fatalf("replaceAll(nil) kept %d bans, want 0", n)
	}
	if _, ok := m.get(key, time.Now()); ok {
		t.Error("an emptied shared keyspace left a stale ban enforced")
	}
}

func TestWebhookURLsAreRedactedInLogs(t *testing.T) {
	if got := redactURL("https://discord.com/api/webhooks/1234/s3cr3t-token"); got != "https://discord.com/…" {
		t.Errorf("redactURL = %q", got)
	}
	if got := redactURL("::not a url"); got != "(unparseable url)" {
		t.Errorf("redactURL(garbage) = %q", got)
	}
}

// A failed reputation lookup cached nothing, so once AbuseIPDB answered 429 every
// later request from that address retried, forever.
func TestAbuseIPDBFailuresAreNegativelyCached(t *testing.T) {
	got := &capture{}
	srv := httptest.NewServer(got.handler(http.StatusTooManyRequests, `{"errors":[{"detail":"rate limited"}]}`))
	defer srv.Close()

	n := notifierFor(t, func(c *Config) {
		c.Notify.AbuseIPDB = AbuseIPDBConfig{
			Enabled: true, APIKey: "key-123", Check: true, MinConfidence: 50, CacheTTL: "1h",
		}
	})
	n.abuseBase = srv.URL

	n.score("203.0.113.5")
	deadline := time.Now().Add(3 * time.Second)
	for got.count() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got.count() != 1 {
		t.Fatal("the first lookup was never made")
	}
	for i := 0; i < 20; i++ {
		if _, ok := n.score("203.0.113.5"); ok {
			t.Fatal("a failed lookup must not report a score")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got.count() != 1 {
		t.Errorf("a failed lookup was retried %d times within the failure TTL", got.count()-1)
	}
}

// A saved override set from a build with a different editable schema would layer
// zero values over the file for every field added since. Refused instead.
func TestOverridesFromAnotherSchemaVersionAreIgnored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	legacy := `{"version":1,"bans":[],"overrides":{"updated":"2026-01-01T00:00:00Z",` +
		`"detectors":{"honeypots":{"enabled":true,"paths":["/legacy-trap"]}}}}`
	if err := writeFile(path, legacy); err != nil {
		t.Fatal(err)
	}

	h, rt := consoleHandler(t, func(c *Config) {
		c.Store.Backend = "file"
		c.Store.Path = path
	})
	if !rt.overrides.empty() {
		t.Error("an override set without a schema version was adopted")
	}
	if got := send(h, "GET", "/legacy-trap", "203.0.113.38:1", nil).Code; got == http.StatusForbidden {
		t.Error("a legacy override was applied: its honeypot is live")
	}
	if got := send(h, "GET", "/wp-login.php", "203.0.113.39:1", nil).Code; got != http.StatusForbidden {
		t.Errorf("the file configuration is not in force, got %d", got)
	}
}

// The console's block is the documented place for serveOnDetectionRoutes, but the
// uiMode merge dropped it, so it only worked when the console was built first.
func TestServeOnDetectionRoutesSurvivesDetectorFirstBuildOrder(t *testing.T) {
	instance := t.Name()
	defer resetRuntime(instance)

	detectorCfg := CreateConfig()
	detectorCfg.InstanceName = instance

	consoleCfg := CreateConfig()
	consoleCfg.InstanceName = instance
	consoleCfg.UIMode = true
	consoleCfg.Admin.Enabled = true
	consoleCfg.Admin.Token = ruleToken
	consoleCfg.Admin.ServeOnDetectionRoutes = true

	detector, err := New(context.Background(), okBackend(), detectorCfg, "detector@test")
	if err != nil {
		t.Fatalf("New detector: %v", err)
	}
	if _, err := New(context.Background(), okBackend(), consoleCfg, "console@test"); err != nil {
		t.Fatalf("New console: %v", err)
	}
	if rec := send(detector, "GET", "/__scanguard/", "203.0.113.73:1", nil); !strings.Contains(rec.Body.String(), "gate-form") {
		t.Errorf("serveOnDetectionRoutes declared on the console was lost because the detector was built first (%d)", rec.Code)
	}
}

func TestFailedAdminAuthenticationIsCounted(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Admin.Enabled = true
		c.Admin.Token = ruleToken
	})
	rt := registry[t.Name()]
	for i := 0; i < 3; i++ {
		send(h, "GET", "/__scanguard/api/health", "203.0.113.52:1", map[string]string{headerToken: "wrong-token-0123456789"})
	}
	if got := rt.stats.AuthFailures.Load(); got != 3 {
		t.Errorf("authFailures = %d, want 3", got)
	}
}

// The defaults that were rewritten: the same probes must still match, and the
// ordinary paths that used to be caught must not.
func TestRewrittenDefaultsKeepTheProbesAndDropTheRoutes(t *testing.T) {
	s := mustSettings(t, nil)
	for _, path := range []string{
		"/credentials.json", "/secrets.json", "/.azure/credentials", "/.docker/secrets.json",
		"/credentials", "/id_rsa", "/app/credentials.yml",
		"/backup.zip", "/db.sql", "/www.zip", "/site.tar.gz",
		"/.aws/config", "/.claude/settings.json", "/.anthropic/config.json",
		"/.config/gcloud/credentials.db", "/.config/anthropic/credentials/default.json",
		"/bedrock/config.yaml", "/litellm_config.yaml", "/openai-proxy/config.json",
		"/.git-credentials", "/.bashrc", "/.bash_history", "/.gitlab-ci.yml", "/.travis.yml",
		"/.circleci/config.yml", "/.github/workflows/deploy.yml", "/secrets.env", "/serverless.yml",
		"/filemanager/php/connector.minimal.php", "/SDK/webLanguage",
	} {
		if !s.sigMatcher.match(path) {
			t.Errorf("default signatures do not match %s", path)
		}
	}
	for _, path := range []string{
		"/api/v1/credentials", "/settings/credentials", "/vault/secrets", "/projects/42/secrets",
		"/downloads/site.zip", "/releases/web.zip", "/files/backup.zip",
		"/.well-known/traffic-advice",
		"/profile", "/user/profile", "/config.json", "/ai/config.json",
	} {
		if s.sigMatcher.match(path) {
			t.Errorf("default signatures falsely match %s — that is a self-inflicted outage", path)
		}
	}
}
