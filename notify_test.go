package scanguard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Everything in this file exercises code that makes outbound HTTP calls. Those
// calls run in plugin-spawned goroutines, where an unrecovered panic does not
// fail a request — it takes down the entire Traefik process, and with it every
// site behind the proxy. So the delivery paths and the guards around them both
// need to have actually run.

// capture records what a fake endpoint received.
type capture struct {
	mu      sync.Mutex
	calls   int
	method  string
	path    string
	query   url.Values
	headers http.Header
	body    string
}

func (c *capture) handler(status int, reply string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)

		c.mu.Lock()
		c.calls++
		c.method = req.Method
		c.path = req.URL.Path
		c.query = req.URL.Query()
		c.headers = req.Header.Clone()
		c.body = string(body)
		c.mu.Unlock()

		rw.WriteHeader(status)
		_, _ = rw.Write([]byte(reply))
	}
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *capture) snapshot() capture {
	c.mu.Lock()
	defer c.mu.Unlock()
	return capture{calls: c.calls, method: c.method, path: c.path, query: c.query, headers: c.headers, body: c.body}
}

func notifierFor(t *testing.T, mutate func(*Config)) *notifier {
	t.Helper()
	cfg := CreateConfig()
	cfg.InstanceName = t.Name()
	if mutate != nil {
		mutate(cfg)
	}
	s, err := cfg.parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return newNotifier(s)
}

func banEvent() Event {
	return Event{
		Kind:     eventBan,
		Key:      "203.0.113.5/32",
		Client:   "203.0.113.5",
		Detector: detectorSignature,
		Rule:     `/wp-login\.php`,
		Method:   "GET",
		Path:     "/wp-login.php",
		BanFor:   "1h",
		Time:     time.Now().UTC(),
	}
}

func TestWebhookDelivery(t *testing.T) {
	got := &capture{}
	srv := httptest.NewServer(got.handler(200, "ok"))
	defer srv.Close()

	n := notifierFor(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{
			URL:     srv.URL + "/ban",
			Headers: map[string]string{"Authorization": "Bearer hook-secret"},
		}}
	})
	n.send(banEvent())

	snap := got.snapshot()
	if snap.calls != 1 {
		t.Fatalf("webhook was called %d times, want 1", snap.calls)
	}
	if snap.method != http.MethodPost {
		t.Errorf("method = %s, want POST", snap.method)
	}
	if snap.headers.Get("Authorization") != "Bearer hook-secret" {
		t.Error("configured headers were not sent")
	}
	if snap.headers.Get("Content-Type") != "application/json" {
		t.Errorf("content type = %s", snap.headers.Get("Content-Type"))
	}

	// The payload is a documented contract: a firewall helper consumes it.
	var payload struct {
		Source   string `json:"source"`
		Instance string `json:"instance"`
		Event    Event  `json:"event"`
	}
	if err := json.Unmarshal([]byte(snap.body), &payload); err != nil {
		t.Fatalf("payload is not valid JSON: %v (%s)", err, snap.body)
	}
	if payload.Source != "scanguard" {
		t.Errorf("source = %q", payload.Source)
	}
	if payload.Event.Key != "203.0.113.5/32" || payload.Event.Detector != detectorSignature {
		t.Errorf("event did not survive the round trip: %+v", payload.Event)
	}
	if payload.Event.BanFor != "1h" {
		t.Errorf("banFor = %q, want 1h", payload.Event.BanFor)
	}
}

func TestWebhookEventFiltering(t *testing.T) {
	got := &capture{}
	srv := httptest.NewServer(got.handler(200, ""))
	defer srv.Close()

	n := notifierFor(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: srv.URL, Events: []string{"unban"}}}
	})

	n.send(banEvent())
	if got.count() != 0 {
		t.Fatal("a ban was delivered to a webhook subscribed only to unbans")
	}
	n.send(Event{Kind: eventUnban, Key: "203.0.113.5/32", Actor: "token"})
	if got.count() != 1 {
		t.Fatal("the subscribed event was not delivered")
	}

	// An empty filter means bans and unbans, but never the high-volume kinds.
	n2 := notifierFor(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: srv.URL}}
	})
	before := got.count()
	n2.send(Event{Kind: eventReject, Key: "203.0.113.6/32"})
	if got.count() != before {
		t.Error("a per-request reject was delivered; that would flood the endpoint")
	}
}

// A webhook that is down, slow or returning errors must never break anything.
func TestWebhookFailuresAreSurvivable(t *testing.T) {
	errSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
	}))
	defer errSrv.Close()

	n := notifierFor(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{
			{URL: errSrv.URL},
			{URL: "http://127.0.0.1:1"}, // nothing listening
		}
		c.Notify.Timeout = "300ms"
	})

	done := make(chan struct{})
	go func() {
		n.send(banEvent())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a dead webhook stalled the notifier")
	}
}

func TestChatPayloadsPerProvider(t *testing.T) {
	cases := map[string]func(t *testing.T, body string, hdr http.Header){
		"discord": func(t *testing.T, body string, _ http.Header) {
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(body), &m); err != nil || m["content"] == "" || m["content"] == nil {
				t.Errorf("discord payload = %s", body)
			}
		},
		"slack": func(t *testing.T, body string, _ http.Header) {
			var m map[string]string
			if err := json.Unmarshal([]byte(body), &m); err != nil || m["text"] == "" {
				t.Errorf("slack payload = %s", body)
			}
		},
		"gotify": func(t *testing.T, body string, _ http.Header) {
			var m map[string]interface{}
			if err := json.Unmarshal([]byte(body), &m); err != nil || m["message"] == "" || m["title"] == "" {
				t.Errorf("gotify payload = %s", body)
			}
		},
		"ntfy": func(t *testing.T, body string, hdr http.Header) {
			if strings.HasPrefix(body, "{") {
				t.Errorf("ntfy takes a plain-text body, got %s", body)
			}
			if hdr.Get("Content-Type") != "text/plain" {
				t.Errorf("ntfy content type = %s", hdr.Get("Content-Type"))
			}
			if hdr.Get("Title") == "" {
				t.Error("ntfy Title header missing")
			}
		},
	}

	for kind, verify := range cases {
		got := &capture{}
		srv := httptest.NewServer(got.handler(200, ""))

		n := notifierFor(t, func(c *Config) {
			c.Notify.Chat = ChatConfig{Kind: kind, URL: srv.URL}
		})
		n.send(banEvent())

		snap := got.snapshot()
		if snap.calls != 1 {
			t.Errorf("%s: called %d times, want 1", kind, snap.calls)
			srv.Close()
			continue
		}
		if !strings.Contains(snap.body, "203.0.113.5/32") {
			t.Errorf("%s: the banned key is missing from the message: %s", kind, snap.body)
		}
		verify(t, snap.body, snap.headers)
		srv.Close()
	}
}

func TestAbuseIPDBReport(t *testing.T) {
	got := &capture{}
	srv := httptest.NewServer(got.handler(200, `{"data":{"abuseConfidenceScore":100}}`))
	defer srv.Close()

	n := notifierFor(t, func(c *Config) {
		c.Notify.AbuseIPDB = AbuseIPDBConfig{Enabled: true, APIKey: "key-123", Report: true}
	})
	n.abuseBase = srv.URL

	n.send(banEvent())

	snap := got.snapshot()
	if snap.calls != 1 {
		t.Fatalf("report called %d times, want 1", snap.calls)
	}
	if snap.path != "/api/v2/report" {
		t.Errorf("path = %s", snap.path)
	}
	if snap.headers.Get("Key") != "key-123" {
		t.Error("the API key was not sent in the Key header")
	}
	form, err := url.ParseQuery(snap.body)
	if err != nil {
		t.Fatalf("body is not form-encoded: %v", err)
	}
	if form.Get("ip") != "203.0.113.5" {
		t.Errorf("reported ip = %q, want the client address rather than the ban key", form.Get("ip"))
	}
	if form.Get("categories") == "" {
		t.Error("no AbuseIPDB categories were sent")
	}

	// Reporting the same address again immediately is rude and rate-limited.
	n.send(banEvent())
	if got.count() != 1 {
		t.Errorf("the same address was reported %d times; the dedupe window is not working", got.count())
	}

	// A dry-run ban must never be reported: nothing was actually blocked.
	n2 := notifierFor(t, func(c *Config) {
		c.Notify.AbuseIPDB = AbuseIPDBConfig{Enabled: true, APIKey: "key-123", Report: true}
	})
	n2.abuseBase = srv.URL
	dry := banEvent()
	dry.DryRun = true
	dry.Client = "198.51.100.9"
	n2.send(dry)
	if got.count() != 1 {
		t.Error("a dry-run ban was reported to AbuseIPDB")
	}
}

// The reputation check must never block a request: on a cache miss it reports
// "unknown" and fetches in the background.
func TestAbuseIPDBCheckIsAsyncAndCached(t *testing.T) {
	got := &capture{}
	srv := httptest.NewServer(got.handler(200, `{"data":{"abuseConfidenceScore":93}}`))
	defer srv.Close()

	n := notifierFor(t, func(c *Config) {
		c.Notify.AbuseIPDB = AbuseIPDBConfig{
			Enabled: true, APIKey: "key-123", Check: true, MinConfidence: 50, CacheTTL: "1h",
		}
	})
	n.abuseBase = srv.URL

	if _, ok := n.score("203.0.113.5"); ok {
		t.Fatal("a cache miss must report no answer rather than blocking on the API")
	}

	deadline := time.Now().Add(3 * time.Second)
	var score int
	var ok bool
	for time.Now().Before(deadline) {
		if score, ok = n.score("203.0.113.5"); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ok {
		t.Fatal("the background lookup never populated the cache")
	}
	if score != 93 {
		t.Errorf("score = %d, want 93", score)
	}

	calls := got.count()
	for i := 0; i < 5; i++ {
		n.score("203.0.113.5")
	}
	if got.count() != calls {
		t.Errorf("the cache was not used: %d calls became %d", calls, got.count())
	}

	snap := got.snapshot()
	if snap.query.Get("ipAddress") != "203.0.113.5" {
		t.Errorf("ipAddress = %q", snap.query.Get("ipAddress"))
	}
}

func TestGeoLookupIsAsyncAndCached(t *testing.T) {
	got := &capture{}
	srv := httptest.NewServer(got.handler(200, `{"status":"success","countryCode":"NL"}`))
	defer srv.Close()

	s := mustSettings(t, func(c *Config) {
		c.Geo = GeoConfig{Enabled: true, Provider: "ip-api", CacheTTL: "1h"}
	})
	g := newGeoCache(s)
	g.base = srv.URL

	if country := g.lookup("203.0.113.5"); country != "" {
		t.Fatalf("a cache miss returned %q; it must never block a ban decision", country)
	}

	deadline := time.Now().Add(3 * time.Second)
	country := ""
	for time.Now().Before(deadline) {
		if country = g.lookup("203.0.113.5"); country != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if country != "NL" {
		t.Fatalf("country = %q, want NL", country)
	}

	calls := got.count()
	for i := 0; i < 5; i++ {
		g.lookup("203.0.113.5")
	}
	if got.count() != calls {
		t.Errorf("the cache was not used: %d calls became %d", calls, got.count())
	}

	// Expired entries are swept so the cache cannot grow without bound.
	g.ttl = time.Nanosecond
	g.sweep(time.Now())
	if len(g.entries) != 0 {
		t.Error("expired geo entries were not swept")
	}
}

// geo.endpoint and notify.abuseipdb.endpoint reach the clients: a self-hosted
// stand-in, or the fakes the interpreter smoke test uses.
func TestEndpointsAreConfigurable(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.Geo.Endpoint = "http://geo.internal:8080/"
		c.Notify.AbuseIPDB.Endpoint = "https://abuse.internal"
	})
	if g := newGeoCache(s); g.base != "http://geo.internal:8080" {
		t.Errorf("geo base = %q", g.base)
	}
	if n := newNotifier(s); n.abuseBase != "https://abuse.internal" {
		t.Errorf("abuse base = %q", n.abuseBase)
	}
	if d := mustSettings(t, nil); newGeoCache(d).base != ipAPIBase || newNotifier(d).abuseBase != abuseIPDBBase {
		t.Error("the defaults are not the public services")
	}
}

func TestGeoDisabledMakesNoCalls(t *testing.T) {
	got := &capture{}
	srv := httptest.NewServer(got.handler(200, `{"status":"success","countryCode":"NL"}`))
	defer srv.Close()

	s := mustSettings(t, nil) // geo disabled by default
	g := newGeoCache(s)
	g.base = srv.URL

	if country := g.lookup("203.0.113.5"); country != "" {
		t.Errorf("a disabled geo cache returned %q", country)
	}
	time.Sleep(100 * time.Millisecond)
	if got.count() != 0 {
		t.Error("a disabled geo cache still called the API")
	}
}

// drainNotifyQueue waits until every queued delivery has been handed to a
// worker and finished. The queue is package-global, so a test that leaves jobs
// behind would hand them to the next test's expectations.
func drainNotifyQueue(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if notifyPending.Load() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the notification queue did not drain")
}

// Delivery is a bounded queue drained by a fixed pool: a flood never spawns an
// unbounded number of goroutines inside the reverse proxy, dispatch never
// blocks, and nothing that fits the queue is lost. The old check compared
// len(ch) with cap(ch), which no channel can ever fail.
func TestDispatchIsBoundedNotUnbounded(t *testing.T) {
	release := make(chan struct{})
	var inFlight, peak atomic.Int64
	var delivered atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		cur := inFlight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
		delivered.Add(1)
		rw.WriteHeader(200)
	}))
	defer srv.Close()

	n := notifierFor(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: srv.URL}}
		c.Notify.Timeout = "10s"
	})

	const events = 500
	var callers sync.WaitGroup
	for i := 0; i < events; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			n.dispatch(banEvent())
		}()
	}
	done := make(chan struct{})
	go func() { callers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("dispatch blocked instead of queueing")
	}

	// Concurrency is measured where it matters, at the receiver.
	time.Sleep(100 * time.Millisecond)
	if p := peak.Load(); p > notifyWorkers {
		t.Errorf("%d deliveries were in flight at once, want at most %d workers", p, notifyWorkers)
	}
	if n.dropped.Load() != 0 {
		t.Errorf("%d events dropped although %d fit a queue of %d", n.dropped.Load(), events, notifyQueueSize)
	}
	close(release)
	drainNotifyQueue(t)
	if got := delivered.Load(); got != events {
		t.Errorf("%d of %d queued events were delivered", got, events)
	}
}

// Past the queue, events are dropped — counted and logged — rather than
// blocking the caller or growing without bound.
func TestDispatchDropsAndCountsPastTheQueue(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		<-release
		rw.WriteHeader(200)
	}))
	defer srv.Close()
	n := notifierFor(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: srv.URL}}
		c.Notify.Timeout = "10s"
	})

	// The warning is throttled process-wide; start this burst with a fresh window.
	notifyDropWarnMu.Lock()
	notifyDropWarnAt = time.Time{}
	notifyDroppedSince = 0
	notifyDropWarnMu.Unlock()

	total := notifyQueueSize + notifyWorkers + 50
	lines := captureLog(t, func() {
		for i := 0; i < total; i++ {
			n.dispatch(banEvent())
		}
	})
	if n.dropped.Load() == 0 {
		t.Error("nothing was counted as dropped past the queue")
	}
	if n.dropped.Load() > 50+notifyWorkers {
		t.Errorf("%d dropped, want only what did not fit the queue and the workers", n.dropped.Load())
	}
	warned := 0
	for _, l := range lines {
		if strings.Contains(l.Msg, "notification queue is full") {
			warned++
		}
	}
	if warned != 1 {
		t.Errorf("the queue-full warning was logged %d times for one burst, want once (throttled)", warned)
	}
	close(release)
	drainNotifyQueue(t)
}

// The failure the queue exists for: a janitor tick that expires more bans than
// the old semaphore had slots must deliver an unban for every one of them. A
// firewall helper that misses an unban keeps the rule forever.
func TestEveryExpiryOfATickReachesTheWebhook(t *testing.T) {
	var delivered atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		_, _ = io.ReadAll(req.Body)
		delivered.Add(1)
		rw.WriteHeader(200)
	}))
	defer srv.Close()

	build(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: srv.URL, Events: []string{"unban"}}}
	})
	rt := registry[t.Name()]
	const expired = 100
	now := time.Now()
	for i := 0; i < expired; i++ {
		b := Ban{Key: fmt.Sprintf("203.0.%d.%d/32", 100+i/250, i%250), Detector: detectorSignature,
			Created: now.Add(-2 * time.Hour), Expires: now.Add(-time.Minute), Offences: 1}
		if err := rt.store().put(b); err != nil {
			t.Fatal(err)
		}
	}
	rt.tick()
	drainNotifyQueue(t)
	if got := delivered.Load(); got != expired {
		t.Fatalf("%d of %d expiry unbans were delivered", got, expired)
	}
	if rt.stats.NotifyDropped.Load() != 0 {
		t.Errorf("%d events counted as dropped", rt.stats.NotifyDropped.Load())
	}
}

// Crawler-policy and reputation bans are never filed with AbuseIPDB: the first
// reports a commercial crawler as an attacker, the second reports an address
// back to the service whose score banned it.
func TestAbuseIPDBSkipsCrawlerAndReputationBans(t *testing.T) {
	got := &capture{}
	srv := httptest.NewServer(got.handler(200, ""))
	defer srv.Close()
	n := notifierFor(t, func(c *Config) {
		c.Notify.AbuseIPDB = AbuseIPDBConfig{Enabled: true, APIKey: "key-123", Report: true}
	})
	n.abuseBase = srv.URL
	for i, det := range []string{detectorCrawler, detectorReputation, detectorManual} {
		e := banEvent()
		e.Detector = det
		e.Client = fmt.Sprintf("203.0.113.%d", 50+i)
		n.send(e)
	}
	if got.count() != 0 {
		t.Errorf("%d reports were filed for detectors that must not be reported", got.count())
	}
	e := banEvent()
	e.Detector = detectorHoneypot
	n.send(e)
	snap := got.snapshot()
	form, _ := url.ParseQuery(snap.body)
	if snap.calls != 1 || form.Get("categories") != "21" {
		t.Errorf("a honeypot ban was filed as %q (%d calls), want category 21 without Port Scan", form.Get("categories"), snap.calls)
	}
}

// The chat text embeds the attacker's request path. Discord gets a message
// that cannot mention anyone; Slack gets its control characters escaped.
func TestChatMessagesCannotPingTheChannel(t *testing.T) {
	for _, kind := range []string{"discord", "slack"} {
		got := &capture{}
		srv := httptest.NewServer(got.handler(200, ""))
		n := notifierFor(t, func(c *Config) { c.Notify.Chat = ChatConfig{Kind: kind, URL: srv.URL} })
		e := banEvent()
		e.Path = "/@everyone/<!channel>/wp-login.php"
		n.send(e)
		body := got.snapshot().body
		srv.Close()
		switch kind {
		case "discord":
			var m struct {
				Content         string `json:"content"`
				AllowedMentions struct {
					Parse []string `json:"parse"`
				} `json:"allowed_mentions"`
			}
			if err := json.Unmarshal([]byte(body), &m); err != nil || m.AllowedMentions.Parse == nil || len(m.AllowedMentions.Parse) != 0 {
				t.Errorf("discord payload does not disable mentions: %s", body)
			}
		case "slack":
			var m map[string]string
			if err := json.Unmarshal([]byte(body), &m); err != nil {
				t.Fatalf("slack payload: %v", err)
			}
			if strings.Contains(m["text"], "<!channel>") || !strings.Contains(m["text"], "&lt;!channel&gt;") {
				t.Errorf("slack text was not escaped: %s", m["text"])
			}
		}
	}
}

// A chat endpoint answering 4xx is a dead webhook; it is said in the log, and a
// dry-run would-ban is announced as one.
func TestChatFailuresAreLoggedAndDryRunIsLabelled(t *testing.T) {
	got := &capture{}
	srv := httptest.NewServer(got.handler(404, "Unknown Webhook"))
	defer srv.Close()
	n := notifierFor(t, func(c *Config) { c.Notify.Chat = ChatConfig{Kind: "discord", URL: srv.URL} })
	dry := banEvent()
	dry.DryRun = true
	lines := captureLog(t, func() { n.send(dry) })
	if f := fieldsOf(lines, "chat endpoint rejected the notification"); f == nil || f["status"] != float64(404) {
		t.Errorf("a 404 from the chat endpoint was not logged with its status: %v", f)
	}
	if body := got.snapshot().body; !strings.Contains(body, "dry run") || strings.Contains(body, "scanguard banned ") {
		t.Errorf("a dry-run would-ban was announced as a ban: %s", body)
	}
}

// The transport error from a failed delivery embeds the full request URL,
// credential and all; the log line must not.
func TestWebhookFailureLogDoesNotLeakTheURL(t *testing.T) {
	n := notifierFor(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: "http://127.0.0.1:1/api/webhooks/1234/s3cr3t-token"}}
		c.Notify.Timeout = "300ms"
	})
	lines := captureLog(t, func() { n.send(banEvent()) })
	f := fieldsOf(lines, "webhook delivery failed")
	if f == nil {
		t.Fatal("the failed delivery was not logged")
	}
	for k, v := range f {
		if s, _ := v.(string); strings.Contains(s, "s3cr3t") || strings.Contains(s, "/api/webhooks") {
			t.Errorf("log field %s leaks the webhook URL: %s", k, s)
		}
	}
}

// Ban durations are rendered exactly when they are not a whole unit, and the
// ban event carries the expiry itself.
func TestDurationsAreRenderedExactly(t *testing.T) {
	cases := map[time.Duration]string{
		permanent:                    "permanent",
		time.Hour:                    "1h",
		24 * time.Hour:               "1d",
		168 * time.Hour:              "7d",
		90 * time.Minute:             "1h30m",
		36 * time.Hour:               "1d12h",
		90 * time.Second:             "1m30s",
		45 * time.Second:             "45s",
		25*time.Hour + 5*time.Second: "1d1h5s",
	}
	for d, want := range cases {
		if got := formatDuration(d); got != want {
			t.Errorf("formatDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestBanEventsCarryTheExpiry(t *testing.T) {
	h := build(t, func(c *Config) { c.Enforcement.Escalation = []string{"90m", "0"} })
	rt := registry[t.Name()]
	send(h, "GET", "/wp-login.php", "203.0.113.185:1", nil)
	var e Event
	for _, ev := range rt.events.recent(0) {
		if ev.Kind == eventBan {
			e = ev
		}
	}
	if e.BanFor != "1h30m" {
		t.Errorf("banFor = %q, want 1h30m", e.BanFor)
	}
	if e.Expires == nil || e.Expires.Sub(e.Time) < 89*time.Minute || e.Expires.Sub(e.Time) > 91*time.Minute {
		t.Errorf("expires = %v for a 90m ban issued at %v", e.Expires, e.Time)
	}
	buf, _ := json.Marshal(e)
	if !strings.Contains(string(buf), "\"expires\":\"") {
		t.Errorf("the event JSON has no expires field: %s", buf)
	}
}

// A panic in a plugin-spawned goroutine is not recovered by Traefik and kills the
// whole process. Every such goroutine defers recoverPanic; this proves it holds.
func TestRecoverPanicContainsTheDamage(t *testing.T) {
	survived := make(chan bool, 1)

	go func() {
		defer func() {
			// If recoverPanic did not catch it, this second recover does, and the
			// test reports the failure instead of taking the test binary down.
			if r := recover(); r != nil {
				survived <- false
				return
			}
			survived <- true
		}()
		defer recoverPanic("test", "deliberate")
		panic("simulated failure inside a background goroutine")
	}()

	select {
	case ok := <-survived:
		if !ok {
			t.Fatal("recoverPanic did not contain the panic; in production this kills Traefik")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the goroutine never returned")
	}

	// Nil and error panics must be handled too, not just strings.
	for _, v := range []interface{}{nil, io.EOF, 42, struct{ A int }{1}} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("recoverPanic escaped for %v", v)
				}
			}()
			defer recoverPanic("test", "value")
			panic(v)
		}()
	}
}

func TestNotifierDisabledDoesNothing(t *testing.T) {
	n := notifierFor(t, nil)
	if n.enabled() {
		t.Fatal("a notifier with nothing configured reports itself enabled")
	}
	n.dispatch(banEvent()) // must not panic or block
}

// An unban by expiry is an unban. The janitor used to record it straight into
// the event ring, so a webhook consumer that adds a firewall rule on "ban" never
// got the "unban" that takes it out again; only manual unbans were delivered.
func TestExpiredBansAreReportedToNotifiers(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		mu.Lock()
		bodies = append(bodies, string(body))
		mu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	h := build(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: srv.URL + "/ban"}}
	})
	_ = h
	rt := registry[t.Name()]

	now := time.Now()
	expired := Ban{Key: "203.0.113.180/32", Detector: detectorSignature, Rule: "/wp-login\\.php",
		Created: now.Add(-2 * time.Hour), Expires: now.Add(-time.Minute), Offences: 1}
	if err := rt.store().put(expired); err != nil {
		t.Fatalf("put: %v", err)
	}
	shadow := expired
	shadow.Key = "203.0.113.181/32"
	if err := rt.shadow.put(shadow); err != nil {
		t.Fatalf("shadow put: %v", err)
	}

	rt.tick()

	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(bodies)
		mu.Unlock()
		if n >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("the janitor's sweep produced %d webhook deliveries, want 2 (the real and the shadow expiry)", len(bodies))
	}
	seen := map[string]Event{}
	for _, body := range bodies {
		var payload struct {
			Event Event `json:"event"`
		}
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("payload is not valid JSON: %v (%s)", err, body)
		}
		seen[payload.Event.Key] = payload.Event
	}
	real, ok := seen["203.0.113.180/32"]
	if !ok || real.Kind != eventUnban || real.Actor != "expiry" || real.DryRun {
		t.Errorf("the expired ban's unban did not arrive as kind=unban actor=expiry: %+v", real)
	}
	dry, ok := seen["203.0.113.181/32"]
	if !ok || dry.Kind != eventUnban || dry.Actor != "expiry" || !dry.DryRun {
		t.Errorf("the expired shadow ban's unban did not arrive with dryRun set: %+v", dry)
	}
}
