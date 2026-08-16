package scanguard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
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
			var m map[string]string
			if err := json.Unmarshal([]byte(body), &m); err != nil || m["content"] == "" {
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

// Under a ban flood, dispatch must drop notifications rather than spawn an
// unbounded number of goroutines inside the reverse proxy.
func TestDispatchIsBoundedNotUnbounded(t *testing.T) {
	release := make(chan struct{})
	var inFlight sync.WaitGroup

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		<-release
		rw.WriteHeader(200)
	}))
	defer srv.Close()

	n := notifierFor(t, func(c *Config) {
		c.Notify.Webhooks = []WebhookConfig{{URL: srv.URL}}
		c.Notify.Timeout = "5s"
	})

	// Far more events than the semaphore allows.
	for i := 0; i < 500; i++ {
		inFlight.Add(1)
		go func() {
			defer inFlight.Done()
			n.dispatch(banEvent())
		}()
	}

	// dispatch itself must return immediately whether or not it queued anything.
	done := make(chan struct{})
	go func() { inFlight.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("dispatch blocked instead of dropping when saturated")
	}

	if n := len(notifySem); n > cap(notifySem) {
		t.Errorf("%d in flight exceeds the cap of %d", n, cap(notifySem))
	}
	close(release)
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
