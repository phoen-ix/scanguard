package scanguard

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// okBackend answers 200 for everything except /missing/*, which 404s, and /login,
// which 401s — enough to drive the response-status detectors.
func okBackend() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasPrefix(req.URL.Path, "/missing/"):
			rw.WriteHeader(http.StatusNotFound)
		case req.URL.Path == "/login":
			rw.WriteHeader(http.StatusUnauthorized)
		default:
			rw.Header().Set("X-Backend", "reached")
			_, _ = rw.Write([]byte("ok"))
		}
	})
}

func build(t *testing.T, mutate func(*Config)) http.Handler {
	t.Helper()
	cfg := CreateConfig()
	// Every test gets its own instance name, because runtime state is a
	// process-global registry keyed by exactly that.
	cfg.InstanceName = t.Name()
	if mutate != nil {
		mutate(cfg)
	}
	h, err := New(context.Background(), okBackend(), cfg, "scanguard@test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func send(h http.Handler, method, target, remote string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = remote
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSignatureProbeIsBlockedAndSourceBanned(t *testing.T) {
	h := build(t, nil)

	if got := send(h, "GET", "/wp-login.php", "203.0.113.1:1", nil).Code; got != 403 {
		t.Fatalf("probe returned %d, want 403", got)
	}
	if got := send(h, "GET", "/", "203.0.113.1:1", nil).Code; got != 403 {
		t.Fatalf("the banned source returned %d on an innocent path, want 403", got)
	}
	if got := send(h, "GET", "/", "203.0.113.2:1", nil).Code; got != 200 {
		t.Fatalf("an unrelated source returned %d, want 200", got)
	}
}

func TestDryRunDetectsButNeverBlocks(t *testing.T) {
	h := build(t, func(c *Config) { c.DryRun = true })

	rec := send(h, "GET", "/wp-login.php", "203.0.113.3:1", nil)
	if rec.Code == 403 {
		t.Fatal("dry run must never block")
	}
	if rec.Header().Get("X-Backend") != "reached" {
		t.Error("dry run must still forward the request to the backend")
	}
	// A subsequent request must also pass: nothing was written to the ban list.
	if got := send(h, "GET", "/", "203.0.113.3:1", nil).Code; got != 200 {
		t.Fatalf("dry run recorded a real ban, got %d", got)
	}
}

func TestRejectStatusIsConfigurable(t *testing.T) {
	h := build(t, func(c *Config) { c.Enforcement.RejectStatus = 404 })

	if got := send(h, "GET", "/wp-login.php", "203.0.113.4:1", nil).Code; got != 404 {
		t.Fatalf("got %d, want the configured 404 (which hides the middleware)", got)
	}
}

func TestDisabledAndKillSwitch(t *testing.T) {
	h := build(t, func(c *Config) { c.Enabled = false })
	if got := send(h, "GET", "/wp-login.php", "203.0.113.5:1", nil).Code; got != 200 {
		t.Fatalf("a disabled middleware returned %d, want a pass-through", got)
	}

	t.Setenv(disableEnv, "1")
	h = build(t, nil)
	if got := send(h, "GET", "/wp-login.php", "203.0.113.6:1", nil).Code; got != 200 {
		t.Fatalf("the kill switch returned %d, want a pass-through", got)
	}
}

func TestResponseStatusDetectorBansOneRequestLate(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Detectors.Signatures.Enabled = false
		c.Detectors.BadPaths.Capacity = 3
		c.Detectors.BadPaths.Leak = "60s"
		c.Detectors.BadPaths.Statuses = []int{404}
	})

	// The third distinct 404 trips the bucket, but that response is already on its
	// way to the client: enforcement necessarily starts with the NEXT request.
	for i := 0; i < 3; i++ {
		send(h, "GET", fmt.Sprintf("/missing/%d", i), "203.0.113.7:1", nil)
	}
	if got := send(h, "GET", "/", "203.0.113.7:1", nil).Code; got != 403 {
		t.Fatalf("got %d after a 404 flood, want 403", got)
	}
}

// The wrapper must not be applied to protocol upgrades, or WebSocket handshakes
// lose access to http.Hijacker.
func TestUpgradeRequestsBypassTheWrapper(t *testing.T) {
	if !isUpgrade(request("1.2.3.4:1", map[string]string{"Upgrade": "websocket"})) {
		t.Error("an Upgrade header must be detected")
	}
	if !isUpgrade(request("1.2.3.4:1", map[string]string{"Connection": "keep-alive, Upgrade"})) {
		t.Error("Upgrade inside a Connection header must be detected")
	}
	if isUpgrade(request("1.2.3.4:1", nil)) {
		t.Error("an ordinary request must not look like an upgrade")
	}
}

// fullWriter implements everything a real Traefik ResponseWriter does, so the
// wrapper's delegation can be checked.
type fullWriter struct {
	*httptest.ResponseRecorder
	flushed  bool
	hijacked bool
	readFrom bool
}

func (w *fullWriter) Flush() { w.flushed = true }

func (w *fullWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return nil, nil, nil
}

func (w *fullWriter) ReadFrom(r io.Reader) (int64, error) {
	w.readFrom = true
	return io.Copy(w.ResponseRecorder, r)
}

// This is the single most important regression test in the package. A wrapper
// that drops these interfaces silently breaks WebSockets, Server-Sent Events and
// gRPC streaming on every route the middleware touches — traefik#10269 — and the
// failure surfaces weeks later as "the chat app stopped working".
func TestResponseObserverPreservesStreamingInterfaces(t *testing.T) {
	inner := &fullWriter{ResponseRecorder: httptest.NewRecorder()}
	obs := newResponseObserver(inner, "test")

	if _, ok := interface{}(obs).(http.Flusher); !ok {
		t.Fatal("the wrapper does not implement http.Flusher")
	}
	if _, ok := interface{}(obs).(http.Hijacker); !ok {
		t.Fatal("the wrapper does not implement http.Hijacker")
	}
	if _, ok := interface{}(obs).(io.ReaderFrom); !ok {
		t.Fatal("the wrapper does not implement io.ReaderFrom")
	}

	obs.Flush()
	if !inner.flushed {
		t.Error("Flush was not forwarded to the underlying writer")
	}
	if _, _, err := obs.Hijack(); err != nil {
		t.Errorf("Hijack was not forwarded: %v", err)
	}
	if !inner.hijacked {
		t.Error("Hijack did not reach the underlying writer")
	}
	if _, err := obs.ReadFrom(strings.NewReader("body")); err != nil {
		t.Errorf("ReadFrom: %v", err)
	}
	if !inner.readFrom {
		t.Error("ReadFrom did not reach the underlying writer, losing the sendfile path")
	}
	if obs.Unwrap() != http.ResponseWriter(inner) {
		t.Error("Unwrap must expose the original writer")
	}
}

func TestResponseObserverCapturesStatus(t *testing.T) {
	rec := httptest.NewRecorder()
	obs := newResponseObserver(rec, "test")
	obs.WriteHeader(404)
	obs.WriteHeader(500) // a second call must not overwrite the first
	if obs.status != 404 {
		t.Errorf("status = %d, want 404", obs.status)
	}

	rec = httptest.NewRecorder()
	obs = newResponseObserver(rec, "test")
	_, _ = obs.Write([]byte("implicit 200"))
	if obs.status != 200 {
		t.Errorf("an implicit write must record 200, got %d", obs.status)
	}
}

func TestAllowlistedSourceSurvivesAnObviousProbe(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Allowlist.CIDRs = []string{"203.0.113.0/24"}
	})

	if got := send(h, "GET", "/wp-login.php", "203.0.113.8:1", nil).Code; got != 200 {
		t.Fatalf("an allowlisted source got %d, want 200", got)
	}
}

func TestAdminSurface(t *testing.T) {
	const token = "test-token-0123456789"
	h := build(t, func(c *Config) {
		c.Admin.Enabled = true
		c.Admin.Token = token
	})

	auth := map[string]string{"X-Scanguard-Token": token}

	if got := send(h, "GET", "/__scanguard/api/health", "203.0.113.9:1", nil).Code; got != 401 {
		t.Errorf("unauthenticated request got %d, want 401", got)
	}
	if got := send(h, "GET", "/__scanguard/api/health", "203.0.113.9:1",
		map[string]string{"X-Scanguard-Token": "wrong-token-0123456"}).Code; got != 401 {
		t.Errorf("a wrong token got %d, want 401", got)
	}
	if got := send(h, "GET", "/__scanguard/api/health", "203.0.113.9:1", auth).Code; got != 200 {
		t.Errorf("the correct token got %d, want 200", got)
	}
	if got := send(h, "GET", "/__scanguard/api/state", "203.0.113.9:1", auth).Code; got != 200 {
		t.Errorf("state endpoint got %d, want 200", got)
	}

	// Bearer credentials are accepted as an alternative to the custom header.
	if got := send(h, "GET", "/__scanguard/api/health", "203.0.113.9:1",
		map[string]string{"Authorization": "Bearer " + token}).Code; got != 200 {
		t.Errorf("a bearer token got %d, want 200", got)
	}

	// Mutations need the custom action header, which no cross-origin form can set.
	if got := send(h, "DELETE", "/__scanguard/api/bans?key=1.2.3.4", "203.0.113.9:1", auth).Code; got != 403 {
		t.Errorf("a mutation without the action header got %d, want 403", got)
	}

	withAction := map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"}
	if got := send(h, "DELETE", "/__scanguard/api/bans?key=1.2.3.4", "203.0.113.9:1", withAction).Code; got != 200 {
		t.Errorf("a mutation with the action header got %d, want 200", got)
	}

	// The console page and its assets must be non-empty. An empty body here is
	// exactly how //go:embed fails under Yaegi.
	for _, path := range []string{"/__scanguard/", "/__scanguard/app.css", "/__scanguard/app.js"} {
		rec := send(h, "GET", path, "203.0.113.9:1", auth)
		if rec.Code != 200 || rec.Body.Len() < 1000 {
			t.Errorf("%s returned %d with %d bytes", path, rec.Code, rec.Body.Len())
		}
	}

	// Secrets must never appear in what the console is served.
	state := send(h, "GET", "/__scanguard/api/state", "203.0.113.9:1", auth).Body.String()
	if strings.Contains(state, token) {
		t.Error("the admin token leaked into the state response")
	}
}

func TestAdminReadOnlyRefusesMutations(t *testing.T) {
	const token = "test-token-0123456789"
	h := build(t, func(c *Config) {
		c.Admin.Enabled = true
		c.Admin.Token = token
		c.Admin.ReadOnly = true
	})

	rec := send(h, "DELETE", "/__scanguard/api/bans?key=1.2.3.4", "203.0.113.10:1",
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	if rec.Code != 403 {
		t.Fatalf("read-only mode returned %d for a mutation, want 403", rec.Code)
	}
}

// Refusing to ban an allowlisted or trusted address protects the operator from a
// single mistyped click taking their own site down.
func TestManualBanRefusesProtectedAddresses(t *testing.T) {
	const token = "test-token-0123456789"
	h := build(t, func(c *Config) {
		c.Admin.Enabled = true
		c.Admin.Token = token
		c.Allowlist.CIDRs = []string{"198.51.100.0/24"}
		c.ClientIP.TrustedProxies = []string{"10.0.0.0/8"}
	})

	hdr := map[string]string{
		"X-Scanguard-Token":  token,
		"X-Scanguard-Action": "1",
		"Content-Type":       "application/json",
	}
	for _, target := range []string{"198.51.100.5", "10.1.2.3"} {
		req := httptest.NewRequest("POST", "/__scanguard/api/bans",
			strings.NewReader(fmt.Sprintf(`{"key":%q,"duration":"1h"}`, target)))
		req.RemoteAddr = "203.0.113.11:1"
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Errorf("banning the protected address %s returned %d, want 409", target, rec.Code)
		}
	}
}

func TestUIModeNeverCallsNext(t *testing.T) {
	const token = "test-token-0123456789"
	h := build(t, func(c *Config) {
		c.UIMode = true
		c.Admin.Token = token
	})

	rec := send(h, "GET", "/anything/at/all", "203.0.113.12:1",
		map[string]string{"X-Scanguard-Token": token})
	if rec.Header().Get("X-Backend") == "reached" {
		t.Fatal("a uiMode instance must never forward to the backend")
	}
	if rec.Code != 404 {
		t.Errorf("an unknown console path returned %d, want 404", rec.Code)
	}

	rec = send(h, "GET", "/", "203.0.113.12:1", map[string]string{"X-Scanguard-Token": token})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<title>scanguard</title>") {
		t.Error("a uiMode instance must serve the console at its router root")
	}
}

// sendCancelled issues a request whose context is already dead, so any tarpit
// releases immediately. Used to set up a ban without paying the delay.
func sendCancelled(h http.Handler, target, remote string) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest("GET", target, nil).WithContext(ctx)
	req.RemoteAddr = remote
	h.ServeHTTP(httptest.NewRecorder(), req)
}

func TestTarpitDelaysRejectedRequests(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Enforcement.Tarpit.Enabled = true
		c.Enforcement.Tarpit.Delay = "300ms"
		c.Enforcement.Tarpit.MaxConcurrent = 4
	})

	sendCancelled(h, "/wp-login.php", "203.0.113.13:1")

	start := time.Now()
	rec := send(h, "GET", "/", "203.0.113.13:1", nil)
	elapsed := time.Since(start)

	if rec.Code != 403 {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	if elapsed < 250*time.Millisecond {
		t.Errorf("the rejection took %v, want roughly the configured 300ms delay", elapsed)
	}
}

// Every tarpitted request pins a goroutine and a socket, so a client that hangs
// up must release both immediately. Without this, a scanner holding a thousand
// connections turns the tarpit into a denial of service against its own host.
func TestTarpitAbortsWhenTheClientDisconnects(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Enforcement.Tarpit.Enabled = true
		c.Enforcement.Tarpit.Delay = "30s"
		c.Enforcement.Tarpit.MaxConcurrent = 1
	})

	sendCancelled(h, "/wp-login.php", "203.0.113.14:1")

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	req.RemoteAddr = "203.0.113.14:1"

	done := make(chan struct{})
	go func() {
		h.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the tarpit did not release when the client disconnected")
	}
}

func TestNewRejectsMissingArguments(t *testing.T) {
	if _, err := New(context.Background(), okBackend(), nil, "x"); err == nil {
		t.Error("a nil configuration must be refused")
	}
	if _, err := New(context.Background(), nil, CreateConfig(), "x"); err == nil {
		t.Error("a nil next handler must be refused")
	}
}
