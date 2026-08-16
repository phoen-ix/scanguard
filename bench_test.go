package scanguard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// These benchmarks measure the compiled hot path. Traefik interprets this plugin
// with Yaegi, so real-world cost is a multiple of what is measured here — which
// is precisely why the numbers matter: whatever is slow compiled is much slower
// interpreted, and interpreted code is effectively unprofilable (every frame
// shows as yaegi/interp.call.func9 in pprof).

// nopWriter is a ResponseWriter that costs nothing, so the benchmarks measure the
// middleware rather than httptest.ResponseRecorder's allocations. It implements
// Flusher and Hijacker too, so the wrapper takes its normal delegating path.
type nopWriter struct{ h http.Header }

func newNopWriter() *nopWriter                   { return &nopWriter{h: make(http.Header)} }
func (w *nopWriter) Header() http.Header         { return w.h }
func (w *nopWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *nopWriter) WriteHeader(int)             {}
func (w *nopWriter) Flush()                      {}

func benchHandler(b *testing.B, mutate func(*Config)) http.Handler {
	b.Helper()
	cfg := CreateConfig()
	cfg.InstanceName = b.Name()
	if mutate != nil {
		mutate(cfg)
	}
	h, err := New(nil, http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte("ok"))
	}), cfg, "bench")
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	return h
}

// The overwhelmingly common case: ordinary traffic that matches nothing. This is
// the number that decides whether the plugin is affordable.
func BenchmarkCleanRequest(b *testing.B) {
	h := benchHandler(b, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/42", nil)
	req.RemoteAddr = "203.0.113.50:1000"
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0")

	rw := newNopWriter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(rw, req)
	}
}

// An already-banned source should be the cheapest path of all: resolve, one map
// lookup, write a status.
func BenchmarkBannedRequest(b *testing.B) {
	h := benchHandler(b, nil)
	probe := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
	probe.RemoteAddr = "203.0.113.51:1000"
	h.ServeHTTP(httptest.NewRecorder(), probe)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.51:1000"

	rw := newNopWriter()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ServeHTTP(rw, req)
	}
}

func BenchmarkSignatureMatcher(b *testing.B) {
	m, err := newMatcher("bench", defaultSignatures)
	if err != nil {
		b.Fatal(err)
	}
	paths := []string{"/", "/api/v1/users/42", "/static/app.9f2c.css", "/wp-login.php"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.match(paths[i%len(paths)])
	}
}

func BenchmarkUserAgentMatcher(b *testing.B) {
	m, err := newMatcher("bench", defaultUserAgents)
	if err != nil {
		b.Fatal(err)
	}
	agents := []string{
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
		"curl/8.5.0",
		"sqlmap/1.7#stable",
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.match(agents[i%len(agents)])
	}
}

func BenchmarkClientIPResolution(b *testing.B) {
	s := mustSettingsB(b, func(c *Config) {
		c.ClientIP.TrustedProxies = []string{
			"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "10.0.0.0/8",
		}
		c.ClientIP.Header = "Cf-Connecting-Ip"
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "173.245.48.7:1000"
	req.Header.Set("Cf-Connecting-Ip", "198.51.100.42")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.resolve(req)
	}
}

func mustSettingsB(b *testing.B, mutate func(*Config)) *settings {
	b.Helper()
	cfg := CreateConfig()
	if mutate != nil {
		mutate(cfg)
	}
	s, err := cfg.parse()
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	return s
}
