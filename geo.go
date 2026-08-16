package scanguard

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// geoCache annotates addresses with a country code for the admin UI.
//
// Display only, and never on the request path. GeoIP databases are out of reach
// here — the MaxMind reader libraries rely on memory-mapped files and reflection
// that do not survive the Yaegi interpreter — so this asks a small HTTP API and
// caches the answer for a week. A lookup failure must never influence a ban
// decision; the worst case is a blank column in the UI.
type geoCache struct {
	enabled  bool
	provider string
	ttl      time.Duration
	instance string
	client   *http.Client

	mu       sync.Mutex
	entries  map[string]geoEntry
	inflight map[string]struct{}
}

type geoEntry struct {
	country string
	fetched time.Time
}

// geoInflightMax bounds concurrent lookups. The free ip-api endpoint rate-limits
// at 45 requests a minute, and hammering it past that gets the whole host banned
// from the service.
const geoInflightMax = 4

func newGeoCache(s *settings) *geoCache {
	return &geoCache{
		enabled:  s.geoEnabled,
		provider: s.geoProvider,
		ttl:      s.geoCacheTTL,
		instance: s.instanceName,
		client:   &http.Client{Timeout: 3 * time.Second},
		entries:  make(map[string]geoEntry),
		inflight: make(map[string]struct{}),
	}
}

// lookup returns a cached country code, scheduling a background fetch on a miss.
// It returns an empty string until the answer is available.
func (g *geoCache) lookup(ip string) string {
	if g == nil || !g.enabled || ip == "" {
		return ""
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if entry, ok := g.entries[ip]; ok && time.Since(entry.fetched) < g.ttl {
		return entry.country
	}
	if _, busy := g.inflight[ip]; busy || len(g.inflight) >= geoInflightMax {
		return ""
	}
	g.inflight[ip] = struct{}{}

	go func() {
		defer recoverPanic(g.instance, "geo lookup")
		g.fetch(ip)
	}()
	return ""
}

func (g *geoCache) fetch(ip string) {
	defer func() {
		g.mu.Lock()
		delete(g.inflight, ip)
		g.mu.Unlock()
	}()

	endpoint := "http://ip-api.com/json/" + url.PathEscape(ip) + "?fields=status,countryCode"
	resp, err := g.client.Get(endpoint)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var payload struct {
		Status      string `json:"status"`
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return
	}
	if payload.Status != "success" {
		return
	}

	g.mu.Lock()
	g.entries[ip] = geoEntry{country: payload.CountryCode, fetched: time.Now()}
	g.mu.Unlock()
}

// sweep drops expired entries so the cache cannot grow without bound.
func (g *geoCache) sweep(now time.Time) {
	if g == nil {
		return
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	for ip, entry := range g.entries {
		if now.Sub(entry.fetched) > g.ttl {
			delete(g.entries, ip)
		}
	}
	if len(g.entries) > 50000 {
		g.entries = make(map[string]geoEntry)
	}
}
