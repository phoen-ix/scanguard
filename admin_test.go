package scanguard

// Regression tests from the second audit round, admin API and client IP.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func stateOf(t *testing.T, h http.Handler, path string) StateResponse {
	t.Helper()
	rec := ruleRequestAt(t, h, http.MethodGet, nil, path)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s returned %d: %s", path, rec.Code, rec.Body.String())
	}
	var s StateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	return s
}

// Geo was consulted once, at ban time, on a source seen for the first time, so
// the cache missed and the "" was frozen into the ban. The column is filled
// from the cache when the list is read, so it shows the answer once it lands.
func TestBansGetTheirCountryWhenTheLookupLands(t *testing.T) {
	geo := &capture{}
	srv := httptest.NewServer(geo.handler(200, `{"status":"success","countryCode":"AT"}`))
	defer srv.Close()

	h, rt := consoleHandler(t, func(c *Config) {
		c.Geo = GeoConfig{Enabled: true, Provider: "ip-api", CacheTTL: "1h"}
	})
	rt.geo().base = srv.URL

	if got := send(h, "GET", "/wp-login.php", "203.0.113.200:1", nil).Code; got != 403 {
		t.Fatalf("probe returned %d", got)
	}
	stored, _ := rt.store().get(key("203.0.113.200/32"), time.Now())
	if stored.Country != "" {
		t.Fatalf("the stored ban has country %q before any lookup could have answered", stored.Country)
	}

	deadline := time.Now().Add(3 * time.Second)
	country := ""
	for time.Now().Before(deadline) {
		st := stateOf(t, h, "/__scanguard/api/state")
		if len(st.Bans) == 1 && st.Bans[0].Country != "" {
			country = st.Bans[0].Country
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if country != "AT" {
		t.Fatalf("the ban list never showed the country; last value %q", country)
	}
	rec := ruleRequestAt(t, h, http.MethodGet, nil, "/__scanguard/api/bans")
	var list BanListResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Bans) != 1 || list.Bans[0].Country != "AT" {
		t.Errorf("/api/bans shows %+v, want the country filled", list.Bans)
	}
}

// A ban persisted at an earlier, narrower key width is listed as active and
// matches nothing; the only sensible thing to do with it is remove it, and the
// DELETE used to refuse exactly that. The POST check stands, with a hint that
// points the right way.
func TestNarrowStaleBansCanBeDeleted(t *testing.T) {
	h, rt := consoleHandler(t, func(c *Config) { c.ClientIP.IPv4Prefix = 24 })
	stale := ban("203.0.113.5/32", time.Now().Add(time.Hour))
	if err := rt.store().put(stale); err != nil {
		t.Fatal(err)
	}

	rec := ruleRequestAt(t, h, http.MethodPost, map[string]string{"key": "203.0.113.5/32"}, "/__scanguard/api/bans")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "set clientIP.ipv4Prefix to 32") {
		t.Errorf("POST of a narrow key returned %d %s, want 400 with the hint to set ipv4Prefix to 32", rec.Code, rec.Body.String())
	}
	rec = ruleRequestAt(t, h, http.MethodDelete, nil, "/__scanguard/api/bans?key=203.0.113.5/32")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"unbanned":true`) {
		t.Fatalf("DELETE of the stale narrow key returned %d %s, want it removed", rec.Code, rec.Body.String())
	}
	if n := len(rt.store().list(time.Now())); n != 0 {
		t.Errorf("%d bans left after the delete", n)
	}
}

// The configured client-IP header is read from its LAST value: the proxy sets
// or appends it, so the proxy's value is the last one, and the first was the
// one a client could write. Values in the shapes proxies write are accepted.
func TestConfiguredHeaderIsReadFromTheProxyEnd(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.ClientIP.TrustedProxies = []string{"10.0.0.0/8"}
		c.ClientIP.Header = "X-Client-Ip"
	})
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{"one value", []string{"198.51.100.7"}, "198.51.100.7"},
		{"client line then proxy line", []string{"203.0.113.9", "198.51.100.7"}, "198.51.100.7"},
		{"client value, proxy appended", []string{"203.0.113.9, 198.51.100.7"}, "198.51.100.7"},
		{"ip:port as some proxies write it", []string{"198.51.100.7:4321"}, "198.51.100.7"},
		{"bracketed IPv6", []string{"[2001:db8::7]:443"}, "2001:db8::7"},
		{"trailing comma", []string{"198.51.100.7,"}, "198.51.100.7"},
	}
	for _, tc := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.1.2.3:5000"
		for _, l := range tc.lines {
			req.Header.Add("X-Client-Ip", l)
		}
		res := s.resolve(req)
		if res.client.String() != tc.want || res.source != "X-Client-Ip" || !res.bannable {
			t.Errorf("%s: client=%s source=%s bannable=%v, want %s", tc.name, res.client, res.source, res.bannable, tc.want)
		}
	}

	// An unreadable rightmost value ends the search rather than moving left.
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.1.2.3:5000"
	req.Header.Set("X-Client-Ip", "203.0.113.9, garbage")
	if res := s.resolve(req); res.source == "X-Client-Ip" {
		t.Errorf("an unreadable proxy value let the client's value through: %s", res.client)
	}

	// A configured header that never arrives is said, once.
	lines := captureLog(t, func() {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.1.2.3:5000"
		s.resolve(req)
	})
	found := false
	for _, l := range lines {
		if strings.Contains(l.Msg, "neither clientIP.header") {
			found = true
		}
	}
	if !found {
		t.Error("a configured header that never arrives was not warned about")
	}
}

// Browsers fetch /favicon.ico on every open, without a token. Counted as a
// failed login it made every console open look like a guessing attempt.
func TestFaviconIsNotAFailedLogin(t *testing.T) {
	h, rt := consoleHandler(t, nil)
	if got := send(h, "GET", "/__scanguard/favicon.ico", "203.0.113.201:1", nil).Code; got != http.StatusNotFound {
		t.Errorf("favicon returned %d, want a plain 404", got)
	}
	if n := rt.stats.AuthFailures.Load(); n != 0 {
		t.Errorf("the favicon request counted as %d failed logins", n)
	}
	if !strings.Contains(indexHTML, `rel="icon"`) {
		t.Error("the page declares no icon, so browsers keep asking for /favicon.ico")
	}
}

// The scheme in Authorization is case-insensitive.
func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	h, _ := consoleHandler(t, nil)
	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		rec := send(h, "GET", "/__scanguard/api/health", "203.0.113.202:1", map[string]string{"Authorization": scheme + " " + ruleToken})
		if rec.Code != http.StatusOK {
			t.Errorf("%q scheme returned %d", scheme, rec.Code)
		}
	}
	if !tokenMatches(ruleToken, ruleToken) || tokenMatches(ruleToken+"x", ruleToken) || tokenMatches("", ruleToken) {
		t.Error("tokenMatches does not compare tokens")
	}
}

// In a dry run the would-bans are listed, flagged, and can be lifted. They
// used to be invisible to /api/bans and immune to DELETE.
func TestDryRunBansAreListedAndCanBeLifted(t *testing.T) {
	h, rt := consoleHandler(t, func(c *Config) { c.DryRun = true })
	if got := send(h, "GET", "/wp-login.php", "203.0.113.203:1", nil).Code; got != 200 {
		t.Fatalf("dry run returned %d", got)
	}
	st := stateOf(t, h, "/__scanguard/api/state")
	if len(st.Bans) != 1 || !st.Bans[0].DryRun || st.Bans[0].Key != "203.0.113.203/32" || st.BansTotal != 1 {
		t.Fatalf("state lists %+v (total %d), want the would-ban flagged dryRun", st.Bans, st.BansTotal)
	}
	rec := ruleRequestAt(t, h, http.MethodDelete, nil, "/__scanguard/api/bans?key=203.0.113.203")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"unbanned":true`) {
		t.Fatalf("DELETE of a would-ban returned %d %s", rec.Code, rec.Body.String())
	}
	if _, ok := rt.shadow.get(key("203.0.113.203/32"), time.Now()); ok {
		t.Error("the would-ban is still in the shadow list")
	}
	if n := len(rt.store().list(time.Now())); n != 0 {
		t.Errorf("the real store holds %d bans after a dry run", n)
	}
}

// Behind a trusted proxy the TCP peer is the proxy; the failed-login line
// names the client that was resolved.
func TestFailedLoginLogNamesTheResolvedClient(t *testing.T) {
	h, _ := consoleHandler(t, func(c *Config) { c.ClientIP.TrustedProxies = []string{"10.0.0.0/8"} })
	lines := captureLog(t, func() {
		send(h, "GET", "/__scanguard/api/health", "10.0.0.1:1", map[string]string{
			"X-Forwarded-For":   "203.0.113.77",
			"X-Scanguard-Token": "wrong-token-0123456789",
		})
	})
	f := fieldsOf(lines, "admin authentication failed")
	if f == nil || f["client"] != "203.0.113.77" || f["peer"] != "10.0.0.1" {
		t.Errorf("failed-login line = %v, want client 203.0.113.77 behind peer 10.0.0.1", f)
	}
}
