package scanguard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func mustSettings(t *testing.T, mutate func(*Config)) *settings {
	t.Helper()
	cfg := CreateConfig()
	if mutate != nil {
		mutate(cfg)
	}
	s, err := cfg.parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}

func request(remoteAddr string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return req
}

func TestResolveDirectPeer(t *testing.T) {
	s := mustSettings(t, nil)

	res := s.resolve(request("203.0.113.5:41234", nil))
	if !res.bannable {
		t.Fatal("a direct peer must be bannable")
	}
	if got := res.client.String(); got != "203.0.113.5" {
		t.Errorf("client = %s, want 203.0.113.5", got)
	}
	if got := res.key.String(); got != "203.0.113.5/32" {
		t.Errorf("key = %s, want 203.0.113.5/32", got)
	}
}

// The security property that matters most: a forwarded header from a peer that is
// not a configured trusted proxy must be ignored completely. Believing it lets an
// attacker both evade their own ban and get arbitrary third parties banned.
func TestResolveIgnoresHeadersFromUntrustedPeer(t *testing.T) {
	s := mustSettings(t, nil)

	res := s.resolve(request("203.0.113.5:41234", map[string]string{
		"X-Forwarded-For": "198.51.100.99",
		"X-Real-Ip":       "198.51.100.99",
	}))
	if got := res.client.String(); got != "203.0.113.5" {
		t.Fatalf("client = %s, want the peer 203.0.113.5 — a spoofed header was believed", got)
	}
}

func TestResolveTrustedProxyUsesConfiguredHeader(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.ClientIP.TrustedProxies = []string{"10.0.0.0/8"}
		c.ClientIP.Header = "Cf-Connecting-Ip"
	})

	res := s.resolve(request("10.1.2.3:5000", map[string]string{
		"Cf-Connecting-Ip": "198.51.100.7",
		"X-Forwarded-For":  "203.0.113.1, 198.51.100.7",
	}))
	if got := res.client.String(); got != "198.51.100.7" {
		t.Errorf("client = %s, want 198.51.100.7", got)
	}
	if res.source != "Cf-Connecting-Ip" {
		t.Errorf("source = %s, want the configured header", res.source)
	}
	if !res.bannable {
		t.Error("a client behind a trusted proxy must be bannable")
	}
}

// X-Forwarded-For is read right to left, skipping hops that are themselves
// trusted, so the rightmost address we cannot vouch for is the one attributed.
func TestResolveWalksForwardedForRightToLeft(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.ClientIP.TrustedProxies = []string{"10.0.0.0/8", "192.168.0.0/16"}
	})

	res := s.resolve(request("10.1.2.3:5000", map[string]string{
		"X-Forwarded-For": "198.51.100.7, 203.0.113.4, 192.168.1.1",
	}))
	if got := res.client.String(); got != "203.0.113.4" {
		t.Errorf("client = %s, want 203.0.113.4 (rightmost untrusted hop)", got)
	}
}

// When every hop is trusted there is no client we can attribute the request to,
// and banning the proxy itself would take the site down for everyone.
func TestResolveRefusesWhenAllHopsAreTrusted(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.ClientIP.TrustedProxies = []string{"10.0.0.0/8"}
	})

	res := s.resolve(request("10.1.2.3:5000", map[string]string{
		"X-Forwarded-For": "10.4.5.6, 10.7.8.9",
	}))
	if res.bannable {
		t.Fatal("a request attributable only to a trusted proxy must not be bannable")
	}
}

func TestResolveTrustedProxyWithoutHeadersIsNotBannable(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.ClientIP.TrustedProxies = []string{"10.0.0.0/8"}
	})

	res := s.resolve(request("10.1.2.3:5000", nil))
	if res.bannable {
		t.Fatal("a trusted proxy sending no forwarded headers must not be bannable")
	}
}

func TestBanKeyAggregation(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.ClientIP.IPv4Prefix = 24
		c.ClientIP.IPv6Prefix = 64
	})

	cases := []struct {
		remote string
		want   string
	}{
		{"203.0.113.77:1000", "203.0.113.0/24"},
		{"[2001:db8:1:2:3:4:5:6]:1000", "2001:db8:1:2::/64"},
		// An IPv4-mapped IPv6 peer must be treated as IPv4, not banned as a /64.
		{"[::ffff:203.0.113.77]:1000", "203.0.113.0/24"},
	}
	for _, tc := range cases {
		res := s.resolve(request(tc.remote, nil))
		if got := res.key.String(); got != tc.want {
			t.Errorf("%s -> key %s, want %s", tc.remote, got, tc.want)
		}
	}
}

func TestExemptRules(t *testing.T) {
	s := mustSettings(t, func(c *Config) {
		c.Allowlist.CIDRs = []string{"198.51.100.0/24"}
		c.Allowlist.UserAgents = []string{`UptimeRobot`}
		c.Allowlist.Paths = []string{`^/health$`}
	})

	if _, ok := s.exempt(request("198.51.100.9:1", nil), s.resolve(request("198.51.100.9:1", nil))); !ok {
		t.Error("an allowlisted CIDR must be exempt")
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.RemoteAddr = "203.0.113.1:1"
	if _, ok := s.exempt(req, s.resolve(req)); !ok {
		t.Error("an allowlisted path must be exempt")
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:1"
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; UptimeRobot/2.0)")
	if _, ok := s.exempt(req, s.resolve(req)); !ok {
		t.Error("an allowlisted user-agent must be exempt")
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:1"
	if _, ok := s.exempt(req, s.resolve(req)); ok {
		t.Error("ordinary traffic must not be exempt")
	}
}

func TestParsePeerFormats(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4:5678":        "1.2.3.4",
		"[2001:db8::1]:5678":  "2001:db8::1",
		"1.2.3.4":             "1.2.3.4",
		"[fe80::1%25eth0]:80": "fe80::1",
	}
	for in, want := range cases {
		addr, ok := parsePeer(in)
		if !ok {
			t.Errorf("parsePeer(%q) failed", in)
			continue
		}
		if got := addr.String(); got != want {
			t.Errorf("parsePeer(%q) = %s, want %s", in, got, want)
		}
	}
	if _, ok := parsePeer("not-an-address"); ok {
		t.Error("parsePeer must reject nonsense")
	}
}
