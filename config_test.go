package scanguard

import (
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigIsValid(t *testing.T) {
	if _, err := CreateConfig().parse(); err != nil {
		t.Fatalf("the default configuration must be valid: %v", err)
	}
}

func TestManifestTestDataShape(t *testing.T) {
	// The plugin catalog EXECUTES the testData block in .traefik.yml when
	// validating a submission, so a configuration matching it has to work.
	cfg := CreateConfig()
	cfg.InstanceName = "catalog-test"
	cfg.DryRun = true
	cfg.Store.Backend = "memory"
	cfg.Detectors.Honeypots.Paths = []string{"/.git/config"}
	cfg.Enforcement.Escalation = []string{"1h", "24h", "168h"}

	if _, err := cfg.parse(); err != nil {
		t.Fatalf("the manifest testData configuration must parse: %v", err)
	}
}

// Rejecting this at startup is a security control, not tidiness: honouring a
// client-IP header from an unverified peer is a remote "ban anyone" primitive.
func TestClientIPHeaderRequiresTrustedProxies(t *testing.T) {
	cfg := CreateConfig()
	cfg.ClientIP.Header = "Cf-Connecting-Ip"

	_, err := cfg.parse()
	if err == nil {
		t.Fatal("a client-IP header with no trusted proxies must be refused")
	}
	if !strings.Contains(err.Error(), "trustedProxies") {
		t.Errorf("the error should name the missing setting, got: %v", err)
	}
}

func TestAdminRequiresAuthentication(t *testing.T) {
	cfg := CreateConfig()
	cfg.Admin.Enabled = true

	if _, err := cfg.parse(); err == nil {
		t.Fatal("an admin console with neither a token nor SSO must be refused")
	}

	cfg.Admin.Token = "short"
	if _, err := cfg.parse(); err == nil {
		t.Fatal("a short admin token must be refused")
	}

	cfg.Admin.Token = "long-enough-token-here"
	if _, err := cfg.parse(); err != nil {
		t.Fatalf("a sufficient token must be accepted: %v", err)
	}

	cfg.Admin.Token = ""
	cfg.Admin.TrustForwardedUser = true
	if _, err := cfg.parse(); err != nil {
		t.Fatalf("upstream SSO must be accepted as authentication: %v", err)
	}
}

func TestUIModeImpliesAdmin(t *testing.T) {
	cfg := CreateConfig()
	cfg.UIMode = true
	if _, err := cfg.parse(); err == nil {
		t.Fatal("uiMode without a token must be refused, since it enables the console")
	}

	cfg.Admin.Token = "long-enough-token-here"
	s, err := cfg.parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !s.adminEnabled {
		t.Error("uiMode must enable the admin surface")
	}
}

func TestInvalidValuesAreRejected(t *testing.T) {
	cases := map[string]func(*Config){
		"bad regular expression": func(c *Config) {
			c.Detectors.Signatures.Patterns = []string{"([unclosed"}
		},
		"bad CIDR": func(c *Config) {
			c.Allowlist.CIDRs = []string{"999.1.1.1/24"}
		},
		"bad duration": func(c *Config) {
			c.Enforcement.Decay = "one fortnight"
		},
		"bad status code": func(c *Config) {
			c.Enforcement.RejectStatus = 9000
		},
		"unknown store backend": func(c *Config) {
			c.Store.Backend = "postgres"
		},
		"file backend with no path": func(c *Config) {
			c.Store.Backend = "file"
			c.Store.Path = ""
		},
		"redis backend with no address": func(c *Config) {
			c.Store.Backend = "redis"
		},
		"honeypot path without a leading slash": func(c *Config) {
			c.Detectors.Honeypots.Paths = []string{"admin.php"}
		},
		"ipv4 prefix out of range": func(c *Config) {
			c.ClientIP.IPv4Prefix = 40
		},
		"webhook with no URL": func(c *Config) {
			c.Notify.Webhooks = []WebhookConfig{{}}
		},
		"webhook with a non-http URL": func(c *Config) {
			c.Notify.Webhooks = []WebhookConfig{{URL: "ftp://example.com"}}
		},
		"unknown chat kind": func(c *Config) {
			c.Notify.Chat.Kind = "telepathy"
			c.Notify.Chat.URL = "https://example.com"
		},
		"abuseipdb without a key": func(c *Config) {
			c.Notify.AbuseIPDB.Enabled = true
		},
	}

	for name, mutate := range cases {
		cfg := CreateConfig()
		mutate(cfg)
		if _, err := cfg.parse(); err == nil {
			t.Errorf("%s: expected the configuration to be refused", name)
		}
	}
}

func TestParseDurationAcceptsPermanent(t *testing.T) {
	for _, raw := range []string{"0", "never", "permanent", "forever", "PERMANENT"} {
		got, err := parseDuration("test", raw, time.Hour)
		if err != nil {
			t.Errorf("%q: %v", raw, err)
			continue
		}
		if got != permanent {
			t.Errorf("%q = %v, want permanent", raw, got)
		}
	}

	if got, _ := parseDuration("test", "", 42*time.Second); got != 42*time.Second {
		t.Errorf("an empty duration must fall back to the default, got %v", got)
	}
	if _, err := parseDuration("test", "-5m", 0); err == nil {
		t.Error("a negative duration must be refused")
	}
}

func TestParsePrefixesAcceptsBareAddresses(t *testing.T) {
	got, err := parsePrefixes("test", []string{"10.0.0.0/8", "1.2.3.4", "2001:db8::1", ""})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"10.0.0.0/8", "1.2.3.4/32", "2001:db8::1/128"}
	if len(got) != len(want) {
		t.Fatalf("got %d prefixes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("prefix %d = %s, want %s", i, got[i], want[i])
		}
	}
}

// needsResponse decides whether the ResponseWriter is wrapped at all, which is
// what keeps the Flusher/Hijacker risk off routes that do not need it.
func TestNeedsResponseTracksDetectors(t *testing.T) {
	cfg := CreateConfig()
	cfg.Detectors.BadPaths.Enabled = false
	cfg.Detectors.BruteForce.Enabled = false
	s, err := cfg.parse()
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.needsResponse {
		t.Error("with no response-status detector enabled, the writer must not be wrapped")
	}

	cfg.Detectors.BadPaths.Enabled = true
	if s, _ = cfg.parse(); !s.needsResponse {
		t.Error("badPaths requires response observation")
	}
}

func TestDefaultRulesCompile(t *testing.T) {
	s := mustSettings(t, nil)

	if s.sigMatcher.size() < 30 {
		t.Errorf("only %d default signatures compiled", s.sigMatcher.size())
	}
	if s.uaMatcher.size() < 15 {
		t.Errorf("only %d default user-agent patterns compiled", s.uaMatcher.size())
	}

	// Spot-check that the defaults actually catch what they claim to.
	for _, path := range []string{
		"/wp-login.php", "/.env", "/.git/config", "/phpmyadmin/",
		"/vendor/phpunit/phpunit/src/util/php/eval-stdin.php", "/actuator/env",
	} {
		if !s.sigMatcher.match(path) {
			t.Errorf("default signatures do not match %s", path)
		}
	}
	// ...and that they do not catch ordinary traffic.
	for _, path := range []string{
		"/", "/index.html", "/api/v1/users", "/static/app.css",
		"/admin", "/login", "/health", "/.well-known/acme-challenge/xyz",
	} {
		if s.sigMatcher.match(path) {
			t.Errorf("default signatures falsely match %s — that is a self-inflicted outage", path)
		}
	}
}

func TestDefaultUserAgentsAvoidLegitimateClients(t *testing.T) {
	s := mustSettings(t, nil)

	for _, ua := range []string{"nikto/2.5", "sqlmap/1.7#stable", "Nuclei - Open-source project"} {
		if !s.uaMatcher.match(ua) {
			t.Errorf("default user-agents do not match %q", ua)
		}
	}
	// Generic HTTP clients are used overwhelmingly by legitimate automation.
	for _, ua := range []string{
		"curl/8.5.0", "python-requests/2.31", "Go-http-client/1.1", "Wget/1.21",
		"Mozilla/5.0 (Macintosh) Safari/605.1", "UptimeRobot/2.0",
	} {
		if s.uaMatcher.match(ua) {
			t.Errorf("default user-agents falsely match %q", ua)
		}
	}
}
