package scanguard

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Traefik decodes plugin configuration with mapstructure using WeaklyTypedInput
// and a StringToSliceHookFunc(","). It has no hook for time.Duration, so every
// duration on the wire is a string ("1h", "10s", "0" for "never expires") and is
// parsed into its typed counterpart by (*Config).parse.

// Config is the plugin configuration as it appears in Traefik dynamic configuration.
type Config struct {
	// Enabled turns the whole middleware into a pass-through when false.
	Enabled bool `json:"enabled,omitempty"`
	// InstanceName keys the process-global state. Two middleware definitions sharing
	// an InstanceName share counters and bans; different names are fully isolated.
	InstanceName string `json:"instanceName,omitempty"`
	// DryRun detects and logs but never blocks. Start here when rolling out.
	DryRun bool `json:"dryRun,omitempty"`
	// ObserveResponse wraps the ResponseWriter so response-status detectors
	// (badPaths, bruteForce) can see what the backend returned. Turn this OFF on
	// routes carrying WebSockets, SSE or gRPC streaming.
	ObserveResponse bool `json:"observeResponse,omitempty"`
	// UIMode makes this middleware instance serve ONLY the admin UI. It never calls
	// next, so attach it to a dedicated router pointing at noop@internal.
	UIMode bool `json:"uiMode,omitempty"`

	Store       StoreConfig       `json:"store,omitempty"`
	ClientIP    ClientIPConfig    `json:"clientIP,omitempty"`
	Allowlist   AllowlistConfig   `json:"allowlist,omitempty"`
	Detectors   DetectorsConfig   `json:"detectors,omitempty"`
	Enforcement EnforcementConfig `json:"enforcement,omitempty"`
	Notify      NotifyConfig      `json:"notify,omitempty"`
	Geo         GeoConfig         `json:"geo,omitempty"`
	Admin       AdminConfig       `json:"admin,omitempty"`
}

// StoreConfig selects and configures the state backend.
type StoreConfig struct {
	// Backend is one of "memory", "file" or "redis".
	Backend string `json:"backend,omitempty"`
	// Path is the JSON snapshot location for the "file" backend.
	Path string `json:"path,omitempty"`
	// SnapshotInterval bounds how often the file backend rewrites its snapshot.
	// Counter updates never trigger a write on their own; a 404 flood would
	// otherwise burn IOPS rewriting the file thousands of times a second.
	SnapshotInterval string `json:"snapshotInterval,omitempty"`
	// FailOpen decides what happens when the backend is unreachable. Fail-closed
	// on a Redis blip takes the whole site down, so this defaults to true.
	FailOpen bool `json:"failOpen,omitempty"`
	// MaxEntries hard-caps the tracked-source table. Entries are LRU-evicted past
	// this point: an unbounded per-IP map is a memory-exhaustion vector under a
	// distributed scan, and it is the known bug in the comparable plugins.
	MaxEntries int         `json:"maxEntries,omitempty"`
	Redis      RedisConfig `json:"redis,omitempty"`
}

// RedisConfig configures the shared-state backend used for multi-replica setups.
type RedisConfig struct {
	Address   string `json:"address,omitempty"`
	Password  string `json:"password,omitempty"`
	DB        int    `json:"db,omitempty"`
	KeyPrefix string `json:"keyPrefix,omitempty"`
	Timeout   string `json:"timeout,omitempty"`
}

// ClientIPConfig controls how the true client address is resolved and how wide a
// net a ban casts.
type ClientIPConfig struct {
	// TrustedProxies lists CIDRs whose forwarded headers may be believed. It has
	// NO default on purpose: trusting the wrong peer lets an attacker get third
	// parties banned, and banning a CDN edge takes the site down for everyone.
	TrustedProxies []string `json:"trustedProxies,omitempty"`
	// Header names a single-value client-IP header (e.g. Cf-Connecting-Ip). It is
	// only consulted when the TCP peer is itself in TrustedProxies.
	Header string `json:"header,omitempty"`
	// IPv4Prefix and IPv6Prefix set the ban-key width. A /128 IPv6 ban is close to
	// useless because one host normally owns a whole /64 and rotates freely.
	IPv4Prefix int `json:"ipv4Prefix,omitempty"`
	IPv6Prefix int `json:"ipv6Prefix,omitempty"`
}

// AllowlistConfig names traffic that must never be banned.
type AllowlistConfig struct {
	CIDRs      []string `json:"cidrs,omitempty"`
	UserAgents []string `json:"userAgents,omitempty"`
	Paths      []string `json:"paths,omitempty"`
}

// DetectorsConfig switches individual detection signals on and off.
type DetectorsConfig struct {
	Signatures SignatureConfig  `json:"signatures,omitempty"`
	Honeypots  HoneypotConfig   `json:"honeypots,omitempty"`
	UserAgent  UserAgentConfig  `json:"userAgent,omitempty"`
	BadPaths   BadPathsConfig   `json:"badPaths,omitempty"`
	BruteForce BruteForceConfig `json:"bruteForce,omitempty"`
	RateAbuse  RateAbuseConfig  `json:"rateAbuse,omitempty"`
	Payload    PayloadConfig    `json:"payload,omitempty"`
}

// SignatureConfig matches known-bad request paths before the backend is touched.
type SignatureConfig struct {
	Enabled     bool     `json:"enabled,omitempty"`
	UseDefaults bool     `json:"useDefaults,omitempty"`
	Patterns    []string `json:"patterns,omitempty"`
	Exclude     []string `json:"exclude,omitempty"`
}

// HoneypotConfig lists paths no legitimate client would ever request.
type HoneypotConfig struct {
	Enabled bool     `json:"enabled,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

// UserAgentConfig matches scanner tooling by its User-Agent.
type UserAgentConfig struct {
	Enabled     bool     `json:"enabled,omitempty"`
	UseDefaults bool     `json:"useDefaults,omitempty"`
	Patterns    []string `json:"patterns,omitempty"`
	BanEmptyUA  bool     `json:"banEmptyUA,omitempty"`
}

// BadPathsConfig is a leaky bucket over DISTINCT paths that produced an error
// status. Counting distinct paths rather than raw 404 volume is what stops one
// broken link, hammered by a legitimate client, from banning that client.
type BadPathsConfig struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Capacity int    `json:"capacity,omitempty"`
	Leak     string `json:"leak,omitempty"`
	Statuses []int  `json:"statuses,omitempty"`
}

// BruteForceConfig counts auth failures against real endpoints.
type BruteForceConfig struct {
	Enabled  bool     `json:"enabled,omitempty"`
	Statuses []int    `json:"statuses,omitempty"`
	Paths    []string `json:"paths,omitempty"`
	Capacity int      `json:"capacity,omitempty"`
	Window   string   `json:"window,omitempty"`
}

// RateAbuseConfig bans sources exceeding a request rate regardless of status.
type RateAbuseConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	RPS     int  `json:"rps,omitempty"`
	Burst   int  `json:"burst,omitempty"`
}

// PayloadConfig matches injection probes in the query string and, optionally, the body.
type PayloadConfig struct {
	Enabled      bool     `json:"enabled,omitempty"`
	UseDefaults  bool     `json:"useDefaults,omitempty"`
	Patterns     []string `json:"patterns,omitempty"`
	ScanQuery    bool     `json:"scanQuery,omitempty"`
	ScanBody     bool     `json:"scanBody,omitempty"`
	MaxBodyBytes int      `json:"maxBodyBytes,omitempty"`
}

// EnforcementConfig decides what happens to a source once it is flagged.
type EnforcementConfig struct {
	// RejectStatus is returned to banned sources. 404 hides the middleware's
	// existence from the scanner; 403 is honest.
	RejectStatus int    `json:"rejectStatus,omitempty"`
	RejectBody   string `json:"rejectBody,omitempty"`
	// Escalation is the ban-duration ladder, applied by offence count.
	// A "0" entry means permanent.
	Escalation []string `json:"escalation,omitempty"`
	// Decay is how long a source must behave before its offence count drops.
	Decay  string       `json:"decay,omitempty"`
	Tarpit TarpitConfig `json:"tarpit,omitempty"`
}

// TarpitConfig slows banned clients down instead of rejecting them outright.
// Off by default: every tarpitted request holds a Traefik goroutine and a client
// connection for the whole delay, so an attacker with many connections turns it
// into a self-inflicted denial of service. MaxConcurrent is the safety valve.
type TarpitConfig struct {
	Enabled       bool   `json:"enabled,omitempty"`
	Delay         string `json:"delay,omitempty"`
	MaxConcurrent int    `json:"maxConcurrent,omitempty"`
}

// NotifyConfig pushes ban and unban events outside the plugin.
type NotifyConfig struct {
	Webhooks  []WebhookConfig `json:"webhooks,omitempty"`
	Chat      ChatConfig      `json:"chat,omitempty"`
	AbuseIPDB AbuseIPDBConfig `json:"abuseipdb,omitempty"`
	Timeout   string          `json:"timeout,omitempty"`
}

// WebhookConfig is the generic escape hatch. It is also how OS-firewall
// enforcement works: a privileged helper container consumes these events and
// applies nftables rules, because os/exec does not exist under Yaegi.
type WebhookConfig struct {
	URL     string            `json:"url,omitempty"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Events  []string          `json:"events,omitempty"`
}

// ChatConfig posts human-readable notifications.
type ChatConfig struct {
	// Kind is one of "discord", "slack", "ntfy" or "gotify".
	Kind   string   `json:"kind,omitempty"`
	URL    string   `json:"url,omitempty"`
	Events []string `json:"events,omitempty"`
}

// AbuseIPDBConfig reports offenders to and optionally checks them against AbuseIPDB.
type AbuseIPDBConfig struct {
	Enabled       bool   `json:"enabled,omitempty"`
	APIKey        string `json:"apiKey,omitempty"`
	Report        bool   `json:"report,omitempty"`
	Check         bool   `json:"check,omitempty"`
	MinConfidence int    `json:"minConfidence,omitempty"`
	CacheTTL      string `json:"cacheTTL,omitempty"`
}

// GeoConfig enriches the admin UI with country information. Display only: a
// lookup failure must never influence a ban decision.
type GeoConfig struct {
	Enabled  bool   `json:"enabled,omitempty"`
	Provider string `json:"provider,omitempty"`
	CacheTTL string `json:"cacheTTL,omitempty"`
}

// AdminConfig exposes the web GUI. Disabled by default and shipped with no
// default token: this surface can unban IPs and edit rules from inside the
// reverse proxy, and Traefik gives a plugin-served page no authentication at all.
type AdminConfig struct {
	Enabled bool `json:"enabled,omitempty"`
	// PathPrefix is intercepted on whatever router this middleware is attached to.
	PathPrefix string `json:"pathPrefix,omitempty"`
	// Token is compared in constant time against the X-Scanguard-Token header or
	// a Bearer credential. Required whenever Enabled is true.
	Token string `json:"token,omitempty"`
	// TrustForwardedUser honours X-Forwarded-User from an upstream SSO proxy
	// (Authelia, Authentik, oauth2-proxy) as an alternative to the token.
	TrustForwardedUser bool `json:"trustForwardedUser,omitempty"`
	// ReadOnly serves the dashboard but refuses every mutation.
	ReadOnly bool `json:"readOnly,omitempty"`
	// EventLogSize bounds the in-memory ring buffer backing the live event view.
	EventLogSize int `json:"eventLogSize,omitempty"`
	// ServeOnDetectionRoutes re-enables a behaviour that used to be implicit: every
	// DETECTION middleware sharing this runtime answering the admin surface at
	// PathPrefix on every router it protects, using an admin block it never
	// declared itself. Declare it on the block you actually wrote — normally the
	// uiMode console's.
	//
	// This does not affect prefix mode. A detection middleware that declares its
	// own admin.enabled has asked to serve the console on its router, and still
	// does, whatever this is set to.
	//
	// Leave it false. The console is normally the one thing behind an IP allowlist,
	// and its static assets are served unauthenticated by design; turning this on
	// puts an unguarded copy of that surface on every route the detector protects.
	ServeOnDetectionRoutes bool `json:"serveOnDetectionRoutes,omitempty"`
}

// CreateConfig returns the default plugin configuration. Traefik calls this
// before decoding the user's dynamic configuration over the top, so any field the
// user omits keeps the value set here.
func CreateConfig() *Config {
	return &Config{
		Enabled:         true,
		InstanceName:    "default",
		DryRun:          false,
		ObserveResponse: true,
		Store: StoreConfig{
			Backend:          "memory",
			Path:             "/var/lib/scanguard/state.json",
			SnapshotInterval: "30s",
			FailOpen:         true,
			MaxEntries:       50000,
			Redis: RedisConfig{
				Address:   "",
				KeyPrefix: "scanguard:",
				Timeout:   "2s",
			},
		},
		ClientIP: ClientIPConfig{
			TrustedProxies: []string{},
			Header:         "",
			IPv4Prefix:     32,
			IPv6Prefix:     64,
		},
		Allowlist: AllowlistConfig{
			CIDRs:      []string{},
			UserAgents: []string{},
			Paths:      []string{},
		},
		Detectors: DetectorsConfig{
			Signatures: SignatureConfig{Enabled: true, UseDefaults: true},
			Honeypots:  HoneypotConfig{Enabled: true},
			UserAgent:  UserAgentConfig{Enabled: true, UseDefaults: true, BanEmptyUA: false},
			// Statuses and Escalation are intentionally left empty here: see the
			// note on defaultBadPathStatuses. mapstructure merges into a
			// pre-populated slice rather than replacing it, so a default set at
			// this point would leak into whatever the operator configures.
			BadPaths: BadPathsConfig{
				Enabled:  true,
				Capacity: 10,
				Leak:     "10s",
			},
			BruteForce: BruteForceConfig{
				Enabled:  false,
				Capacity: 5,
				Window:   "60s",
			},
			RateAbuse: RateAbuseConfig{Enabled: false, RPS: 50, Burst: 100},
			Payload: PayloadConfig{
				Enabled:      false,
				UseDefaults:  true,
				ScanQuery:    true,
				ScanBody:     false,
				MaxBodyBytes: 8192,
			},
		},
		Enforcement: EnforcementConfig{
			RejectStatus: 403,
			Decay:        "24h",
			Tarpit: TarpitConfig{
				Enabled:       false,
				Delay:         "3s",
				MaxConcurrent: 50,
			},
		},
		Notify: NotifyConfig{
			Timeout: "5s",
			AbuseIPDB: AbuseIPDBConfig{
				Report:        true,
				Check:         false,
				MinConfidence: 75,
				CacheTTL:      "24h",
			},
		},
		Geo: GeoConfig{
			Enabled:  false,
			Provider: "ip-api",
			CacheTTL: "168h",
		},
		Admin: AdminConfig{
			Enabled:      false,
			PathPrefix:   "/__scanguard",
			EventLogSize: 500,
		},
	}
}

// List defaults live here rather than in CreateConfig, and that is a correctness
// requirement rather than a preference.
//
// Traefik decodes plugin configuration with mapstructure, which merges into a
// slice that already has elements instead of replacing it. Pre-populating
// Enforcement.Escalation with four rungs and then configuring one rung yields the
// operator's value at index 0 followed by three defaults they never asked for —
// silently. So CreateConfig leaves these empty and they are applied afterwards,
// when the decoder can no longer confuse them.
var (
	defaultBadPathStatuses = []int{400, 401, 403, 404, 405, 501}
	defaultBruteStatuses   = []int{401, 403}
	defaultEscalation      = []string{"1h", "24h", "168h", "0"}
)

// normalizeDefaults fills in the list defaults CreateConfig has to leave empty,
// so the console shows what is actually in force rather than a blank field.
func (c *Config) normalizeDefaults() {
	if len(c.Detectors.BadPaths.Statuses) == 0 {
		c.Detectors.BadPaths.Statuses = append([]int{}, defaultBadPathStatuses...)
	}
	if len(c.Detectors.BruteForce.Statuses) == 0 {
		c.Detectors.BruteForce.Statuses = append([]int{}, defaultBruteStatuses...)
	}
	if len(c.Enforcement.Escalation) == 0 {
		c.Enforcement.Escalation = append([]string{}, defaultEscalation...)
	}
}

// permanent is the ban duration meaning "never expires".
const permanent time.Duration = 0

// parseDuration accepts Go duration syntax plus "0", "never" and "permanent",
// all of which mean "does not expire".
func parseDuration(field, raw string, def time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return def, nil
	}
	switch strings.ToLower(raw) {
	case "0", "never", "permanent", "forever":
		return permanent, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a valid duration (want e.g. \"30s\", \"1h\", or \"0\" for permanent)", field, raw)
	}
	if d < 0 {
		return 0, fmt.Errorf("%s: duration must not be negative, got %q", field, raw)
	}
	return d, nil
}

// parsePrefixes turns a CIDR list into netip prefixes. A bare address is accepted
// and treated as a host route, because writing "10.1.2.3" instead of "10.1.2.3/32"
// is the single most common configuration slip here.
func parsePrefixes(field string, raw []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raw))
	for _, entry := range raw {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				return nil, fmt.Errorf("%s: %q is not a valid CIDR: %w", field, entry, err)
			}
			out = append(out, p.Masked())
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is neither a CIDR nor an IP address", field, entry)
		}
		out = append(out, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
	}
	return out, nil
}

// statusSet is a tiny set of HTTP status codes. A map lookup beats a linear scan
// on the request path, and the path is interpreted, so the constant matters.
type statusSet map[int]struct{}

func newStatusSet(codes []int) statusSet {
	s := make(statusSet, len(codes))
	for _, c := range codes {
		s[c] = struct{}{}
	}
	return s
}

func (s statusSet) has(code int) bool {
	_, ok := s[code]
	return ok
}

// settings is the validated, parsed, ready-to-use form of Config. Everything
// expensive — duration parsing, CIDR parsing, regex compilation — happens once
// here in New() so the request path stays cheap.
type settings struct {
	enabled         bool
	instanceName    string
	dryRun          bool
	observeResponse bool
	uiMode          bool

	storeBackend     string
	storePath        string
	snapshotInterval time.Duration
	failOpen         bool
	maxEntries       int
	redis            RedisConfig
	redisTimeout     time.Duration

	trustedProxies []netip.Prefix
	clientIPHeader string
	ipv4Prefix     int
	ipv6Prefix     int

	allowCIDRs []netip.Prefix
	allowUA    *matcher
	allowPaths *matcher

	sigEnabled    bool
	sigMatcher    *matcher
	sigExclude    *matcher
	honeyEnabled  bool
	honeyPaths    map[string]struct{}
	uaEnabled     bool
	uaMatcher     *matcher
	uaBanEmpty    bool
	badPaths      BadPathsConfig
	badPathsLeak  time.Duration
	badPathsCodes statusSet
	brute         BruteForceConfig
	bruteWindow   time.Duration
	bruteCodes    statusSet
	brutePaths    *matcher
	rate          RateAbuseConfig
	payload       PayloadConfig
	payloadMatch  *matcher

	rejectStatus  int
	rejectBody    string
	escalation    []time.Duration
	decay         time.Duration
	tarpitEnabled bool
	tarpitDelay   time.Duration
	tarpitMax     int

	notify        NotifyConfig
	notifyTimeout time.Duration
	abuseCacheTTL time.Duration

	geoEnabled  bool
	geoProvider string
	geoCacheTTL time.Duration

	adminEnabled bool
	// adminServeHere is THIS middleware definition's own answer to "do I serve the
	// admin surface", derived only from the config handed to this New() call. It is
	// copied onto the handler at construction time, for the same reason uiMode is:
	// the shared settings object cannot express a per-middleware decision.
	adminServeHere bool
	// adminServeShared is the runtime-wide opt-in that restores the old implicit
	// behaviour: every detection middleware sharing this runtime also answers the
	// admin prefix, using an admin block it never declared itself. Off by default.
	adminServeShared bool
	adminPrefix      string
	adminToken       string
	adminSSO         bool
	adminReadOnly    bool
	eventLogSize     int

	// needsResponse records whether any enabled detector actually requires the
	// response status. If none does, the ResponseWriter is never wrapped and the
	// Flusher/Hijacker passthrough risk disappears entirely for that route.
	needsResponse bool
}

// parse validates the wire configuration and produces the runtime settings.
// Every error here surfaces at Traefik startup, which is the only place a
// configuration mistake is cheap to notice.
func (c *Config) parse() (*settings, error) {
	if c == nil {
		return nil, errors.New("scanguard: nil configuration")
	}
	s := &settings{
		enabled:         c.Enabled,
		instanceName:    strings.TrimSpace(c.InstanceName),
		dryRun:          c.DryRun,
		observeResponse: c.ObserveResponse,
		uiMode:          c.UIMode,
	}
	if s.instanceName == "" {
		s.instanceName = "default"
	}

	if err := c.parseStore(s); err != nil {
		return nil, err
	}
	if err := c.parseClientIP(s); err != nil {
		return nil, err
	}
	if err := c.parseAllowlist(s); err != nil {
		return nil, err
	}
	if err := c.parseDetectors(s); err != nil {
		return nil, err
	}
	if err := c.parseEnforcement(s); err != nil {
		return nil, err
	}
	if err := c.parseNotify(s); err != nil {
		return nil, err
	}
	if err := c.parseAdmin(s); err != nil {
		return nil, err
	}

	s.needsResponse = s.badPaths.Enabled || s.brute.Enabled
	return s, nil
}

func (c *Config) parseStore(s *settings) error {
	s.storeBackend = strings.ToLower(strings.TrimSpace(c.Store.Backend))
	if s.storeBackend == "" {
		s.storeBackend = "memory"
	}
	switch s.storeBackend {
	case "memory", "file", "redis":
	default:
		return fmt.Errorf("store.backend: %q is not one of memory, file, redis", c.Store.Backend)
	}
	s.storePath = strings.TrimSpace(c.Store.Path)
	if s.storeBackend == "file" && s.storePath == "" {
		return errors.New("store.path is required when store.backend is \"file\"")
	}
	if s.storeBackend == "redis" && strings.TrimSpace(c.Store.Redis.Address) == "" {
		return errors.New("store.redis.address is required when store.backend is \"redis\"")
	}

	var err error
	if s.snapshotInterval, err = parseDuration("store.snapshotInterval", c.Store.SnapshotInterval, 30*time.Second); err != nil {
		return err
	}
	if s.snapshotInterval == permanent {
		s.snapshotInterval = 30 * time.Second
	}
	if s.redisTimeout, err = parseDuration("store.redis.timeout", c.Store.Redis.Timeout, 2*time.Second); err != nil {
		return err
	}
	s.failOpen = c.Store.FailOpen
	s.maxEntries = c.Store.MaxEntries
	if s.maxEntries <= 0 {
		s.maxEntries = 50000
	}
	s.redis = c.Store.Redis
	if strings.TrimSpace(s.redis.KeyPrefix) == "" {
		s.redis.KeyPrefix = "scanguard:"
	}
	return nil
}

func (c *Config) parseClientIP(s *settings) error {
	var err error
	if s.trustedProxies, err = parsePrefixes("clientIP.trustedProxies", c.ClientIP.TrustedProxies); err != nil {
		return err
	}
	s.clientIPHeader = strings.TrimSpace(c.ClientIP.Header)
	if s.clientIPHeader != "" && len(s.trustedProxies) == 0 {
		// Honouring a client-IP header from an untrusted peer is not a hardening
		// gap, it is a remote "ban anyone you like" primitive. Refuse to start.
		return errors.New("clientIP.header is set but clientIP.trustedProxies is empty: " +
			"an attacker could then set that header per request to evade bans and to get " +
			"arbitrary third parties banned. List the CIDRs of your CDN or load balancer.")
	}

	s.ipv4Prefix = c.ClientIP.IPv4Prefix
	if s.ipv4Prefix == 0 {
		s.ipv4Prefix = 32
	}
	if s.ipv4Prefix < 8 || s.ipv4Prefix > 32 {
		return fmt.Errorf("clientIP.ipv4Prefix: %d is outside 8-32", s.ipv4Prefix)
	}
	s.ipv6Prefix = c.ClientIP.IPv6Prefix
	if s.ipv6Prefix == 0 {
		s.ipv6Prefix = 64
	}
	if s.ipv6Prefix < 16 || s.ipv6Prefix > 128 {
		return fmt.Errorf("clientIP.ipv6Prefix: %d is outside 16-128", s.ipv6Prefix)
	}
	return nil
}

func (c *Config) parseAllowlist(s *settings) error {
	var err error
	if s.allowCIDRs, err = parsePrefixes("allowlist.cidrs", c.Allowlist.CIDRs); err != nil {
		return err
	}
	if s.allowUA, err = newMatcher("allowlist.userAgents", c.Allowlist.UserAgents); err != nil {
		return err
	}
	if s.allowPaths, err = newMatcher("allowlist.paths", c.Allowlist.Paths); err != nil {
		return err
	}
	return nil
}

func (c *Config) parseDetectors(s *settings) error {
	d := c.Detectors
	var err error

	s.sigEnabled = d.Signatures.Enabled
	sigPatterns := d.Signatures.Patterns
	if d.Signatures.UseDefaults {
		sigPatterns = append(append([]string{}, defaultSignatures...), sigPatterns...)
	}
	if s.sigMatcher, err = newMatcher("detectors.signatures.patterns", sigPatterns); err != nil {
		return err
	}
	if s.sigEnabled && s.sigMatcher == nil {
		return errors.New("detectors.signatures is enabled but no patterns are configured " +
			"(set useDefaults: true or provide patterns)")
	}
	if s.sigExclude, err = newMatcher("detectors.signatures.exclude", d.Signatures.Exclude); err != nil {
		return err
	}

	s.honeyEnabled = d.Honeypots.Enabled
	s.honeyPaths = make(map[string]struct{}, len(d.Honeypots.Paths))
	for _, p := range d.Honeypots.Paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("detectors.honeypots.paths: %q must start with \"/\"", p)
		}
		s.honeyPaths[p] = struct{}{}
	}
	if s.honeyEnabled && len(s.honeyPaths) == 0 {
		// Not an error: an operator may legitimately want the detector wired up and
		// add trap paths later from the GUI.
		s.honeyEnabled = len(s.honeyPaths) > 0
	}

	s.uaEnabled = d.UserAgent.Enabled
	uaPatterns := d.UserAgent.Patterns
	if d.UserAgent.UseDefaults {
		uaPatterns = append(append([]string{}, defaultUserAgents...), uaPatterns...)
	}
	if s.uaMatcher, err = newMatcher("detectors.userAgent.patterns", uaPatterns); err != nil {
		return err
	}
	s.uaBanEmpty = d.UserAgent.BanEmptyUA

	s.badPaths = d.BadPaths
	if s.badPaths.Capacity <= 0 {
		s.badPaths.Capacity = 10
	}
	if s.badPathsLeak, err = parseDuration("detectors.badPaths.leak", d.BadPaths.Leak, 10*time.Second); err != nil {
		return err
	}
	if s.badPathsLeak == permanent {
		return errors.New("detectors.badPaths.leak must be a positive duration")
	}
	codes := d.BadPaths.Statuses
	if len(codes) == 0 {
		codes = defaultBadPathStatuses
	}
	s.badPathsCodes = newStatusSet(codes)

	s.brute = d.BruteForce
	if s.brute.Capacity <= 0 {
		s.brute.Capacity = 5
	}
	if s.bruteWindow, err = parseDuration("detectors.bruteForce.window", d.BruteForce.Window, time.Minute); err != nil {
		return err
	}
	if s.bruteWindow == permanent {
		return errors.New("detectors.bruteForce.window must be a positive duration")
	}
	bcodes := d.BruteForce.Statuses
	if len(bcodes) == 0 {
		bcodes = defaultBruteStatuses
	}
	s.bruteCodes = newStatusSet(bcodes)
	if s.brutePaths, err = newMatcher("detectors.bruteForce.paths", d.BruteForce.Paths); err != nil {
		return err
	}

	s.rate = d.RateAbuse
	if s.rate.Enabled {
		if s.rate.RPS <= 0 {
			return errors.New("detectors.rateAbuse.rps must be positive when the detector is enabled")
		}
		if s.rate.Burst <= 0 {
			s.rate.Burst = s.rate.RPS * 2
		}
	}

	s.payload = d.Payload
	payloadPatterns := d.Payload.Patterns
	if d.Payload.UseDefaults {
		payloadPatterns = append(append([]string{}, defaultPayloadPatterns...), payloadPatterns...)
	}
	if s.payloadMatch, err = newMatcher("detectors.payload.patterns", payloadPatterns); err != nil {
		return err
	}
	if s.payload.Enabled && s.payloadMatch == nil {
		return errors.New("detectors.payload is enabled but no patterns are configured")
	}
	if s.payload.MaxBodyBytes <= 0 {
		s.payload.MaxBodyBytes = 8192
	}
	return nil
}

func (c *Config) parseEnforcement(s *settings) error {
	s.rejectStatus = c.Enforcement.RejectStatus
	if s.rejectStatus == 0 {
		s.rejectStatus = 403
	}
	if s.rejectStatus < 100 || s.rejectStatus > 599 {
		return fmt.Errorf("enforcement.rejectStatus: %d is not a valid HTTP status code", s.rejectStatus)
	}
	s.rejectBody = c.Enforcement.RejectBody

	raw := c.Enforcement.Escalation
	if len(raw) == 0 {
		raw = defaultEscalation
	}
	s.escalation = make([]time.Duration, 0, len(raw))
	for i, entry := range raw {
		d, err := parseDuration("enforcement.escalation["+strconv.Itoa(i)+"]", entry, 0)
		if err != nil {
			return err
		}
		s.escalation = append(s.escalation, d)
	}

	var err error
	if s.decay, err = parseDuration("enforcement.decay", c.Enforcement.Decay, 24*time.Hour); err != nil {
		return err
	}

	s.tarpitEnabled = c.Enforcement.Tarpit.Enabled
	if s.tarpitDelay, err = parseDuration("enforcement.tarpit.delay", c.Enforcement.Tarpit.Delay, 3*time.Second); err != nil {
		return err
	}
	s.tarpitMax = c.Enforcement.Tarpit.MaxConcurrent
	if s.tarpitMax <= 0 {
		s.tarpitMax = 50
	}
	return nil
}

func (c *Config) parseNotify(s *settings) error {
	s.notify = c.Notify
	var err error
	if s.notifyTimeout, err = parseDuration("notify.timeout", c.Notify.Timeout, 5*time.Second); err != nil {
		return err
	}
	if s.notifyTimeout == permanent {
		s.notifyTimeout = 5 * time.Second
	}
	for i, w := range c.Notify.Webhooks {
		if strings.TrimSpace(w.URL) == "" {
			return fmt.Errorf("notify.webhooks[%d].url is required", i)
		}
		if !strings.HasPrefix(w.URL, "http://") && !strings.HasPrefix(w.URL, "https://") {
			return fmt.Errorf("notify.webhooks[%d].url must be an http(s) URL, got %q", i, w.URL)
		}
	}
	if c.Notify.Chat.Kind != "" {
		switch strings.ToLower(c.Notify.Chat.Kind) {
		case "discord", "slack", "ntfy", "gotify":
		default:
			return fmt.Errorf("notify.chat.kind: %q is not one of discord, slack, ntfy, gotify", c.Notify.Chat.Kind)
		}
		if strings.TrimSpace(c.Notify.Chat.URL) == "" {
			return errors.New("notify.chat.url is required when notify.chat.kind is set")
		}
	}
	if c.Notify.AbuseIPDB.Enabled && strings.TrimSpace(c.Notify.AbuseIPDB.APIKey) == "" {
		return errors.New("notify.abuseipdb.apiKey is required when abuseipdb is enabled")
	}
	if s.abuseCacheTTL, err = parseDuration("notify.abuseipdb.cacheTTL", c.Notify.AbuseIPDB.CacheTTL, 24*time.Hour); err != nil {
		return err
	}

	s.geoEnabled = c.Geo.Enabled
	s.geoProvider = strings.ToLower(strings.TrimSpace(c.Geo.Provider))
	if s.geoProvider == "" {
		s.geoProvider = "ip-api"
	}
	if s.geoEnabled && s.geoProvider != "ip-api" {
		return fmt.Errorf("geo.provider: %q is not supported (only \"ip-api\")", c.Geo.Provider)
	}
	if s.geoCacheTTL, err = parseDuration("geo.cacheTTL", c.Geo.CacheTTL, 168*time.Hour); err != nil {
		return err
	}
	return nil
}

func (c *Config) parseAdmin(s *settings) error {
	s.adminEnabled = c.Admin.Enabled || c.UIMode
	// Whether THIS middleware answers the admin surface is decided by THIS config
	// and nothing else: a uiMode router is the console, and a detection router that
	// declares its own admin block asked for prefix mode explicitly. What is
	// deliberately excluded is the third case — a detection router with no admin
	// block of its own, answering because a sibling console instance had one.
	s.adminServeHere = c.UIMode || c.Admin.Enabled
	s.adminServeShared = c.Admin.ServeOnDetectionRoutes
	s.adminPrefix = strings.TrimRight(strings.TrimSpace(c.Admin.PathPrefix), "/")
	if s.adminPrefix == "" {
		s.adminPrefix = "/__scanguard"
	}
	if !strings.HasPrefix(s.adminPrefix, "/") {
		return fmt.Errorf("admin.pathPrefix: %q must start with \"/\"", c.Admin.PathPrefix)
	}
	s.adminToken = strings.TrimSpace(c.Admin.Token)
	s.adminSSO = c.Admin.TrustForwardedUser
	s.adminReadOnly = c.Admin.ReadOnly
	s.eventLogSize = c.Admin.EventLogSize
	if s.eventLogSize <= 0 {
		s.eventLogSize = 500
	}

	if s.adminEnabled && s.adminToken == "" && !s.adminSSO {
		// This page can unban IPs and edit detection rules from inside the reverse
		// proxy, and Traefik contributes no authentication to it whatsoever.
		return errors.New("admin.enabled is true but neither admin.token nor admin.trustForwardedUser is set: " +
			"the admin UI would be reachable, and mutable, by anyone who can reach the router it is attached to")
	}
	if s.adminToken != "" && len(s.adminToken) < 16 {
		return errors.New("admin.token must be at least 16 characters")
	}
	return nil
}
