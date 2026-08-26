package scanguard

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The admin surface is the highest-risk part of this plugin, so the threat model
// is worth stating.
//
// Traefik contributes no authentication to a page a plugin serves: it is
// reachable by anyone who can reach the router the middleware is attached to. The
// only comparable plugin in the catalog ships its web UI with no authentication
// at all, an arbitrary file write driven by a request header, and log.Fatal
// inside request handlers — which under Yaegi is a panic a remote client can
// trigger to kill Traefik. It is an existence proof, not a template.
//
// Defences here, in order:
//
//   - Disabled by default, and refuses to start with neither a token nor an
//     upstream SSO identity configured.
//   - The token is compared in constant time and must be at least 16 characters.
//   - Credentials travel in a custom request header, never a cookie, so a
//     cross-site request cannot carry them.
//   - Mutations additionally require a custom header that no cross-origin form
//     can set, and are refused in readOnly mode.
//   - Every mutation is logged with actor and timestamp.
//   - The response carries a restrictive CSP and is never cached.
//
// None of that removes the need to chain Traefik's own basicAuth or forwardAuth
// in front of the admin router and, ideally, bind it to a private entrypoint.

const (
	headerToken   = "X-Scanguard-Token"
	headerAction  = "X-Scanguard-Action"
	headerSSOUser = "X-Forwarded-User"
)

// serveAdmin routes an admin request. uiMode comes from the handler rather than
// from settings, because the console and the detector share one settings value.
func (rt *runtime) serveAdmin(s *settings, uiMode bool, rw http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	if !uiMode {
		path = strings.TrimPrefix(path, s.adminPrefix)
	}
	if path == "" {
		path = "/"
	}

	adminHeaders(rw)

	// The three static assets are served WITHOUT authentication, and they have to
	// be. The console carries its own login gate: index.html renders an "Access
	// token" prompt, app.js stores what you type in sessionStorage and validates it
	// against /api/health before revealing anything. Gating the assets behind the
	// very check that gate exists to satisfy makes the page undeliverable, so a
	// browser only ever receives the 401 JSON body and the console is reachable
	// from curl alone.
	//
	// Nothing is given away by serving them. They are compiled-in string constants
	// with no secrets, no configuration and no state; the 401 they replace already
	// announced that scanguard is running here. Every endpoint that reads or
	// changes anything stays behind authenticate() below — including /api/health,
	// which must stay gated because rejecting a wrong token is exactly how the gate
	// reports a bad token back to the user.
	switch path {
	case "/", "/index.html":
		rt.serveAsset(rw, req, "text/html; charset=utf-8", indexHTML)
		return
	case "/app.css":
		rt.serveAsset(rw, req, "text/css; charset=utf-8", appCSS)
		return
	case "/app.js":
		rt.serveAsset(rw, req, "application/javascript; charset=utf-8", appJS)
		return
	}

	actor, ok := rt.authenticate(s, req)
	if !ok {
		rw.Header().Set("WWW-Authenticate", `Bearer realm="scanguard"`)
		writeJSON(rw, http.StatusUnauthorized, map[string]string{
			"error": "authentication required: send the configured token in the " + headerToken + " header",
		})
		return
	}

	switch path {
	case "/api/state":
		rt.apiState(s, rw, req)
	case "/api/events":
		rt.apiEvents(rw, req)
	case "/api/sources":
		rt.apiSources(rw, req)
	case "/api/bans":
		rt.apiBans(s, rw, req, actor)
	case "/api/rules":
		rt.apiRules(s, rw, req, actor)
	case "/api/rules/compiled":
		rt.apiCompiledRules(s, rw, req)
	case "/api/health":
		writeJSON(rw, http.StatusOK, map[string]interface{}{
			"ok":       true,
			"instance": rt.name,
			"backend":  rt.store.backend(),
		})
	default:
		writeJSON(rw, http.StatusNotFound, map[string]string{"error": "no such endpoint"})
	}
}

// adminHeaders applies the security headers every admin response carries.
//
// The content security policy is strict because it can be: the page loads its
// stylesheet and script from sibling endpoints rather than inlining them, so
// script-src does not need 'unsafe-inline' and an injected string in a path or
// user-agent cannot become executable script.
func adminHeaders(rw http.ResponseWriter) {
	h := rw.Header()
	h.Set("Cache-Control", "no-store, max-age=0")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "+
			"img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
}

// authenticate validates the request and returns the acting identity.
func (rt *runtime) authenticate(s *settings, req *http.Request) (string, bool) {
	if s.adminSSO {
		if user := strings.TrimSpace(req.Header.Get(headerSSOUser)); user != "" {
			return truncate(user, 128), true
		}
	}
	if s.adminToken == "" {
		return "", false
	}

	presented := strings.TrimSpace(req.Header.Get(headerToken))
	if presented == "" {
		if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			presented = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	if presented == "" {
		return "", false
	}
	// Constant time, so the comparison cannot be used as an oracle to recover the
	// token one character at a time.
	if subtle.ConstantTimeCompare([]byte(presented), []byte(s.adminToken)) != 1 {
		return "", false
	}
	return "token", true
}

// authorizeMutation gates every state-changing request.
func (rt *runtime) authorizeMutation(s *settings, rw http.ResponseWriter, req *http.Request) bool {
	if s.adminReadOnly {
		writeJSON(rw, http.StatusForbidden, map[string]string{"error": "scanguard is in read-only mode"})
		return false
	}
	// A custom header cannot be set by a cross-origin form or image request, so
	// requiring one makes cross-site request forgery structurally impossible here.
	if req.Header.Get(headerAction) == "" {
		writeJSON(rw, http.StatusForbidden, map[string]string{
			"error": "mutations require the " + headerAction + " header",
		})
		return false
	}
	return true
}

func (rt *runtime) serveAsset(rw http.ResponseWriter, req *http.Request, contentType, body string) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	rw.Header().Set("Content-Type", contentType)
	rw.WriteHeader(http.StatusOK)
	if req.Method == http.MethodHead {
		return
	}
	_, _ = rw.Write([]byte(body))
}

// BanListResponse, BanResponse and EventsResponse exist for the same reason as
// RulesResponse: every admin payload carrying a struct gets a named type.
type BanListResponse struct {
	Bans []Ban `json:"bans"`
}

type BanResponse struct {
	Ban Ban `json:"ban"`
}

type EventsResponse struct {
	Events  []Event `json:"events"`
	LastSeq uint64  `json:"lastSeq"`
}

// StateResponse is the payload backing the dashboard's first paint.
type StateResponse struct {
	Instance   string                 `json:"instance"`
	Backend    string                 `json:"backend"`
	DryRun     bool                   `json:"dryRun"`
	ReadOnly   bool                   `json:"readOnly"`
	Uptime     string                 `json:"uptime"`
	Stats      map[string]int64       `json:"stats"`
	Tracked    int                    `json:"trackedSources"`
	Evicted    int64                  `json:"evictedSources"`
	Bans       []Ban                  `json:"bans"`
	Events     []Event                `json:"events"`
	LastSeq    uint64                 `json:"lastSeq"`
	TopPaths   []TopEntry             `json:"topPaths"`
	TopSources []TopEntry             `json:"topSources"`
	Detectors  []TopEntry             `json:"topDetectors"`
	TopHosts   []TopEntry             `json:"topHosts"`
	TopExempt  []TopEntry             `json:"topExempt"`
	Config     map[string]interface{} `json:"config"`
}

func (rt *runtime) apiState(s *settings, rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}
	now := time.Now()

	writeJSON(rw, http.StatusOK, StateResponse{
		Instance: rt.name,
		Backend:  rt.store.backend(),
		DryRun:   s.dryRun,
		ReadOnly: s.adminReadOnly,
		Uptime:   now.Sub(rt.stats.StartedAt).Truncate(time.Second).String(),
		Stats: map[string]int64{
			"requests":   rt.stats.Requests.Load(),
			"rejected":   rt.stats.Rejected.Load(),
			"detections": rt.stats.Detections.Load(),
			"bansIssued": rt.stats.BansIssued.Load(),
			"bansManual": rt.stats.BansManual.Load(),
			"unbans":     rt.stats.Unbans.Load(),
			"expired":    rt.stats.Expired.Load(),
			"exempt":     rt.stats.Skipped.Load(),
		},
		Tracked:    rt.counters.size(),
		Evicted:    rt.counters.evicted(),
		Bans:       rt.store.list(now),
		Events:     rt.events.recent(100),
		LastSeq:    rt.events.lastSeq(),
		TopPaths:   rt.topPaths.top(10),
		TopSources: rt.topSources.top(10),
		Detectors:  rt.topDetectors.top(10),
		TopHosts:   rt.topHosts.top(10),
		TopExempt:  rt.topExempt.top(10),
		Config:     configSummary(s),
	})
}

// SourcesResponse is the tracked-source table. A named struct, like every other
// admin response: encoding one as map[string]interface{} with struct values
// yields empty objects under Yaegi, with no error to notice.
type SourcesResponse struct {
	Sources   []SourceEntry `json:"sources"`
	Total     int           `json:"total"`
	Truncated bool          `json:"truncated"`
}

// apiSources serves the tracked-source table on demand.
//
// Deliberately NOT folded into apiState: the console polls that every three
// seconds, and this walks a table capped at 50000 entries while holding the lock
// the request hot path needs. It is fetched only while the tile is open.
func (rt *runtime) apiSources(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}

	limit := 50
	if v := req.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}

	sources, total := rt.counters.recent(limit)
	writeJSON(rw, http.StatusOK, SourcesResponse{
		Sources:   sources,
		Total:     total,
		Truncated: total > len(sources),
	})
}

func (rt *runtime) apiEvents(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}

	var since uint64
	if raw := req.URL.Query().Get("since"); raw != "" {
		if n, err := strconv.ParseUint(raw, 10, 64); err == nil {
			since = n
		}
	}
	limit := 200
	if raw := req.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}

	writeJSON(rw, http.StatusOK, EventsResponse{
		Events:  rt.events.since(since, limit),
		LastSeq: rt.events.lastSeq(),
	})
}

// banRequest is the body of a manual ban or unban.
type banRequest struct {
	Key      string `json:"key"`
	Duration string `json:"duration"`
	Reason   string `json:"reason"`
}

func (rt *runtime) apiBans(s *settings, rw http.ResponseWriter, req *http.Request, actor string) {
	switch req.Method {
	case http.MethodGet:
		writeJSON(rw, http.StatusOK, BanListResponse{Bans: rt.store.list(time.Now())})

	case http.MethodPost:
		if !rt.authorizeMutation(s, rw, req) {
			return
		}
		var body banRequest
		if err := json.NewDecoder(http.MaxBytesReader(rw, req.Body, 8192)).Decode(&body); err != nil {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		key, err := parseBanKey(s, body.Key)
		if err != nil {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// An operator can still hurt themselves, but not with a single click and
		// not silently: banning something that is explicitly allowlisted, or the
		// proxy in front of Traefik, is refused outright.
		if containsAddr(s.trustedProxies, key.Addr()) || containsAddr(s.allowCIDRs, key.Addr()) {
			writeJSON(rw, http.StatusConflict, map[string]string{
				"error": "refusing to ban " + key.String() + ": it is in trustedProxies or the allowlist",
			})
			return
		}
		duration, err := parseDuration("duration", body.Duration, time.Hour)
		if err != nil {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		reason := strings.TrimSpace(body.Reason)
		if reason == "" {
			reason = "manual ban"
		}

		ban := rt.banManual(s, key, duration, truncate(reason, 256), actor)
		logWarn(rt.name, "manual ban created", map[string]interface{}{
			"key": ban.Key, "actor": actor, "duration": formatDuration(duration), "reason": reason,
		})
		// Named type, not a map: see the note on RulesResponse for why a struct
		// nested in a map[string]interface{} can lose its fields under Yaegi.
		writeJSON(rw, http.StatusOK, BanResponse{Ban: ban})

	case http.MethodDelete:
		if !rt.authorizeMutation(s, rw, req) {
			return
		}
		key, err := parseBanKey(s, req.URL.Query().Get("key"))
		if err != nil {
			writeJSON(rw, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		removed := rt.unban(key, actor)
		logInfo(rt.name, "manual unban", map[string]interface{}{
			"key": key.String(), "actor": actor, "found": removed,
		})
		writeJSON(rw, http.StatusOK, map[string]interface{}{"unbanned": removed, "key": key.String()})

	default:
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "GET, POST or DELETE"})
	}
}

// apiRules is the rule editor: GET the editable configuration, PUT a new one,
// DELETE to hand control back to the file.
//
// The write path deliberately re-derives everything through Config.parse rather
// than mutating live settings, so a browser edit is validated by exactly the same
// code that validates traefik's dynamic configuration at startup. An invalid
// submission is rejected with the reason and changes nothing.
func (rt *runtime) apiRules(s *settings, rw http.ResponseWriter, req *http.Request, actor string) {
	switch req.Method {
	case http.MethodGet:
		rt.writeRules(rw, http.StatusOK)

	case http.MethodPut, http.MethodPost:
		if !rt.authorizeMutation(s, rw, req) {
			return
		}
		var body editableConfig
		decoder := json.NewDecoder(http.MaxBytesReader(rw, req.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			writeJSON(rw, http.StatusBadRequest, map[string]string{
				"error": "the submitted rule set could not be read: " + err.Error(),
			})
			return
		}
		if err := rt.setOverrides(body.toOverrides(), actor); err != nil {
			// A rejected edit is the normal case while somebody is typing a regular
			// expression, so it is a 422 with the parser's own message, not a 500.
			writeJSON(rw, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		rt.writeRules(rw, http.StatusOK)

	case http.MethodDelete:
		if !rt.authorizeMutation(s, rw, req) {
			return
		}
		if err := rt.setOverrides(nil, actor); err != nil {
			writeJSON(rw, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		logInfo(rt.name, "console rule changes discarded; the file configuration is back in force",
			map[string]interface{}{"actor": actor})
		rt.writeRules(rw, http.StatusOK)

	default:
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "GET, PUT or DELETE"})
	}
}

// RulesResponse is the rule editor's payload.
//
// It is a declared struct rather than a map[string]interface{}, and that is not
// a style preference. Under the Yaegi interpreter, encoding this response as a
// map with the configuration structs as values produced `{"effective":{}}` — the
// nested structs lost every field, silently and without an encoding error. The
// console then read that empty object, wrote it back, and wiped the ruleset.
//
// A declared struct encodes correctly in both compiled and interpreted builds.
// The rule to follow here: give any response containing a nested struct a named
// type, and never hand the encoder a heterogeneous map. The smoke test asserts a
// round trip through this endpoint precisely because the failure is invisible to
// `go test`.
type RulesResponse struct {
	Effective  editableConfig `json:"effective"`
	FromFile   editableConfig `json:"fromFile"`
	Overridden []string       `json:"overridden"`
	BuiltIn    builtInCounts  `json:"builtIn"`
	Updated    *time.Time     `json:"updated,omitempty"`
	Actor      string         `json:"actor,omitempty"`
}

type builtInCounts struct {
	Signatures int `json:"signatures"`
	UserAgents int `json:"userAgents"`
	Payload    int `json:"payload"`
}

func (rt *runtime) writeRules(rw http.ResponseWriter, status int) {
	effective, fromFile, ov, err := rt.rulesView()
	if err != nil {
		writeJSON(rw, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}

	payload := RulesResponse{
		Effective:  effective,
		FromFile:   fromFile,
		Overridden: ov.sections(),
		BuiltIn: builtInCounts{
			Signatures: len(defaultSignatures),
			UserAgents: len(defaultUserAgents),
			Payload:    len(defaultPayloadPatterns),
		},
	}
	if ov != nil {
		updated := ov.Updated
		payload.Updated = &updated
		payload.Actor = ov.Actor
	}
	writeJSON(rw, status, payload)
}

// apiCompiledRules reports what the detectors actually ended up with, which is
// not the same as what was configured: built-in defaults are folded in, patterns
// are de-duplicated, and empty sections disappear.
func (rt *runtime) apiCompiledRules(s *settings, rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeJSON(rw, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}

	honeypots := make([]string, 0, len(s.honeyPaths))
	for p := range s.honeyPaths {
		honeypots = append(honeypots, p)
	}
	sort.Strings(honeypots)

	writeJSON(rw, http.StatusOK, map[string]interface{}{
		"signatures": s.sigMatcher.list(),
		"exclude":    s.sigExclude.list(),
		"userAgents": s.uaMatcher.list(),
		"honeypots":  honeypots,
		"payload":    s.payloadMatch.list(),
		"allowPaths": s.allowPaths.list(),
		"allowUA":    s.allowUA.list(),
		"allowCIDRs": prefixStrings(s.allowCIDRs),
		"trusted":    prefixStrings(s.trustedProxies),
	})
}

// parseBanKey accepts an address or a CIDR and normalises it to the configured
// ban-key width, so an operator typing "1.2.3.4" and the detector that banned
// "1.2.3.4/32" agree about what to unban.
func parseBanKey(s *settings, raw string) (netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Prefix{}, errKeyRequired
	}
	if strings.Contains(raw, "/") {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return netip.Prefix{}, errBadKey
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, errBadKey
	}
	return banKey(addr, s.ipv4Prefix, s.ipv6Prefix), nil
}

type adminError string

func (e adminError) Error() string { return string(e) }

const (
	errKeyRequired adminError = "key is required (an IP address or a CIDR)"
	errBadKey      adminError = "key is not a valid IP address or CIDR"
)

func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}

// configSummary is what the UI is allowed to see. Secrets never appear: the admin
// token, the AbuseIPDB key, the Redis password and webhook URLs (which routinely
// embed credentials) are all withheld, and only their presence is reported.
func configSummary(s *settings) map[string]interface{} {
	return map[string]interface{}{
		"instance":        s.instanceName,
		"dryRun":          s.dryRun,
		"observeResponse": s.observeResponse && s.needsResponse,
		"storeBackend":    s.storeBackend,
		"maxEntries":      s.maxEntries,
		"ipv4Prefix":      s.ipv4Prefix,
		"ipv6Prefix":      s.ipv6Prefix,
		"trustedProxies":  len(s.trustedProxies),
		"clientIPHeader":  s.clientIPHeader,
		"rejectStatus":    s.rejectStatus,
		"escalation":      durationStrings(s.escalation),
		"decay":           s.decay.String(),
		"tarpit":          s.tarpitEnabled,
		// Read-only on purpose. admin.* is never console-editable (see overrides.go),
		// and this field in particular decides where the console itself is reachable
		// — a setting a stolen token must not be able to widen. Reported so an
		// operator can SEE the answer without reading the configuration file.
		"adminOnDetectionRoutes": s.adminServeShared,
		"detectors": map[string]bool{
			detectorSignature:  s.sigEnabled,
			detectorHoneypot:   s.honeyEnabled,
			detectorUserAgent:  s.uaEnabled,
			detectorBadPaths:   s.badPaths.Enabled,
			detectorBruteForce: s.brute.Enabled,
			detectorRateAbuse:  s.rate.Enabled,
			detectorPayload:    s.payload.Enabled,
		},
		"crawlers": s.uaCrawlers,
		"notify": map[string]bool{
			"webhooks":  len(s.notify.Webhooks) > 0,
			"chat":      s.notify.Chat.Kind != "",
			"abuseipdb": s.notify.AbuseIPDB.Enabled,
		},
		"geo": s.geoEnabled,
	}
}

func durationStrings(ds []time.Duration) []string {
	out := make([]string, 0, len(ds))
	for _, d := range ds {
		out = append(out, formatDuration(d))
	}
	return out
}

func writeJSON(rw http.ResponseWriter, status int, payload interface{}) {
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(payload)
}
