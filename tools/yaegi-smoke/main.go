// Command yaegi-smoke runs scanguard the way Traefik actually runs it: as source
// interpreted by Yaegi, not as compiled Go.
//
// This exists because the two ways a Traefik plugin fails are both invisible to
// `go build` and `go test`:
//
//   - Using a standard-library API newer than the Go 1.22 surface Yaegi exposes.
//     It compiles locally against a modern toolchain and fails at plugin load.
//   - Using a construct Yaegi mis-handles or refuses — //go:embed being the
//     notorious one, because it fails SILENTLY: the variable is empty, the tests
//     pass, and the page is blank only once Traefik loads it.
//
// Everything here mirrors traefik/pkg/plugins/middlewareyaegi.go: the same
// interpreter setup, the same stdlib symbols, the same mapstructure decoding of
// a YAML-shaped configuration map into the plugin's Config.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
	"gopkg.in/yaml.v3"
)

const (
	modulePath = "github.com/phoen-ix/scanguard"
	basePkg    = "scanguard"
)

var failures int

func main() {
	goPath := os.Getenv("SMOKE_GOPATH")
	if goPath == "" {
		goPath = "/go"
	}

	fmt.Println("scanguard yaegi smoke test")
	fmt.Println("  module:", modulePath)
	fmt.Println("  gopath:", goPath)
	fmt.Println()

	i := interp.New(interp.Options{GoPath: goPath, Env: os.Environ()})
	if err := i.Use(stdlib.Symbols); err != nil {
		fatal("could not load stdlib symbols: %v", err)
	}

	if _, err := i.Eval(fmt.Sprintf("import %q", modulePath)); err != nil {
		fatal("the plugin does not import cleanly under Yaegi.\n"+
			"This is the failure Traefik would report at startup as "+
			"\"invalid middleware type or middleware does not exist\".\n\n%v", err)
	}
	fmt.Println("PASS  package imports under Yaegi")

	newFn, err := i.Eval(basePkg + ".New")
	if err != nil {
		fatal("could not resolve %s.New: %v", basePkg, err)
	}
	createFn, err := i.Eval(basePkg + ".CreateConfig")
	if err != nil {
		fatal("could not resolve %s.CreateConfig: %v", basePkg, err)
	}
	fmt.Println("PASS  New and CreateConfig are exported with the expected names")

	build := func(raw map[string]interface{}) (http.Handler, error) {
		results := createFn.Call(nil)
		if len(results) != 1 {
			return nil, fmt.Errorf("CreateConfig returned %d values, want 1", len(results))
		}
		cfg := results[0].Interface()

		// Exactly what Traefik does with the dynamic configuration.
		decoder, derr := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook:       mapstructure.StringToSliceHookFunc(","),
			WeaklyTypedInput: true,
			Result:           cfg,
		})
		if derr != nil {
			return nil, derr
		}
		if derr = decoder.Decode(raw); derr != nil {
			return nil, fmt.Errorf("configuration did not decode: %w", derr)
		}

		out := newFn.Call([]reflect.Value{
			reflect.ValueOf(context.Background()),
			reflect.ValueOf(http.Handler(backend())),
			results[0],
			reflect.ValueOf("scanguard@smoke"),
		})
		if len(out) != 2 {
			return nil, fmt.Errorf("New returned %d values, want 2", len(out))
		}
		if e := out[1].Interface(); e != nil {
			return nil, e.(error)
		}
		h, ok := out[0].Interface().(http.Handler)
		if !ok {
			return nil, fmt.Errorf("New did not return an http.Handler")
		}
		return h, nil
	}

	runChecks(build)

	fmt.Println()
	if failures > 0 {
		fmt.Printf("FAILED  %d check(s) did not pass\n", failures)
		os.Exit(1)
	}
	fmt.Println("OK  scanguard runs correctly under the Yaegi interpreter")
}

// withAdminToken copies cfg one level deep, replacing only admin.token, so the
// caller's configuration map is left untouched.
func withAdminToken(cfg map[string]interface{}, token string) map[string]interface{} {
	out := make(map[string]interface{}, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	admin := make(map[string]interface{})
	if existing, ok := cfg["admin"].(map[string]interface{}); ok {
		for k, v := range existing {
			admin[k] = v
		}
	}
	admin["token"] = token
	out["admin"] = admin
	return out
}

// withCrawlers copies cfg two levels deep along detectors.userAgent, replacing
// only the crawler policy. Used to stand up sibling middleware definitions that
// share an instanceName and differ in nothing else — the exact configuration the
// per-router crawler policy exists for.
func withCrawlers(cfg map[string]interface{}, policy string) map[string]interface{} {
	out := make(map[string]interface{}, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	det := make(map[string]interface{})
	if existing, ok := cfg["detectors"].(map[string]interface{}); ok {
		for k, v := range existing {
			det[k] = v
		}
	}
	ua := make(map[string]interface{})
	if existing, ok := det["userAgent"].(map[string]interface{}); ok {
		for k, v := range existing {
			ua[k] = v
		}
	}
	ua["crawlers"] = policy
	det["userAgent"] = ua
	out["detectors"] = det
	return out
}

// withSubnetEnabled copies cfg two levels deep along enforcement.subnet, setting
// only whether range escalation is on. Used to reload the range-escalation
// instance with the feature off and on again.
func withSubnetEnabled(cfg map[string]interface{}, enabled bool) map[string]interface{} {
	out := make(map[string]interface{}, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	enf := make(map[string]interface{})
	if existing, ok := cfg["enforcement"].(map[string]interface{}); ok {
		for k, v := range existing {
			enf[k] = v
		}
	}
	sub := make(map[string]interface{})
	if existing, ok := enf["subnet"].(map[string]interface{}); ok {
		for k, v := range existing {
			sub[k] = v
		}
	}
	sub["enabled"] = enabled
	enf["subnet"] = sub
	out["enforcement"] = enf
	return out
}

// backend is the "next" handler. It answers 404 for anything under /missing/ so
// the response-status detectors have something to observe.
func backend() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasPrefix(req.URL.Path, "/missing/"):
			rw.WriteHeader(http.StatusNotFound)
			_, _ = rw.Write([]byte("not found"))
		case req.URL.Path == "/login":
			rw.WriteHeader(http.StatusUnauthorized)
			_, _ = rw.Write([]byte("nope"))
		default:
			rw.Header().Set("X-Backend", "reached")
			_, _ = rw.Write([]byte("ok"))
		}
	}
}

func runChecks(build func(map[string]interface{}) (http.Handler, error)) {
	stateDir, err := os.MkdirTemp("", "scanguard-smoke")
	if err != nil {
		fatal("could not create a temporary state directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(stateDir) }()
	statePath := stateDir + "/state.json"

	token := "smoke-token-0123456789"

	cfg := map[string]interface{}{
		"enabled":         true,
		"instanceName":    "smoke",
		"observeResponse": true,
		"store": map[string]interface{}{
			"backend": "file",
			"path":    statePath,
			// The janitor floors this to 30s whatever is written here; the
			// snapshot checks below rely on putBan flushing on every ban, not on
			// the janitor, which janitorChecks exercises on its own.
			"snapshotInterval": "30s",
		},
		"clientIP": map[string]interface{}{
			"ipv4Prefix": 32,
			"ipv6Prefix": 64,
		},
		"allowlist": map[string]interface{}{
			"cidrs": []string{"10.99.0.0/16"},
		},
		"detectors": map[string]interface{}{
			"signatures": map[string]interface{}{"enabled": true, "useDefaults": true},
			"honeypots":  map[string]interface{}{"enabled": true, "paths": []string{"/trap"}},
			"userAgent":  map[string]interface{}{"enabled": true, "useDefaults": true},
			"badPaths": map[string]interface{}{
				"enabled": true, "capacity": 4, "leak": "60s", "statuses": []int{404},
			},
			"bruteForce": map[string]interface{}{
				"enabled": true, "capacity": 3, "window": "60s", "statuses": []int{401},
			},
			"payload":    map[string]interface{}{"enabled": true, "useDefaults": true, "scanQuery": true},
			"uaRotation": map[string]interface{}{"enabled": true, "capacity": 3, "leak": "60s"},
		},
		"enforcement": map[string]interface{}{
			"rejectStatus": 403,
			"escalation":   []string{"1h", "24h"},
		},
		"admin": map[string]interface{}{
			"enabled":    true,
			"pathPrefix": "/__scanguard",
			"token":      token,
		},
	}

	h, err := build(cfg)
	if err != nil {
		fatal("New rejected a valid configuration: %v", err)
	}
	fmt.Println("PASS  configuration decodes and New accepts it")

	// A clean request must reach the backend untouched.
	rec := do(h, "GET", "/", "203.0.113.10:5000", nil)
	check("clean request reaches the backend", rec.Code == 200 && rec.Header().Get("X-Backend") == "reached",
		"got status %d", rec.Code)

	// Signature detection, and the ban that follows it.
	rec = do(h, "GET", "/wp-login.php", "203.0.113.20:5000", nil)
	check("signature probe is blocked", rec.Code == 403, "got status %d", rec.Code)

	rec = do(h, "GET", "/", "203.0.113.20:5000", nil)
	check("the banned source stays blocked on an innocent path", rec.Code == 403, "got status %d", rec.Code)

	// Honeypot.
	rec = do(h, "GET", "/trap", "203.0.113.21:5000", nil)
	check("honeypot path is blocked", rec.Code == 403, "got status %d", rec.Code)

	// Scanner user-agent.
	rec = do(h, "GET", "/", "203.0.113.22:5000", map[string]string{"User-Agent": "sqlmap/1.7"})
	check("scanner user-agent is blocked", rec.Code == 403, "got status %d", rec.Code)

	// Query payload.
	rec = do(h, "GET", "/search?q=1%20UNION%20SELECT%20password", "203.0.113.23:5000", nil)
	check("injection payload in the query string is blocked", rec.Code == 403, "got status %d", rec.Code)

	// User-agent rotation. The distinct-item bucket is now a method on a struct
	// field of the counter record, a shape the interpreter has not run before.
	for _, ua := range []string{"agent-a/1", "agent-b/1"} {
		do(h, "GET", "/", "203.0.113.110:5000", map[string]string{"User-Agent": ua})
	}
	rec = do(h, "GET", "/", "203.0.113.110:5000", map[string]string{"User-Agent": "agent-c/1"})
	check("a source cycling user-agents is banned on the 3rd", rec.Code == 403, "got status %d", rec.Code)
	for n := 0; n < 10; n++ {
		rec = do(h, "GET", "/", "203.0.113.111:5000", map[string]string{"User-Agent": "Mozilla/5.0 same"})
	}
	check("one user-agent repeated is not rotation", rec.Code == 200, "got status %d", rec.Code)

	// Allowlisted source must survive an obvious probe.
	rec = do(h, "GET", "/wp-login.php", "10.99.1.1:5000", nil)
	check("allowlisted CIDR is never banned", rec.Code == 200, "got status %d", rec.Code)

	// Distinct-bad-path leaky bucket: four distinct 404s trip a capacity of four.
	src := "203.0.113.30:5000"
	for n := 0; n < 4; n++ {
		do(h, "GET", fmt.Sprintf("/missing/%d", n), src, nil)
	}
	rec = do(h, "GET", "/", src, nil)
	check("distinct 404 flood triggers a ban", rec.Code == 403, "got status %d", rec.Code)

	// The same path repeated must NOT ban: that is a broken link, not a scan.
	src = "203.0.113.31:5000"
	for n := 0; n < 12; n++ {
		do(h, "GET", "/missing/always-the-same", src, nil)
	}
	rec = do(h, "GET", "/", src, nil)
	check("repeating ONE failing path does not ban (broken link, not a scan)", rec.Code == 200,
		"got status %d — the distinct-path bucket is counting volume instead of distinct paths", rec.Code)

	// Brute force on a real endpoint.
	src = "203.0.113.32:5000"
	for n := 0; n < 3; n++ {
		do(h, "POST", "/login", src, nil)
	}
	rec = do(h, "GET", "/", src, nil)
	check("repeated auth failures trigger a ban", rec.Code == 403, "got status %d", rec.Code)

	// Spoofed forwarded headers from an untrusted peer must be ignored entirely.
	do(h, "GET", "/wp-login.php", "203.0.113.40:5000",
		map[string]string{"X-Forwarded-For": "198.51.100.77"})
	rec = do(h, "GET", "/", "198.51.100.77:5000", nil)
	check("a spoofed X-Forwarded-For cannot get a third party banned", rec.Code == 200,
		"got status %d — the header was believed without a trusted-proxy check", rec.Code)

	// Protocol upgrades must never be wrapped, or WebSockets break.
	rec = do(h, "GET", "/ws", "203.0.113.50:5000",
		map[string]string{"Connection": "Upgrade", "Upgrade": "websocket"})
	check("upgrade requests pass through", rec.Code == 200, "got status %d", rec.Code)

	// Admin surface.
	rec = do(h, "GET", "/__scanguard/api/health", "203.0.113.60:5000", nil)
	check("admin API refuses an unauthenticated request", rec.Code == 401, "got status %d", rec.Code)

	rec = do(h, "GET", "/__scanguard/api/health", "203.0.113.60:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("admin API accepts the configured token", rec.Code == 200, "got status %d", rec.Code)

	rec = do(h, "GET", "/__scanguard/", "203.0.113.60:5000",
		map[string]string{"X-Scanguard-Token": token})
	body := rec.Body.String()
	check("admin UI serves a non-empty page (the go:embed trap)",
		rec.Code == 200 && len(body) > 2000 && strings.Contains(body, "<title>scanguard</title>"),
		"got status %d and %d bytes — an empty page here is exactly how //go:embed fails under Yaegi",
		rec.Code, len(body))

	rec = do(h, "GET", "/__scanguard/app.js", "203.0.113.60:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("admin UI script is served", rec.Code == 200 && len(rec.Body.String()) > 2000,
		"got status %d and %d bytes", rec.Code, rec.Body.Len())

	rec = do(h, "GET", "/__scanguard/api/state", "203.0.113.60:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("admin state endpoint returns JSON", rec.Code == 200 && strings.Contains(rec.Body.String(), "\"bans\""),
		"got status %d", rec.Code)

	// Mutations need the anti-CSRF header.
	rec = do(h, "DELETE", "/__scanguard/api/bans?key=203.0.113.20/32", "203.0.113.60:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("mutation without the action header is refused", rec.Code == 403, "got status %d", rec.Code)

	rec = do(h, "DELETE", "/__scanguard/api/bans?key=203.0.113.20/32", "203.0.113.60:5000",
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	check("unban succeeds with the action header", rec.Code == 200 && strings.Contains(rec.Body.String(), "\"unbanned\":true"),
		"got status %d body %s", rec.Code, rec.Body.String())

	rec = do(h, "GET", "/", "203.0.113.20:5000", nil)
	check("an unbanned source is served again immediately", rec.Code == 200, "got status %d", rec.Code)

	// A range ban from the console has to block the addresses inside it. Under
	// Yaegi it blocked nothing: matchWideLocked's parallel assignment
	// "best, bestBits = b, w.Bits()" left best nil, with no error anywhere.
	rec = doBody(h, "POST", "/__scanguard/api/bans", "203.0.113.60:5000", `{"key":"192.0.2.0/24"}`,
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	check("a manual range ban is accepted", rec.Code == 200, "got status %d body %s", rec.Code, rec.Body.String())
	rec = do(h, "GET", "/", "192.0.2.77:5000", nil)
	check("a manual range ban blocks an address inside it", rec.Code == 403, "got status %d", rec.Code)
	rec = do(h, "DELETE", "/__scanguard/api/bans?key=192.0.2.0/24", "203.0.113.60:5000",
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	check("the range ban is lifted", rec.Code == 200 && strings.Contains(rec.Body.String(), "\"unbanned\":true"),
		"got status %d body %s", rec.Code, rec.Body.String())

	// Persistence. putBan flushes the snapshot on every ban (the janitor, every
	// 30s at the least, never ticks inside this process), so the file must
	// already exist and hold the remaining bans.
	waitFor(2*time.Second, func() bool {
		info, serr := os.Stat(statePath)
		return serr == nil && info.Size() > 0
	})
	raw, rerr := os.ReadFile(statePath)
	check("state snapshot is written to disk", rerr == nil && bytes.Contains(raw, []byte("\"bans\"")),
		"could not read %s: %v", statePath, rerr)

	// A second instance with the same name must reuse the shared runtime rather
	// than starting from scratch — this is what makes bans survive the New() call
	// Traefik makes on every configuration reload.
	h2, err := build(cfg)
	if err != nil {
		fatal("rebuilding the middleware failed: %v", err)
	}
	rec = do(h2, "GET", "/", "203.0.113.21:5000", nil)
	check("bans survive the New() call Traefik makes on every config reload", rec.Code == 403,
		"got status %d — state is not shared across middleware instances", rec.Code)

	// Per-router crawler policy. This is the only gate that sees a Yaegi
	// regression in it: configFingerprint now takes a shallow struct copy to blank
	// the crawler field before hashing, and a struct copy is exactly the shape the
	// interpreter has broken before (see the comment on configFingerprint). If the
	// copy misbehaves under Yaegi the two siblings below stop differing, or the
	// shared settings get rebuilt and the admin token stops working.
	crawler := map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)"}

	blocking, berr := build(withCrawlers(cfg, "block"))
	if berr != nil {
		fatal("New rejected crawlers: block: %v", berr)
	}
	serving, serr := build(withCrawlers(cfg, "ignore"))
	if serr != nil {
		fatal("New rejected crawlers: ignore: %v", serr)
	}

	rec = do(blocking, "GET", "/", "203.0.113.90:5000", crawler)
	check("crawlers: block refuses a listed crawler", rec.Code == 403, "got status %d", rec.Code)

	rec = do(serving, "GET", "/", "203.0.113.91:5000", crawler)
	check("a sibling router on the same instance still serves that crawler",
		rec.Code == 200, "got status %d — the per-router policy did not survive", rec.Code)

	// block must write nothing to the shared ban list: same source, other router.
	rec = do(blocking, "GET", "/", "203.0.113.92:5000", crawler)
	check("crawlers: block refuses the second source too", rec.Code == 403, "got status %d", rec.Code)
	rec = do(serving, "GET", "/", "203.0.113.92:5000", crawler)
	check("a crawler blocked on one router is not banned on the other",
		rec.Code == 200, "got status %d — block leaked into the shared ban list", rec.Code)

	// And the siblings must not have clobbered the shared settings on the way.
	rec = do(serving, "GET", "/__scanguard/api/state", "203.0.113.93:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("the shared admin token still works after building divergent siblings",
		rec.Code == 200, "got status %d — the sibling rebuilt the shared settings", rec.Code)
	rec = do(serving, "GET", "/trap", "203.0.113.94:5000", nil)
	check("the shared honeypot still works after building divergent siblings",
		rec.Code == 403, "got status %d", rec.Code)

	// The tile drill-downs. Under Yaegi these are exactly the shapes that fail
	// silently: a struct reaching a response through an interface{} parameter, or a
	// map[string]interface{} holding structs, both encode to empty with no error.
	// Asserting the bodies are non-empty and correctly shaped is the only gate that
	// sees it — `go test` marshals all of these correctly.
	rec = do(h, "GET", "/__scanguard/api/sources", "203.0.113.80:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("sources endpoint answers", rec.Code == 200, "got status %d", rec.Code)
	var sources struct {
		Sources []struct {
			Key      string `json:"key"`
			LastSeen string `json:"lastSeen"`
			Offences int    `json:"offences"`
			BadPaths int    `json:"badPaths"`
		} `json:"sources"`
		Total int `json:"total"`
	}
	if jerr := json.Unmarshal(rec.Body.Bytes(), &sources); jerr != nil {
		check("sources response decodes", false, "%v: %s", jerr, truncate(rec.Body.String(), 200))
	} else {
		check("sources response carries populated rows, not empty structs",
			len(sources.Sources) > 0 && sources.Sources[0].Key != "" && sources.Sources[0].LastSeen != "",
			"total=%d rows=%d body=%s", sources.Total, len(sources.Sources), truncate(rec.Body.String(), 250))
	}

	rec = do(h, "GET", "/__scanguard/api/state", "203.0.113.81:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("state carries the by-host tally that backs the requests tile",
		strings.Contains(rec.Body.String(), "\"topHosts\"") && strings.Contains(rec.Body.String(), "\"topExempt\""),
		"body=%s", truncate(rec.Body.String(), 250))

	// The other named-struct responses. Each is a struct the interpreter could
	// encode as {} without an error; only decoding them and finding the fields
	// populated proves otherwise.
	rec = do(h, "GET", "/__scanguard/api/events?kind=ban&limit=50", "203.0.113.81:5000",
		map[string]string{"X-Scanguard-Token": token})
	var events struct {
		Events []struct {
			Seq      uint64 `json:"seq"`
			Kind     string `json:"kind"`
			Key      string `json:"key"`
			Detector string `json:"detector"`
		} `json:"events"`
		LastSeq uint64 `json:"lastSeq"`
	}
	if jerr := json.Unmarshal(rec.Body.Bytes(), &events); jerr != nil || rec.Code != 200 {
		check("events response decodes", false, "status %d: %v: %s", rec.Code, jerr, truncate(rec.Body.String(), 200))
	} else {
		check("events response carries populated ban events, not empty structs",
			len(events.Events) > 0 && events.Events[0].Kind == "ban" && events.Events[0].Key != "" &&
				events.Events[0].Seq > 0 && events.LastSeq >= events.Events[0].Seq,
			"lastSeq=%d rows=%d body=%s", events.LastSeq, len(events.Events), truncate(rec.Body.String(), 250))
	}

	rec = do(h, "GET", "/__scanguard/api/bans", "203.0.113.81:5000",
		map[string]string{"X-Scanguard-Token": token})
	var banList struct {
		Bans []struct {
			Key      string `json:"key"`
			Detector string `json:"detector"`
			Created  string `json:"created"`
			Offences int    `json:"offences"`
		} `json:"bans"`
	}
	if jerr := json.Unmarshal(rec.Body.Bytes(), &banList); jerr != nil || rec.Code != 200 {
		check("ban list decodes", false, "status %d: %v: %s", rec.Code, jerr, truncate(rec.Body.String(), 200))
	} else {
		check("ban list carries populated rows, not empty structs",
			len(banList.Bans) > 0 && banList.Bans[0].Key != "" && banList.Bans[0].Detector != "" &&
				banList.Bans[0].Created != "" && banList.Bans[0].Offences > 0,
			"rows=%d body=%s", len(banList.Bans), truncate(rec.Body.String(), 250))
	}

	rec = do(h, "GET", "/__scanguard/api/rules/compiled", "203.0.113.81:5000",
		map[string]string{"X-Scanguard-Token": token})
	var compiled map[string][]string
	if jerr := json.Unmarshal(rec.Body.Bytes(), &compiled); jerr != nil || rec.Code != 200 {
		check("compiled rules decode", false, "status %d: %v: %s", rec.Code, jerr, truncate(rec.Body.String(), 200))
	} else {
		check("compiled rules list the defaults and the configured honeypot",
			len(compiled["signatures"]) > 50 && len(compiled["userAgents"]) > 20 &&
				len(compiled["honeypots"]) == 1 && compiled["honeypots"][0] == "/trap" && len(compiled["crawlers"]) > 0,
			"signatures=%d userAgents=%d honeypots=%v", len(compiled["signatures"]), len(compiled["userAgents"]), compiled["honeypots"])
	}

	// A configuration CHANGE must actually reach the running middleware on rebuild.
	// Traefik drives this path on every dynamic-configuration change, and it is
	// invisible to `go test`: compiled Go marshals a struct correctly through an
	// interface{} parameter, Yaegi empties it. That made every configuration hash
	// to sha256("{}"), so acquireRuntime compared them equal and treated every
	// reload as "nothing changed" — no token, allowlist or detector edit in the
	// dynamic file reached the middleware until Traefik was restarted, silently.
	rotated := "smoke-token-rotated-9876543210"
	h3, err := build(withAdminToken(cfg, rotated))
	if err != nil {
		fatal("rebuilding with a changed token failed: %v", err)
	}
	rec = do(h3, "GET", "/__scanguard/api/health", "203.0.113.90:5000",
		map[string]string{"X-Scanguard-Token": rotated})
	check("a changed admin token takes effect on reload", rec.Code == 200,
		"got status %d — the new configuration was ignored, so nothing in the dynamic file applies without a Traefik restart", rec.Code)

	rec = do(h3, "GET", "/__scanguard/api/health", "203.0.113.90:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("the superseded admin token stops working", rec.Code == 401,
		"got status %d — the old token still authenticates after rotation", rec.Code)

	// Put the original configuration back, so the checks below still hold and the
	// reload path is shown to apply changes in both directions.
	h, err = build(cfg)
	if err != nil {
		fatal("restoring the original configuration failed: %v", err)
	}
	rec = do(h, "GET", "/__scanguard/api/health", "203.0.113.90:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("reverting the configuration restores the previous token", rec.Code == 200,
		"got status %d", rec.Code)

	// Rule editing. This exercises the console's write path end to end through the
	// interpreter: JSON decode, deep copy of the configuration, re-parse, and the
	// atomic swap of live settings.
	rec = do(h, "GET", "/__scanguard/api/rules", "203.0.113.60:5000",
		map[string]string{"X-Scanguard-Token": token})
	check("rule editor exposes the editable configuration",
		rec.Code == 200 && strings.Contains(rec.Body.String(), "\"effective\"") &&
			strings.Contains(rec.Body.String(), "\"fromFile\"") &&
			strings.Contains(rec.Body.String(), `"uaRotation":{"enabled":true,"capacity":3,`) &&
			strings.Contains(rec.Body.String(), `"subnet":{"ipv4Prefix":24,"ipv6Prefix":48,"threshold":5,`),
		"got status %d body %s", rec.Code, truncate(rec.Body.String(), 200))

	var rules struct {
		Effective map[string]interface{} `json:"effective"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rules); err != nil {
		fatal("rules response did not decode: %v", err)
	}

	// Traefik decodes plugin configuration with mapstructure, which MERGES into a
	// slice that already holds elements instead of replacing it. The smoke config
	// sets a single status; anything more than that means a default leaked in and
	// every operator who narrows a list would silently get the defaults back.
	// Each shape assertion is a check in its own right: a response that no longer
	// has the shape used to skip these two silently and look like a pass.
	detectors, ok := rules.Effective["detectors"].(map[string]interface{})
	check("the effective rules carry a detectors section", ok, "effective=%v", rules.Effective)
	if ok {
		bad, ok := detectors["badPaths"].(map[string]interface{})
		check("the effective rules carry badPaths", ok, "detectors=%v", detectors)
		if ok {
			statuses, _ := bad["statuses"].([]interface{})
			check("a configured list replaces the default instead of merging into it",
				len(statuses) == 1, "badPaths.statuses is %v, want exactly [404]", statuses)
		}
	}
	// The same trap for the ban ladder: two configured rungs must not come back
	// with the two default rungs appended.
	enf, ok := rules.Effective["enforcement"].(map[string]interface{})
	check("the effective rules carry an enforcement section", ok, "effective=%v", rules.Effective)
	if ok {
		ladder, _ := enf["escalation"].([]interface{})
		check("a configured escalation ladder replaces the default instead of merging into it",
			len(ladder) == 2 && ladder[0] == "1h" && ladder[1] == "24h",
			"enforcement.escalation is %v, want exactly [1h 24h]", ladder)
	}

	// Add a honeypot from the console and confirm it takes effect immediately.
	if detectors, ok := rules.Effective["detectors"].(map[string]interface{}); ok {
		if honey, ok := detectors["honeypots"].(map[string]interface{}); ok {
			honey["enabled"] = true
			honey["paths"] = []string{"/trap", "/console-trap"}
		}
	}
	edited, err := json.Marshal(rules.Effective)
	if err != nil {
		fatal("could not re-encode the rule set: %v", err)
	}

	rec = doBody(h, "PUT", "/__scanguard/api/rules", "203.0.113.60:5000", string(edited),
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	check("a rule change is accepted", rec.Code == 200, "got status %d body %s", rec.Code, truncate(rec.Body.String(), 300))
	// Decoded, not substring-matched: "detectors" appears in every rules
	// response, so the old check could not fail.
	var applied struct {
		Overridden []string `json:"overridden"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &applied)
	check("the changed section is reported as console-managed",
		len(applied.Overridden) == 1 && applied.Overridden[0] == "detectors",
		"overridden = %v, want [detectors]", applied.Overridden)

	rec = do(h, "GET", "/console-trap", "203.0.113.70:5000", nil)
	check("a honeypot added from the console blocks at once, with no restart",
		rec.Code == 403, "got status %d", rec.Code)

	// A broken pattern must be refused without disturbing what is running.
	rec = doBody(h, "PUT", "/__scanguard/api/rules", "203.0.113.60:5000",
		`{"detectors":{"signatures":{"enabled":true,"patterns":["([unclosed"]}}}`,
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	check("an invalid rule change is refused", rec.Code == 422, "got status %d", rec.Code)

	rec = do(h, "GET", "/console-trap", "203.0.113.71:5000", nil)
	check("the previous rule set still runs after a refused change", rec.Code == 403, "got status %d", rec.Code)

	// A submission naming a section the console may not touch is refused outright.
	rec = doBody(h, "PUT", "/__scanguard/api/rules", "203.0.113.60:5000",
		`{"dryRun":true,"clientIP":{"trustedProxies":["0.0.0.0/0"]}}`,
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	check("a rule change naming a protected section is refused", rec.Code == 400, "got status %d", rec.Code)

	rec = doBody(h, "DELETE", "/__scanguard/api/rules", "203.0.113.60:5000", "",
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	check("rule changes can be reverted to the file configuration", rec.Code == 200, "got status %d", rec.Code)

	rec = do(h, "GET", "/console-trap", "203.0.113.72:5000", nil)
	check("the reverted honeypot no longer blocks", rec.Code == 200, "got status %d", rec.Code)

	subnetChecks(build, token)
	roundTwoChecks(build, token)
	manifestChecks(build)
	settingChecks(build, token, stateDir)

	// A read-only console serves everything and refuses every mutation.
	ro, err := build(map[string]interface{}{
		"instanceName": "smoke-readonly",
		"store":        map[string]interface{}{"backend": "memory"},
		"admin":        map[string]interface{}{"enabled": true, "pathPrefix": "/__scanguard", "token": token, "readOnly": true},
	})
	if err != nil {
		fatal("New rejected the read-only console: %v", err)
	}
	rec = do(ro, "GET", "/__scanguard/api/state", "203.0.113.60:5000", map[string]string{"X-Scanguard-Token": token})
	check("a read-only console still serves state", rec.Code == 200, "got status %d", rec.Code)
	rec = doBody(ro, "PUT", "/__scanguard/api/rules", "203.0.113.60:5000", `{"dryRun":true}`,
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	check("a read-only console refuses a rule change", rec.Code == 403, "got status %d", rec.Code)
	rec = doBody(ro, "POST", "/__scanguard/api/bans", "203.0.113.60:5000", `{"key":"192.0.2.1"}`,
		map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"})
	check("a read-only console refuses a manual ban", rec.Code == 403, "got status %d", rec.Code)

	// The snapshot the main instance wrote is read back by a runtime that starts
	// from nothing but the file. This is the restart path: json.Unmarshal into
	// the plugin's own struct types under the interpreter, then restore().
	restored, err := build(map[string]interface{}{
		"instanceName": "smoke-restore",
		"store":        map[string]interface{}{"backend": "file", "path": statePath},
		"admin":        map[string]interface{}{"enabled": true, "pathPrefix": "/__scanguard", "token": token},
	})
	if err != nil {
		fatal("New rejected a runtime reading the existing snapshot: %v", err)
	}
	rec = do(restored, "GET", "/", "203.0.113.21:5000", nil)
	check("a ban read back from the snapshot is enforced by a fresh runtime", rec.Code == 403,
		"got status %d — the snapshot did not restore under the interpreter", rec.Code)

	// Invalid configuration must be rejected loudly, at startup.
	_, err = build(map[string]interface{}{
		"clientIP": map[string]interface{}{"header": "Cf-Connecting-Ip"},
	})
	check("a client-IP header without trusted proxies is refused", err != nil,
		"New accepted a configuration that would let anyone get third parties banned")

	_, err = build(map[string]interface{}{
		"admin": map[string]interface{}{"enabled": true},
	})
	check("an admin UI without a token is refused", err != nil,
		"New accepted an unauthenticated admin surface")

	_, err = build(map[string]interface{}{
		"detectors": map[string]interface{}{
			"signatures": map[string]interface{}{"enabled": true, "useDefaults": false, "patterns": []string{"([unclosed"}},
		},
	})
	check("an invalid regular expression is refused", err != nil, "New accepted a broken pattern")
}

// subnetChecks runs range escalation on its own instance. It is the path that
// adds a second map lookup to the ban store and a map of members to the counter
// record, both on the hot path, and neither is visible to go test under Yaegi.
func subnetChecks(build func(map[string]interface{}) (http.Handler, error), token string) {
	cfgSubnet := map[string]interface{}{
		"instanceName": "smoke-subnet",
		"store":        map[string]interface{}{"backend": "memory"},
		"allowlist":    map[string]interface{}{"cidrs": []string{"198.51.100.0/25"}},
		"enforcement": map[string]interface{}{
			"subnet": map[string]interface{}{
				"enabled": true, "threshold": 3, "window": "1h", "ipv4Prefix": 24, "ipv6Prefix": 48,
			},
		},
		"admin": map[string]interface{}{"enabled": true, "pathPrefix": "/__scanguard", "token": token},
	}
	h, err := build(cfgSubnet)
	if err != nil {
		fatal("New rejected the range-escalation configuration: %v", err)
	}
	auth := map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"}

	for n := 1; n <= 3; n++ {
		do(h, "GET", "/wp-login.php", fmt.Sprintf("192.0.2.%d:5000", n), nil)
	}
	rec := do(h, "GET", "/", "192.0.2.99:5000", nil)
	check("three banned sources in a /24 ban a fresh address in it", rec.Code == 403, "got status %d", rec.Code)

	rec = do(h, "GET", "/__scanguard/api/bans", "203.0.113.60:5000", auth)
	check("the range ban is listed with detector subnet",
		strings.Contains(rec.Body.String(), `"key":"192.0.2.0/24"`) && strings.Contains(rec.Body.String(), `"detector":"subnet"`),
		"got status %d body %s", rec.Code, truncate(rec.Body.String(), 300))

	// Switch range escalation off on a reload. The /24 is now wider than any key
	// the store knows, so it is found only if setKeyWidths rebuilt the wide index
	// — the method whose parallel assignment Yaegi v0.16.1 ran without effect.
	// Before this check a no-op setKeyWidths passed every gate here, because the
	// masked lookup found the range without it.
	cfgOff := withSubnetEnabled(cfgSubnet, false)
	hOff, oerr := build(cfgOff)
	if oerr != nil {
		fatal("New rejected the range-escalation instance with the feature off: %v", oerr)
	}
	rec = do(hOff, "GET", "/", "192.0.2.99:5000", nil)
	check("an existing range ban still blocks after range escalation is switched off",
		rec.Code == 403, "got status %d — setKeyWidths did not rebuild the wide-prefix index", rec.Code)
	if _, oerr = build(cfgSubnet); oerr != nil {
		fatal("New rejected switching range escalation back on: %v", oerr)
	}
	rec = do(h, "GET", "/", "192.0.2.99:5000", nil)
	check("the range ban still blocks after range escalation is switched back on",
		rec.Code == 403, "got status %d", rec.Code)

	for n := 1; n <= 3; n++ {
		do(h, "GET", "/wp-login.php", fmt.Sprintf("[2001:db8:1:%d::1]:5000", n), nil)
	}
	rec = do(h, "GET", "/", "[2001:db8:1:99::1]:5000", nil)
	check("three banned /64s in a /48 ban a fresh /64 in it", rec.Code == 403, "got status %d", rec.Code)

	for n := 130; n <= 132; n++ {
		do(h, "GET", "/wp-login.php", fmt.Sprintf("198.51.100.%d:5000", n), nil)
	}
	rec = do(h, "GET", "/", "198.51.100.200:5000", nil)
	check("a range overlapping the allowlist is never banned", rec.Code == 200, "got status %d", rec.Code)

	rec = do(h, "DELETE", "/__scanguard/api/bans?key=192.0.2.0/24", "203.0.113.60:5000", auth)
	check("the range ban can be lifted", rec.Code == 200 && strings.Contains(rec.Body.String(), "\"unbanned\":true"),
		"got status %d body %s", rec.Code, rec.Body.String())
	rec = do(h, "GET", "/", "192.0.2.99:5000", nil)
	check("a lifted range ban serves its addresses again", rec.Code == 200, "got status %d", rec.Code)
}

// roundTwoChecks covers what the second audit found this gate never
// interpreted: trusted-proxy attribution, the notifier's outbound payload, the
// uiMode console and Bearer credentials, a dry run with its shadow list, the
// tarpit, rate abuse, body scanning, an empty user-agent, signature exclusions,
// the user-agent and path allowlists, brute-force paths, and the geo and
// AbuseIPDB decoding against fakes. Each instance has its own name, so its
// settings cannot disturb the main instance's.
func roundTwoChecks(build func(map[string]interface{}) (http.Handler, error), token string) {
	auth := map[string]string{"X-Scanguard-Token": token}
	authAction := map[string]string{"X-Scanguard-Token": token, "X-Scanguard-Action": "1"}
	base := func(name string, extra map[string]interface{}) map[string]interface{} {
		cfg := map[string]interface{}{
			"instanceName": name,
			"store":        map[string]interface{}{"backend": "memory"},
			"admin":        map[string]interface{}{"enabled": true, "pathPrefix": "/__scanguard", "token": token},
		}
		for k, v := range extra {
			cfg[k] = v
		}
		return cfg
	}
	mustBuild := func(what string, cfg map[string]interface{}) http.Handler {
		h, err := build(cfg)
		if err != nil {
			fatal("New rejected the %s configuration: %v", what, err)
		}
		return h
	}

	// Trusted proxy: the configured header, then the X-Forwarded-For walk. The
	// main instance trusts no proxy, so resolve() returned before either was
	// read and the "spoofed header" check passed for an implementation with no
	// trust logic at all.
	proxy := mustBuild("trusted-proxy", base("smoke-proxy", map[string]interface{}{
		"clientIP": map[string]interface{}{"trustedProxies": []string{"10.0.0.0/8"}, "header": "X-Real-Ip"},
	}))
	do(proxy, "GET", "/wp-login.php", "10.0.0.5:5000", map[string]string{"X-Real-Ip": "203.0.113.140"})
	rec := do(proxy, "GET", "/", "10.0.0.5:5000", map[string]string{"X-Real-Ip": "203.0.113.140"})
	check("the client named by the trusted proxy's header is banned", rec.Code == 403, "got status %d", rec.Code)
	rec = do(proxy, "GET", "/", "10.0.0.5:5000", map[string]string{"X-Real-Ip": "203.0.113.141"})
	check("another client behind the same proxy is served", rec.Code == 200, "got status %d", rec.Code)
	do(proxy, "GET", "/wp-login.php", "10.0.0.5:5000", map[string]string{"X-Forwarded-For": "203.0.113.142, 10.0.0.9"})
	rec = do(proxy, "GET", "/", "10.0.0.5:5000", map[string]string{"X-Forwarded-For": "203.0.113.142, 10.0.0.9"})
	check("the X-Forwarded-For walk attributes the rightmost untrusted hop", rec.Code == 403,
		"got status %d — the chain was not walked from the proxy's end", rec.Code)
	rec = do(proxy, "GET", "/", "10.0.0.9:5000", nil)
	check("a trusted hop is never banned itself", rec.Code == 200, "got status %d", rec.Code)
	rec = do(proxy, "GET", "/__scanguard", "10.0.0.5:5000", nil)
	check("the bare admin prefix redirects to the directory form",
		rec.Code == 308 && rec.Header().Get("Location") == "/__scanguard/", "got status %d location %q", rec.Code, rec.Header().Get("Location"))

	// The notifier: an outbound call from an interpreted goroutine, and a body
	// that is a named struct holding the Event. Encoded through a map it came
	// out as {} under Yaegi, with no error.
	var sinkMu sync.Mutex
	var payloads []string
	sink := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		sinkMu.Lock()
		payloads = append(payloads, string(b))
		sinkMu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}))
	defer sink.Close()
	received := func(n int) bool {
		sinkMu.Lock()
		defer sinkMu.Unlock()
		return len(payloads) >= n
	}
	notifying := mustBuild("notifier", base("smoke-notify", map[string]interface{}{
		"notify": map[string]interface{}{
			"timeout":  "5s",
			"webhooks": []interface{}{map[string]interface{}{"url": sink.URL + "/ban", "headers": map[string]interface{}{"X-Harness": "smoke"}}},
		},
	}))
	do(notifying, "GET", "/wp-login.php", "203.0.113.150:5000", nil)
	waitFor(5*time.Second, func() bool { return received(1) })
	var hook struct {
		Source   string `json:"source"`
		Instance string `json:"instance"`
		Event    struct {
			Seq      uint64  `json:"seq"`
			Kind     string  `json:"kind"`
			Key      string  `json:"key"`
			Detector string  `json:"detector"`
			BanFor   string  `json:"banFor"`
			Expires  *string `json:"expires"`
			Actor    string  `json:"actor"`
		} `json:"event"`
	}
	sinkMu.Lock()
	first := ""
	if len(payloads) > 0 {
		first = payloads[0]
	}
	sinkMu.Unlock()
	if jerr := json.Unmarshal([]byte(first), &hook); jerr != nil || first == "" {
		check("a ban reaches the webhook as JSON", false, "%d payloads, first %q: %v", len(payloads), truncate(first, 200), jerr)
	} else {
		check("the webhook payload carries the event, not an empty object",
			hook.Source == "scanguard" && hook.Instance == "smoke-notify" && hook.Event.Kind == "ban" &&
				hook.Event.Key == "203.0.113.150/32" && hook.Event.Detector == "signature" && hook.Event.BanFor == "1h" &&
				hook.Event.Seq > 0 && hook.Event.Expires != nil,
			"payload %s", truncate(first, 300))
	}
	rec = do(notifying, "DELETE", "/__scanguard/api/bans?key=203.0.113.150/32", "203.0.113.60:5000", authAction)
	check("the notifying instance lifts the ban", rec.Code == 200, "got status %d", rec.Code)
	waitFor(5*time.Second, func() bool { return received(2) })
	sinkMu.Lock()
	second := ""
	if len(payloads) > 1 {
		second = payloads[1]
	}
	sinkMu.Unlock()
	hook.Event.Kind = ""
	_ = json.Unmarshal([]byte(second), &hook)
	check("the unban reaches the webhook with its actor", hook.Event.Kind == "unban" && hook.Event.Actor == "token",
		"second payload %s", truncate(second, 300))

	// A uiMode console beside its detector, with Bearer credentials.
	detector := mustBuild("ui detector", map[string]interface{}{
		"instanceName": "smoke-ui",
		"store":        map[string]interface{}{"backend": "memory"},
	})
	console := mustBuild("ui console", map[string]interface{}{
		"instanceName": "smoke-ui",
		"uiMode":       true,
		"admin":        map[string]interface{}{"enabled": true, "token": token},
	})
	do(detector, "GET", "/wp-login.php", "203.0.113.160:5000", nil)
	rec = do(console, "GET", "/api/bans", "203.0.113.60:5000", map[string]string{"Authorization": "bearer " + token})
	check("a uiMode console lists the detector's bans to a Bearer credential",
		rec.Code == 200 && strings.Contains(rec.Body.String(), "203.0.113.160/32"), "got status %d body %s", rec.Code, truncate(rec.Body.String(), 200))
	rec = do(console, "GET", "/", "203.0.113.60:5000", nil)
	check("a uiMode console serves the page at its root without a token",
		rec.Code == 200 && strings.Contains(rec.Body.String(), "gate-form"), "got status %d", rec.Code)
	rec = do(console, "GET", "/favicon.ico", "203.0.113.60:5000", nil)
	check("the favicon is a plain 404", rec.Code == 404, "got status %d", rec.Code)
	rec = do(console, "GET", "/api/state", "203.0.113.60:5000", auth)
	var uiState struct {
		Stats map[string]int64 `json:"stats"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &uiState)
	check("the favicon request did not count as a failed login", rec.Code == 200 && uiState.Stats["authFailures"] == 0,
		"status %d authFailures=%d", rec.Code, uiState.Stats["authFailures"])
	rec = do(console, "GET", "/somewhere-else", "203.0.113.60:5000", nil)
	check("a uiMode console refuses an unauthenticated non-asset path", rec.Code == 401, "got status %d", rec.Code)
	rec = do(detector, "GET", "/", "203.0.113.161:5000", nil)
	check("the detector beside a uiMode console still proxies", rec.Code == 200 && rec.Header().Get("X-Backend") == "reached",
		"got status %d", rec.Code)

	// A dry run: nothing refused, the would-ban recorded once, listed flagged.
	dry := mustBuild("dry-run", base("smoke-dry", map[string]interface{}{"dryRun": true}))
	rec = do(dry, "GET", "/wp-login.php", "203.0.113.170:5000", nil)
	check("a dry run passes a probe to the backend", rec.Code == 200 && rec.Header().Get("X-Backend") == "reached", "got status %d", rec.Code)
	rec = do(dry, "GET", "/wp-admin/", "203.0.113.170:5000", nil)
	check("a dry run passes the second probe too", rec.Code == 200, "got status %d", rec.Code)
	rec = do(dry, "GET", "/__scanguard/api/bans", "203.0.113.60:5000", auth)
	check("a dry run lists its would-ban, flagged",
		strings.Contains(rec.Body.String(), `"key":"203.0.113.170/32"`) && strings.Contains(rec.Body.String(), `"dryRun":true`),
		"body %s", truncate(rec.Body.String(), 300))
	rec = do(dry, "GET", "/__scanguard/api/events?kind=ban", "203.0.113.60:5000", auth)
	check("a dry run detects a source once, not on every probe",
		strings.Count(rec.Body.String(), `"key":"203.0.113.170/32"`) == 1, "body %s", truncate(rec.Body.String(), 300))

	// The tarpit: an atomic.Value holding a channel, and a select on a timer.
	tar := mustBuild("tarpit", base("smoke-tarpit", map[string]interface{}{
		"enforcement": map[string]interface{}{"tarpit": map[string]interface{}{"enabled": true, "delay": "300ms", "maxConcurrent": 5}},
	}))
	do(tar, "GET", "/wp-login.php", "203.0.113.180:5000", nil)
	started := time.Now()
	rec = do(tar, "GET", "/", "203.0.113.180:5000", nil)
	elapsed := time.Since(started)
	check("a rejected request is held in the tarpit", rec.Code == 403 && elapsed >= 250*time.Millisecond,
		"got status %d after %v", rec.Code, elapsed)

	// Rate abuse: the token bucket.
	rate := mustBuild("rate-abuse", base("smoke-rate", map[string]interface{}{
		"detectors": map[string]interface{}{
			"signatures": map[string]interface{}{"enabled": false},
			"userAgent":  map[string]interface{}{"enabled": false},
			"badPaths":   map[string]interface{}{"enabled": false},
			"rateAbuse":  map[string]interface{}{"enabled": true, "rps": 1, "burst": 3},
		},
	}))
	for n := 0; n < 3; n++ {
		rec = do(rate, "GET", "/", "203.0.113.190:5000", nil)
	}
	check("requests within the burst allowance are served", rec.Code == 200, "got status %d", rec.Code)
	rec = do(rate, "GET", "/", "203.0.113.190:5000", nil)
	check("the request past the burst allowance is banned", rec.Code == 403, "got status %d", rec.Code)

	// Body scanning: peekBody reads and rewinds the request body.
	bodyScan := mustBuild("payload body", base("smoke-body", map[string]interface{}{
		"detectors": map[string]interface{}{
			"payload": map[string]interface{}{"enabled": true, "useDefaults": true, "scanQuery": false, "scanBody": true, "maxBodyBytes": 4096},
		},
	}))
	rec = doBody(bodyScan, "POST", "/form", "203.0.113.200:5000", "q=1 UNION SELECT password FROM users", nil)
	check("an injection payload in the request body is blocked", rec.Code == 403, "got status %d", rec.Code)
	rec = doBody(bodyScan, "POST", "/form", "203.0.113.201:5000", "name=hello world", nil)
	check("an ordinary body is passed through", rec.Code == 200, "got status %d", rec.Code)

	// An empty user-agent, when that is configured to be a detection.
	emptyUA := mustBuild("empty user-agent", base("smoke-emptyua", map[string]interface{}{
		"detectors": map[string]interface{}{
			"userAgent": map[string]interface{}{"enabled": true, "useDefaults": true, "banEmptyUA": true},
		},
	}))
	rec = do(emptyUA, "GET", "/", "203.0.113.210:5000", nil)
	check("a request with no user-agent is banned when banEmptyUA is on", rec.Code == 403, "got status %d", rec.Code)
	rec = do(emptyUA, "GET", "/", "203.0.113.211:5000", map[string]string{"User-Agent": "Mozilla/5.0 (X11; Linux) Firefox/128.0"})
	check("a request with a user-agent is served", rec.Code == 200, "got status %d", rec.Code)

	// Signature exclusions, the user-agent and path allowlists, brute-force paths.
	rules := mustBuild("exclusions and allowlists", base("smoke-rules", map[string]interface{}{
		"allowlist": map[string]interface{}{"userAgents": []string{"uptime-robot"}, "paths": []string{"^/health$"}},
		"detectors": map[string]interface{}{
			"signatures": map[string]interface{}{"enabled": true, "useDefaults": true, "exclude": []string{"^/wp-login\\.php$"}},
			"bruteForce": map[string]interface{}{"enabled": true, "capacity": 2, "window": "60s", "statuses": []int{401}, "paths": []string{"^/login$"}},
			"badPaths":   map[string]interface{}{"enabled": false},
		},
	}))
	rec = do(rules, "GET", "/wp-login.php", "203.0.113.220:5000", nil)
	check("an excluded signature does not fire", rec.Code == 200, "got status %d", rec.Code)
	rec = do(rules, "GET", "/wp-config.php", "203.0.113.220:5000", nil)
	check("the other signatures still fire beside an exclusion", rec.Code == 403, "got status %d", rec.Code)
	rec = do(rules, "GET", "/health", "203.0.113.220:5000", nil)
	check("an allowlisted path is not a way around a ban", rec.Code == 403, "got status %d", rec.Code)
	rec = do(rules, "GET", "/health", "203.0.113.220:5000", map[string]string{"User-Agent": "uptime-robot/2.0"})
	check("an allowlisted user-agent bypasses the ban, on an allowlisted path too", rec.Code == 200, "got status %d", rec.Code)
	rec = do(rules, "GET", "/.env", "203.0.113.221:5000", map[string]string{"User-Agent": "uptime-robot/2.0"})
	check("an allowlisted user-agent is never banned", rec.Code == 200, "got status %d", rec.Code)
	for n := 0; n < 2; n++ {
		do(rules, "POST", "/login", "203.0.113.224:5000", nil)
	}
	rec = do(rules, "GET", "/", "203.0.113.224:5000", nil)
	check("brute force on the configured login path bans", rec.Code == 403, "got status %d", rec.Code)

	// Geo and AbuseIPDB against fakes: decoding a third party's JSON under the
	// interpreter, the Country column filled on read, a reputation ban.
	geoSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write([]byte(`{"status":"success","countryCode":"AT"}`))
	}))
	defer geoSrv.Close()
	var abuseMu sync.Mutex
	var reported []string
	abuseSrv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/api/v2/check":
			_, _ = rw.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
		case "/api/v2/report":
			b, _ := io.ReadAll(req.Body)
			abuseMu.Lock()
			reported = append(reported, string(b))
			abuseMu.Unlock()
			_, _ = rw.Write([]byte(`{"data":{"abuseConfidenceScore":100}}`))
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer abuseSrv.Close()
	enriched := mustBuild("geo and abuseipdb", base("smoke-geo", map[string]interface{}{
		"geo": map[string]interface{}{"enabled": true, "provider": "ip-api", "cacheTTL": "1h", "endpoint": geoSrv.URL},
		"notify": map[string]interface{}{
			"abuseipdb": map[string]interface{}{
				"enabled": true, "apiKey": "smoke-key", "report": true, "check": true,
				"minConfidence": 75, "cacheTTL": "1h", "endpoint": abuseSrv.URL,
			},
		},
	}))
	do(enriched, "GET", "/wp-login.php", "203.0.113.230:5000", nil)
	waitFor(5*time.Second, func() bool {
		abuseMu.Lock()
		defer abuseMu.Unlock()
		return len(reported) > 0
	})
	abuseMu.Lock()
	report := strings.Join(reported, "\n")
	abuseMu.Unlock()
	check("a ban is reported to AbuseIPDB with the client address and a category",
		strings.Contains(report, "ip=203.0.113.230") && strings.Contains(report, "categories=21"), "reports: %q", truncate(report, 200))
	countryShown := false
	waitFor(5*time.Second, func() bool {
		rec = do(enriched, "GET", "/__scanguard/api/bans", "203.0.113.60:5000", auth)
		countryShown = strings.Contains(rec.Body.String(), `"country":"AT"`)
		return countryShown
	})
	check("the ban list shows the country once the lookup has landed", countryShown, "body %s", truncate(rec.Body.String(), 300))
	// Reputation: the first request schedules the lookup, the next one is banned.
	do(enriched, "GET", "/", "203.0.113.231:5000", nil)
	banned := false
	waitFor(5*time.Second, func() bool {
		rec = do(enriched, "GET", "/", "203.0.113.231:5000", nil)
		banned = rec.Code == 403
		return banned
	})
	rec = do(enriched, "GET", "/__scanguard/api/bans", "203.0.113.60:5000", auth)
	check("a source AbuseIPDB scores as abusive is banned by the reputation detector",
		banned && strings.Contains(rec.Body.String(), `"detector":"reputation"`), "banned=%v body %s", banned, truncate(rec.Body.String(), 300))

	janitorChecks(build, token, sink.URL, received)
}

// manifestChecks builds the plugin from .traefik.yml's testData exactly as the
// plugin catalog does when it validates a submission: decoded from YAML, under
// the interpreter. TestManifestTestDataShape in the plugin's own tests is a
// hand-copied subset and could drift from the file.
func manifestChecks(build func(map[string]interface{}) (http.Handler, error)) {
	path := os.Getenv("SMOKE_MANIFEST")
	if path == "" {
		path = "../../.traefik.yml"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		check("the plugin manifest is readable", false, "%v", err)
		return
	}
	var manifest struct {
		TestData map[string]interface{} `yaml:"testData"`
	}
	if err := yaml.Unmarshal(raw, &manifest); err != nil || len(manifest.TestData) == 0 {
		check("the plugin manifest carries testData", false, "%v (%d keys)", err, len(manifest.TestData))
		return
	}
	h, err := build(manifest.TestData)
	check("the manifest's testData is a configuration New accepts", err == nil, "%v", err)
	if err == nil {
		rec := do(h, "GET", "/", "203.0.113.250:5000", nil)
		check("the testData instance serves a clean request", rec.Code == 200, "got status %d", rec.Code)
	}
}

// settingChecks covers the settings that used to be hardcoded: extra crawler
// patterns, the reject content type, and the debounced snapshot write.
func settingChecks(build func(map[string]interface{}) (http.Handler, error), token, stateDir string) {
	path := stateDir + "/settings.json"
	h, err := build(map[string]interface{}{
		"instanceName": "smoke-settings",
		"store":        map[string]interface{}{"backend": "file", "path": path, "flushDebounce": "300ms"},
		"detectors": map[string]interface{}{
			"userAgent": map[string]interface{}{
				"enabled": true, "useDefaults": true, "crawlers": "block", "crawlerPatterns": []string{"\\bgptbot\\b"},
			},
		},
		"enforcement": map[string]interface{}{"rejectBody": "<p>no</p>", "rejectContentType": "text/html; charset=utf-8"},
		"admin":       map[string]interface{}{"enabled": true, "pathPrefix": "/__scanguard", "token": token},
	})
	if err != nil {
		fatal("New rejected the settings configuration: %v", err)
	}
	rec := do(h, "GET", "/", "203.0.113.251:5000", map[string]string{"User-Agent": "Mozilla/5.0 (compatible; GPTBot/1.2)"})
	check("a crawler from crawlerPatterns is blocked", rec.Code == 403, "got status %d", rec.Code)
	check("the rejection carries the configured content type",
		rec.Header().Get("Content-Type") == "text/html; charset=utf-8", "got %q", rec.Header().Get("Content-Type"))
	do(h, "GET", "/wp-login.php", "203.0.113.252:5000", nil)
	written := false
	waitFor(3*time.Second, func() bool {
		b, rerr := os.ReadFile(path)
		written = rerr == nil && bytes.Contains(b, []byte("203.0.113.252/32"))
		return written
	})
	check("a debounced ban reaches the snapshot", written, "no snapshot holding the ban within 3s")
}

// janitorChecks waits out one janitor tick, so the sweep, the expiry claim and
// the expiry notification run under the interpreter at least once. Thirty-odd
// seconds, so it runs only when SMOKE_JANITOR=1 (CI sets it); the snapshot
// checks above never see a tick.
func janitorChecks(build func(map[string]interface{}) (http.Handler, error), token, sinkURL string, received func(int) bool) {
	if os.Getenv("SMOKE_JANITOR") != "1" {
		fmt.Println("SKIP  janitor tick (set SMOKE_JANITOR=1 to wait one out)")
		return
	}
	// The sink already holds the notifying instance's two deliveries.
	h, err := build(map[string]interface{}{
		"instanceName": "smoke-janitor",
		"store":        map[string]interface{}{"backend": "memory"},
		"enforcement":  map[string]interface{}{"escalation": []string{"2s"}},
		"notify": map[string]interface{}{
			"timeout":  "5s",
			"webhooks": []interface{}{map[string]interface{}{"url": sinkURL + "/janitor", "events": []string{"unban"}}},
		},
		"admin": map[string]interface{}{"enabled": true, "pathPrefix": "/__scanguard", "token": token},
	})
	if err != nil {
		fatal("New rejected the janitor configuration: %v", err)
	}
	rec := do(h, "GET", "/wp-login.php", "203.0.113.240:5000", nil)
	check("the janitor instance bans a probe", rec.Code == 403, "got status %d", rec.Code)
	fmt.Println("....  waiting for a janitor tick (up to 40s)")
	waitFor(40*time.Second, func() bool { return received(3) })
	check("the expiry unban reaches the webhook after the janitor swept the ban", received(3),
		"no unban was delivered within 40s of a 2s ban")
	rec = do(h, "GET", "/__scanguard/api/state", "203.0.113.60:5000", map[string]string{"X-Scanguard-Token": token})
	check("the expired ban is counted", strings.Contains(rec.Body.String(), `"expired":1`), "body %s", truncate(rec.Body.String(), 300))
}

// doBody issues a request with an explicit JSON body, for the console's write endpoints.
func doBody(h http.Handler, method, target, remoteAddr, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func do(h http.Handler, method, target, remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	var body io.Reader
	if method == http.MethodPost {
		body = strings.NewReader("user=admin&pass=admin")
	}
	req := httptest.NewRequest(method, target, body)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func waitFor(limit time.Duration, cond func() bool) {
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func check(name string, ok bool, format string, args ...interface{}) {
	if ok {
		fmt.Println("PASS ", name)
		return
	}
	failures++
	fmt.Printf("FAIL  %s\n        %s\n", name, fmt.Sprintf(format, args...))
}

func fatal(format string, args ...interface{}) {
	fmt.Printf("\nFATAL %s\n", fmt.Sprintf(format, args...))
	os.Exit(1)
}
