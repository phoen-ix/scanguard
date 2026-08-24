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
	"time"

	"github.com/mitchellh/mapstructure"
	"github.com/traefik/yaegi/interp"
	"github.com/traefik/yaegi/stdlib"
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

// backend is the "next" handler. It answers 404 for anything under /missing/ so
// the response-status detectors have something to observe.
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
			"backend":          "file",
			"path":             statePath,
			"snapshotInterval": "1s",
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
			"payload": map[string]interface{}{"enabled": true, "useDefaults": true, "scanQuery": true},
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

	// Persistence. The janitor snapshots on a timer, and applyBan flushes
	// immediately, so the file must already exist and hold the remaining bans.
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
			strings.Contains(rec.Body.String(), "\"fromFile\""),
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
	if detectors, ok := rules.Effective["detectors"].(map[string]interface{}); ok {
		if bad, ok := detectors["badPaths"].(map[string]interface{}); ok {
			statuses, _ := bad["statuses"].([]interface{})
			check("a configured list replaces the default instead of merging into it",
				len(statuses) == 1, "badPaths.statuses is %v, want exactly [404]", statuses)
		}
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
	check("the changed section is reported as console-managed",
		strings.Contains(rec.Body.String(), "\"detectors\""),
		"overridden sections missing from the response")

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
