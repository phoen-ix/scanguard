package scanguard

// Every route the console serves, called with every method by everyone the
// console knows, the refused caller beside the allowed one.
//
// The routes are read from serveAdmin's own switch cases, not from a list: the
// lists this replaces (one here, one in the e2e sweep) had already missed
// /api/sources and the POST alias of /api/rules, and no test sent a forged
// X-Forwarded-User to a token console. A route added to serveAdmin fails
// TestEveryServedAdminRouteHasAnExpectation until it is given one below.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// servedAdminPaths returns serveAdmin's case paths: public ones (served before
// authenticate) and guarded ones (after it).
func servedAdminPaths(t *testing.T) (public, guarded []string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "admin.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var auth token.Pos
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "serveAdmin" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "authenticate" && auth == 0 {
				auth = sel.Pos()
			}
			return true
		})
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			if tag, ok := sw.Tag.(*ast.Ident); !ok || tag.Name != "path" {
				return true
			}
			for _, stmt := range sw.Body.List {
				for _, e := range stmt.(*ast.CaseClause).List {
					lit, ok := e.(*ast.BasicLit)
					if !ok {
						t.Fatalf("serveAdmin has a case that is not a string literal: %T", e)
					}
					p, _ := strconv.Unquote(lit.Value)
					if sw.Pos() < auth {
						public = append(public, p)
					} else {
						guarded = append(guarded, p)
					}
				}
			}
			return true
		})
	}
	if auth == 0 || len(public) < 5 || len(guarded) < 7 {
		t.Fatalf("read %d public and %d guarded paths from serveAdmin (authenticate found: %v); is the walk still reading the switch?",
			len(public), len(guarded), auth != 0)
	}
	return public, guarded
}

// The methods each guarded route answers, and which of them change something.
var adminRouteMethods = map[string]struct{ reads, writes []string }{
	"/api/state":          {reads: []string{"GET"}},
	"/api/events":         {reads: []string{"GET"}},
	"/api/sources":        {reads: []string{"GET"}},
	"/api/bans":           {reads: []string{"GET"}, writes: []string{"POST", "DELETE"}},
	"/api/rules":          {reads: []string{"GET"}, writes: []string{"PUT", "POST", "DELETE"}},
	"/api/rules/compiled": {reads: []string{"GET"}},
	"/api/health":         {reads: []string{"GET"}},
}

func TestEveryServedAdminRouteHasAnExpectation(t *testing.T) {
	_, guarded := servedAdminPaths(t)
	for _, p := range guarded {
		if _, ok := adminRouteMethods[p]; !ok {
			t.Errorf("serveAdmin serves %s, which adminRouteMethods has no methods for", p)
		}
	}
	if len(guarded) != len(adminRouteMethods) {
		t.Errorf("serveAdmin serves %d guarded paths, adminRouteMethods lists %d", len(guarded), len(adminRouteMethods))
	}
}

const walkToken = "walk-token-0123456789"

// The people the console knows. authed is whether authenticate lets them in.
var adminPersonas = []struct {
	name     string
	console  func(*Config)
	headers  map[string]string
	authed   bool
	readOnly bool
}{
	{"guest", tokenConsole(false), nil, false, false},
	{"a wrong token", tokenConsole(false), map[string]string{headerToken: "not-the-token-0123456789"}, false, false},
	{"a forged X-Forwarded-User on a token console", tokenConsole(false), map[string]string{headerSSOUser: "admin"}, false, false},
	{"the token", tokenConsole(false), map[string]string{headerToken: walkToken}, true, false},
	{"a Bearer token", tokenConsole(false), map[string]string{"Authorization": "Bearer " + walkToken}, true, false},
	{"the token on a read-only console", tokenConsole(true), map[string]string{headerToken: walkToken}, true, true},
	{"an SSO user", ssoConsole, map[string]string{headerSSOUser: "alice@example.org"}, true, false},
	{"an SSO console's guest (no identity)", ssoConsole, nil, false, false},
}

func tokenConsole(readOnly bool) func(*Config) {
	return func(c *Config) {
		c.Admin.Enabled = true
		c.Admin.Token = walkToken
		c.Admin.ReadOnly = readOnly
	}
}

func ssoConsole(c *Config) {
	c.Admin.Enabled = true
	c.Admin.TrustForwardedUser = true
}

func walkRequest(h http.Handler, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	target, body := "/__scanguard"+path, ""
	switch {
	case path == "/api/bans" && method == "POST":
		body = `{"key":"198.51.100.7","duration":"1m","reason":"walk"}`
	case path == "/api/bans" && method == "DELETE":
		target += "?key=198.51.100.7"
	case path == "/api/rules" && (method == "PUT" || method == "POST"):
		body = `{}`
	}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.RemoteAddr = "203.0.113.30:1"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEveryAdminRouteAnswersEachCallerAndMethod(t *testing.T) {
	public, guarded := servedAdminPaths(t)
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"}
	calls := 0
	for _, p := range adminPersonas {
		t.Run(p.name, func(t *testing.T) {
			h := build(t, p.console)
			with := func(extra map[string]string) map[string]string {
				out := map[string]string{}
				for k, v := range p.headers {
					out[k] = v
				}
				for k, v := range extra {
					out[k] = v
				}
				return out
			}
			check := func(method, path string, headers map[string]string, want int, why string) {
				calls++
				if got := walkRequest(h, method, path, headers).Code; got != want {
					t.Errorf("%s %s: %d, want %d (%s)", method, path, got, want, why)
				}
			}

			for _, path := range public {
				for _, m := range methods {
					switch {
					case path == "/favicon.ico":
						check(m, path, p.headers, http.StatusNotFound, "answered before authentication, so no failed login")
					case m == "GET" || m == "HEAD":
						check(m, path, p.headers, http.StatusOK, "the gate has to load for everyone")
					default:
						check(m, path, p.headers, http.StatusMethodNotAllowed, "assets are GET only")
					}
				}
			}
			for _, path := range append(guarded, "/api/no-such-endpoint") {
				for _, m := range methods {
					rm, known := adminRouteMethods[path]
					action := map[string]string{headerAction: "1"}
					switch {
					case !p.authed:
						check(m, path, with(action), http.StatusUnauthorized, "not signed in")
					case !known:
						check(m, path, with(action), http.StatusNotFound, "no such endpoint")
					case contains(rm.reads, m):
						check(m, path, p.headers, http.StatusOK, "a read")
					case !contains(rm.writes, m):
						check(m, path, with(action), http.StatusMethodNotAllowed, "a method the route does not take")
					case p.readOnly:
						check(m, path, with(action), http.StatusForbidden, "read-only console")
					default:
						check(m, path, p.headers, http.StatusForbidden, "a change without the anti-CSRF header")
						check(m, path, with(action), http.StatusOK, "a change")
					}
				}
			}
			// The bare prefix redirects to the directory form, for everyone.
			check("GET", "", p.headers, http.StatusPermanentRedirect, "relative asset references need the slash")
		})
	}
	if calls < 8*(5*6+8*6) {
		t.Fatalf("made %d calls; the walk is not walking", calls)
	}
}

// A token console ignores X-Forwarded-User even beside a valid token: the
// actor it records is "token", never a name anyone can put in a header.
func TestATokenConsoleNeverTakesTheForwardedUserAsTheActor(t *testing.T) {
	h := build(t, tokenConsole(false))
	rec := walkRequest(h, "POST", "/api/bans", map[string]string{headerToken: walkToken, headerAction: "1", headerSSOUser: "admin"})
	var got BanResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != 200 {
		t.Fatalf("ban: %d %s", rec.Code, rec.Body)
	}
	if got.Ban.Actor != "token" {
		t.Errorf("the ban was recorded as by %q, want token", got.Ban.Actor)
	}
}
