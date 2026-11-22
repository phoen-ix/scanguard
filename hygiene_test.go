package scanguard

// A test step a user would not take is a product finding, never a test fix.
//
// This reads EVERY e2e file (e2e/**/*.ts), every Go test file and every
// examples/*.sh check, not a list of today's, and fails on the shapes such a
// step takes: a sleep, a forced or synthetic event, a script that sets state
// in the page, an action retried until it works, a page left the instant
// something was clicked. A use that stays is listed in allowedTestShapes with
// its count and its reason; one that goes away must leave the list too.

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	// What a user does, and what a test does to the server behind their back.
	testAction = regexp.MustCompile(`\.(?:click|dblclick|press|fill|type|check|uncheck|selectOption|hover|tap|setInputFiles|pressSequentially|focus|blur)\(|\bkeyboard\.|\bmouse\.|\b(?:probe|status|rules|api|fetch)\(|\brequest\.\w+\(`)

	retryBlocks = []*regexp.Regexp{
		regexp.MustCompile(`(?s)expect\(async \(\) => \{(.*?)\}\)\.toPass\(`),
		regexp.MustCompile(`(?s)expect\.poll\((.*?)\)\.(?:not\.)?to\w+\(`),
		regexp.MustCompile(`(?s)(?:\bwhile\s*\(|\bfor\s*\(\s*;\s*;\s*\))(.*?)\n\s*\}`),
	}

	tsShapes = map[string]*regexp.Regexp{
		"wait":             regexp.MustCompile(`\bwaitForTimeout\(`),
		"sleep":            regexp.MustCompile(`(?:^|[^.\w])setTimeout\(`),
		"force":            regexp.MustCompile(`\bforce:\s*true`),
		"dispatch":         regexp.MustCompile(`\.dispatchEvent\(`),
		"focus":            regexp.MustCompile(`\.(?:focus|blur)\(\)`),
		"script-state":     regexp.MustCompile(`\b(?:evaluate|addInitScript)\([^\n]*?(?:[^=!<>]=[^=>]|\.click\(|setItem\(|removeItem\(|scroll(?:To|By)\(|\.focus\(|\.blur\()`),
		"click-then-leave": regexp.MustCompile(`\.click\([^)\n]*\)\n\s*await [\w.]+\.(?:reload|goto|close)\(`),
	}
	goShapes = map[string]*regexp.Regexp{"sleep": regexp.MustCompile(`\btime\.Sleep\(`)}
	shShapes = map[string]*regexp.Regexp{"sleep": regexp.MustCompile(`(?m)^\s*sleep\s`)}
)

// (file, rule) -> count and why it is not a workaround.
var allowedTestShapes = map[[2]string]struct {
	n   int
	why string
}{
	{"e2e/tests/helpers.ts", "script-state"}:       {1, "unlock() plants the token where the gate keeps it, for tests about something other than the gate; the gate is typed in gate, sso, auth and repeat specs"},
	{"e2e/tests/replicas.spec.ts", "script-state"}: {1, "plants the replicas' token, as unlock() does for the main console"},
	{"e2e/tests/rules.spec.ts", "script-state"}:    {1, "the second page of the beforeunload test starts signed in, as unlock() does"},
	{"e2e/tests/gate.spec.ts", "script-state"}:     {1, "the precondition under test: a token remembered from an earlier day that no longer works"},
	{"e2e/docs/tour.spec.ts", "script-state"}:      {2, "the tour signs in as unlock() does, and scrolls to the top for the screenshot's framing"},
	{"e2e/docs/tour.spec.ts", "focus"}:             {1, "removes the focus ring before a screenshot; nothing is asserted after it"},
	{"e2e/tests/bans.spec.ts", "focus"}:            {1, "the subject is focus surviving the poll; Tab would put it on the same button"},
	{"e2e/tests/tiles.spec.ts", "focus"}:           {1, "the subject is focus surviving the poll; Tab would put it on the same tile"},
	{"e2e/tests/replicas.spec.ts", "retry-action"}: {5, "replication is eventually consistent by design (a 30 s Redis refresh): the probe is re-sent until the other replica has refreshed"},
	{"e2e/tests/global-setup.ts", "retry-action"}:  {1, "waits for the consoles Traefik's file provider adds; touches no page"},
	{"e2e/tests/global-setup.ts", "sleep"}:         {1, "the pause of that readiness loop"},
	{"e2e/tests/global-setup.ts", "force"}:         {1, "node:fs rmSync's option, not a forced click"},
	{"e2e/tests/auth.spec.ts", "retry-action"}:     {1, "waits for the basicAuth console Traefik's file provider adds; touches no page"},
	{"e2e/tests/auth.spec.ts", "sleep"}:            {1, "the pause of that readiness loop"},
	{"admin_test.go", "sleep"}:                     {1, "the pause of a deadline poll for an asynchronous write"},
	{"audit_test.go", "sleep"}:                     {2, "the pause of a deadline poll for an asynchronous lookup, and between lookups that must not repeat it"},
	{"notify_test.go", "sleep"}:                    {6, "pauses of deadline polls for asynchronous deliveries, and of the queue drain"},
	{"settings_test.go", "sleep"}:                  {4, "pauses of deadline polls for an asynchronous lookup and a debounced write"},
	{"store_redis_test.go", "sleep"}:               {1, "the pause of a deadline poll for a Redis publish"},
	{"enforce_test.go", "sleep"}:                   {1, "separates two ban timestamps, which the test compares"},
	{"examples/rules-check.sh", "sleep"}:           {1, "the pause of the readiness loop after the restart"},
	{"examples/notify-check.sh", "sleep"}:          {5, "pauses of delivery polls and the router wait; a window in which rejects must NOT be delivered; the dead webhook's delivery timeout, after which a panic would have happened"},
}

func tsFindings(src string) map[string]int {
	found := map[string]int{}
	for name, re := range tsShapes {
		if n := len(re.FindAllString(src, -1)); n > 0 {
			found[name] = n
		}
	}
	for _, re := range retryBlocks {
		for _, m := range re.FindAllStringSubmatch(src, -1) {
			if testAction.MatchString(m[1]) {
				found["retry-action"]++
			}
		}
	}
	return found
}

func shapeFindings(shapes map[string]*regexp.Regexp, src string) map[string]int {
	found := map[string]int{}
	for name, re := range shapes {
		if n := len(re.FindAllString(src, -1)); n > 0 {
			found[name] = n
		}
	}
	return found
}

func TestNoTestStepAUserWouldNotTake(t *testing.T) {
	var files []string
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "node_modules" || d.Name() == ".git") {
			return filepath.SkipDir
		}
		if p == "hygiene_test.go" { // its own examples
			return nil
		}
		if (strings.HasPrefix(p, "e2e/") && strings.HasSuffix(p, ".ts")) || strings.HasSuffix(p, "_test.go") ||
			(strings.HasPrefix(p, "examples/") && strings.HasSuffix(p, ".sh")) {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	counted := map[string]int{}
	found := map[[2]string]int{}
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var f map[string]int
		switch {
		case strings.HasSuffix(p, ".ts"):
			f, counted["ts"] = tsFindings(string(b)), counted["ts"]+1
		case strings.HasSuffix(p, ".go"):
			f, counted["go"] = shapeFindings(goShapes, string(b)), counted["go"]+1
		default:
			f, counted["sh"] = shapeFindings(shShapes, string(b)), counted["sh"]+1
		}
		for rule, n := range f {
			found[[2]string{p, rule}] = n
		}
	}
	if counted["ts"] < 20 || counted["go"] < 18 || counted["sh"] < 4 {
		t.Fatalf("scanned only %v files; is the walk still right?", counted)
	}
	for key, n := range found {
		if allowed := allowedTestShapes[key]; allowed.n != n {
			t.Errorf("%s: %d × %s, allowed %d. A step a user would not take hides a product bug; fix the product, or list it with its reason.",
				key[0], n, key[1], allowed.n)
		}
	}
	for key, allowed := range allowedTestShapes {
		if allowed.n > 0 && found[key] == 0 {
			t.Errorf("%s no longer has %s; take it off allowedTestShapes", key[0], key[1])
		}
		if allowed.n > 0 && len(allowed.why) < 20 {
			t.Errorf("%s/%s is allowed without a reason", key[0], key[1])
		}
	}
}

func TestTheHygieneScanCatchesWhatItIsFor(t *testing.T) {
	for src, want := range map[string]map[string]int{
		"await page.waitForTimeout(300)":                                   {"wait": 1},
		"await new Promise((r) => setTimeout(r, 500))":                     {"sleep": 1},
		"await row.click({ force: true })":                                 {"force": 1},
		"await el.dispatchEvent('click')":                                  {"dispatch": 1},
		"await button.focus()\nawait field.blur()":                         {"focus": 2},
		"await box.evaluate((el) => (el.scrollTop = 300))":                 {"script-state": 1},
		"await page.evaluate(() => window.scrollTo(0, 0))":                 {"script-state": 1},
		"await page.evaluate(() => document.querySelector('b').click())":   {"script-state": 1},
		"await page.addInitScript((t) => sessionStorage.setItem('k', t))":  {"script-state": 1},
		"  await save(page).click()\n  await page.reload()\n":              {"click-then-leave": 1},
		"await expect(async () => {\n  await tile.click()\n}).toPass()":    {"retry-action": 1},
		"await expect.poll(() => probe(request, ip, '/')).toBe(403)":       {"retry-action": 1},
		"while (!(await ok())) {\n  await page.keyboard.press('Enter')\n}": {"retry-action": 1},
		// What is not a workaround: reading, polling for what the page shows,
		// a click followed by what the user sees.
		"expect(await box.evaluate((el) => el.scrollTop)).toBe(0)":                                       {},
		"await expect.poll(() => box.evaluate((el) => el.scrollTop)).toBe(0)":                            {},
		"await page.evaluate(() => Date.now())":                                                          {},
		"  await save(page).click()\n  await expect(toast(page)).toBeVisible()\n  await page.reload()\n": {},
		"for (const name of ['a', 'b']) await chip(page, name).click()":                                  {},
	} {
		if got := tsFindings(src); !equalCounts(got, want) {
			t.Errorf("%q: %v, want %v", src, got, want)
		}
	}
	if got := shapeFindings(goShapes, "time.Sleep(50 * time.Millisecond)"); got["sleep"] != 1 {
		t.Errorf("a Go sleep was not caught: %v", got)
	}
	if got := shapeFindings(shShapes, "  sleep 3\nfor _ in $(seq 1 30); do"); got["sleep"] != 1 {
		t.Errorf("a shell sleep was not caught: %v", got)
	}
}

func equalCounts(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
