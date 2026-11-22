package scanguard

// e2e/COVERAGE.md states counts: how many routes and console items its
// extraction commands find, how many items each section maps, and the totals.
// All of them were kept by hand and had drifted (10 cases where serveAdmin had
// 11, 44 console items where the command, itself broken, printed 40). This
// reads both sides.

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestCoverageCountsAreTrue(t *testing.T) {
	b, err := os.ReadFile("e2e/COVERAGE.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)

	// The inventory: each count beside the command that produces it.
	inventory := regexp.MustCompile(`# admin routes \(serveAdmin\) - (\d+) cases, (\d+) paths\ngrep -oE '([^']+)' admin.go\n# console: [^\n]* - (\d+) items\ngrep -oE '([^']+)' admin_ui.go`).FindStringSubmatch(doc)
	if inventory == nil {
		t.Fatal("COVERAGE.md: the inventory block is not where this test reads it")
	}
	adminSrc, _ := os.ReadFile("admin.go")
	uiSrc, _ := os.ReadFile("admin_ui.go")
	cases := regexp.MustCompile("(?m)"+inventory[3]).FindAllString(string(adminSrc), -1)
	paths := regexp.MustCompile(`"[^"]*"`).FindAllString(strings.Join(cases, " "), -1)
	items := regexp.MustCompile("(?m)"+inventory[5]).FindAllString(string(uiSrc), -1)
	for _, c := range []struct {
		what   string
		stated string
		found  int
	}{{"admin route cases", inventory[1], len(cases)}, {"admin route paths", inventory[2], len(paths)}, {"console items", inventory[4], len(items)}} {
		if c.stated != strconv.Itoa(c.found) {
			t.Errorf("COVERAGE.md says %s %s, the command finds %d", c.stated, c.what, c.found)
		}
	}

	// Each section's count is its ✅ and ❌ marks; the totals are their sums.
	sections := regexp.MustCompile(`(?m)^## (.+) \((\d+)[,)]`).FindAllStringSubmatchIndex(doc, -1)
	if len(sections) < 6 {
		t.Fatalf("found %d counted sections", len(sections))
	}
	var total, done, open int
	for i, s := range sections {
		end := len(doc)
		if i+1 < len(sections) {
			end = sections[i+1][0]
		}
		body := doc[s[1]:end]
		yes, no := strings.Count(body, "✅"), strings.Count(body, "❌")
		if stated, _ := strconv.Atoi(doc[s[4]:s[5]]); stated != yes+no {
			t.Errorf("COVERAGE.md section %q says %d, it has %d marks (✅ %d, ❌ %d)", doc[s[2]:s[3]], stated, yes+no, yes, no)
		}
		total, done, open = total+yes+no, done+yes, open+no
	}
	want := "**Totals: " + strconv.Itoa(total) + " items — ✅ " + strconv.Itoa(done) + ", ❌ " + strconv.Itoa(open) + "** (" +
		"(a) " + strconv.Itoa(strings.Count(doc, "❌ (a)")) + ", (c) " + strconv.Itoa(strings.Count(doc, "❌ (c)")) +
		", (d) " + strconv.Itoa(strings.Count(doc, "❌ (d)")) + ")."
	if !strings.Contains(doc, want) {
		t.Errorf("COVERAGE.md totals: want %q", want)
	}
}
