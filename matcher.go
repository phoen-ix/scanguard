package scanguard

import (
	"fmt"
	"regexp"
	"strings"
)

// matcher tests a string against many patterns using a single compiled regexp.
//
// This shape is deliberate. Traefik interprets this plugin with Yaegi, so a Go
// loop over N compiled regexps costs N interpreted iterations per request, while
// one alternation regexp costs a single call into natively-compiled regexp code.
// Compiling happens once in New(); the request path only ever calls match.
//
// Measured cost, and a deliberate decision not to optimise further:
//
// An alternation with no literal prefix has to attempt a match at every position
// of the subject, so cost scales with subject length. Matching the 48 default
// signatures against a typical path costs ~3µs; matching the 22 default
// user-agent patterns against a full browser user-agent costs ~65µs interpreted,
// which is the largest single cost on the request path.
//
// Guarding the regex with a literal-substring pre-filter measures 3.2x faster
// interpreted (65µs -> 20µs) for ordinary traffic. It is not implemented, because
// doing it correctly means deriving each pattern's required literal from the
// regex AST, including across alternations where a branch may have none. A
// pre-filter that gets that wrong does not fail loudly — it silently stops the
// matcher from ever seeing a scanner. Given that a request costs single-digit
// microseconds of this either way at the traffic this is built for, a correct
// simple matcher beats a fast subtle one.
//
// If you do revisit it: gate the pre-filter on being able to prove a required
// literal for every pattern, and fall back to the plain regex otherwise.
type matcher struct {
	re       *regexp.Regexp
	patterns []string
}

// newMatcher compiles patterns into one case-insensitive alternation. It returns
// (nil, nil) for an empty pattern list, and a nil *matcher matches nothing.
//
// Each pattern is compiled individually first so that a configuration error names
// the offending pattern instead of reporting a syntax error in a 4 KB alternation
// nobody wrote by hand.
func newMatcher(field string, patterns []string) (*matcher, error) {
	cleaned := make([]string, 0, len(patterns))
	seen := make(map[string]struct{}, len(patterns))
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		if _, err := regexp.Compile(p); err != nil {
			return nil, fmt.Errorf("%s: %q is not a valid regular expression: %w", field, p, err)
		}
		cleaned = append(cleaned, p)
	}
	if len(cleaned) == 0 {
		return nil, nil
	}

	grouped := make([]string, 0, len(cleaned))
	for _, p := range cleaned {
		grouped = append(grouped, "(?:"+p+")")
	}
	re, err := regexp.Compile("(?i)" + strings.Join(grouped, "|"))
	if err != nil {
		return nil, fmt.Errorf("%s: patterns could not be combined: %w", field, err)
	}
	// Deliberately NOT calling re.Longest(). All the request path asks is "does
	// anything match", and leftmost-first lets the engine stop at the first hit
	// and keep its one-pass optimisations. Leftmost-longest would force it to keep
	// scanning for a longer alternative it has no use for.
	return &matcher{re: re, patterns: cleaned}, nil
}

// match reports whether s matches any configured pattern. A nil matcher never matches.
func (m *matcher) match(s string) bool {
	if m == nil {
		return false
	}
	return m.re.MatchString(s)
}

// which returns the first individual pattern that matches s, for reporting which
// rule fired. It is deliberately NOT on the hot path: it recompiles nothing but
// does walk the pattern list, so it runs only after match has already said yes.
func (m *matcher) which(s string) string {
	if m == nil {
		return ""
	}
	for _, p := range m.patterns {
		re, err := regexp.Compile("(?i)" + p)
		if err != nil {
			continue
		}
		if re.MatchString(s) {
			return p
		}
	}
	return ""
}

// size reports how many patterns the matcher holds.
func (m *matcher) size() int {
	if m == nil {
		return 0
	}
	return len(m.patterns)
}

// list returns a copy of the configured patterns, for the admin API.
func (m *matcher) list() []string {
	if m == nil {
		return []string{}
	}
	out := make([]string, len(m.patterns))
	copy(out, m.patterns)
	return out
}
