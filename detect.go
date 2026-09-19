package scanguard

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Detector names. These appear in the event log, the admin UI, webhook payloads
// and AbuseIPDB category mapping, so they are part of the public interface.
const (
	detectorSignature  = "signature"
	detectorHoneypot   = "honeypot"
	detectorUserAgent  = "user-agent"
	detectorCrawler    = "crawler"
	detectorBadPaths   = "bad-paths"
	detectorBruteForce = "brute-force"
	detectorRateAbuse  = "rate-abuse"
	detectorPayload    = "payload"
	detectorReputation = "reputation"
	detectorManual     = "manual"
)

// detection is a single positive result from one detector.
type detection struct {
	detector string
	rule     string
}

// exempt reports whether a request must never be acted on, and why.
//
// Checked before any detector runs and before any ban is written, so a mistake in
// a detection rule cannot lock out an allowlisted source. Trusted proxies are
// implicitly exempt: banning your own CDN edge or load balancer takes the site
// down for every legitimate user at once, which is a far worse outcome than
// missing a scanner.
// The reason returned alongside it names WHICH rule granted the exemption. The
// console tallies these: "1 exempt" with no way to ask which rule produced it is
// indistinguishable from a misconfigured allowlist quietly exempting everything.
const (
	exemptUnattributable = "unattributable"
	exemptTrustedProxy   = "trusted-proxy"
	exemptCIDR           = "allowlist-cidr"
	exemptPath           = "allowlist-path"
	exemptUserAgent      = "allowlist-user-agent"
	exemptCrawler        = "crawler-exempt"
)

func (s *settings) exempt(req *http.Request, res resolution) (string, bool) {
	if !res.bannable {
		return exemptUnattributable, true
	}
	if containsAddr(s.trustedProxies, res.client) {
		return exemptTrustedProxy, true
	}
	if containsAddr(s.allowCIDRs, res.client) {
		return exemptCIDR, true
	}
	if s.allowPaths != nil && s.allowPaths.match(req.URL.Path) {
		return exemptPath, true
	}
	if s.allowUA != nil && s.allowUA.match(req.UserAgent()) {
		return exemptUserAgent, true
	}
	return "", false
}

// exemptFor is exempt plus the per-router crawler policy. Request-path callers
// want this one; exempt itself stays as the policy-free check so its existing
// callers and tests are unaffected.
//
// The crawler test comes last so the reason string still names the more specific
// rule when both apply — a crawler arriving from a trusted proxy reports
// "trusted-proxy", as it did before this was per-router.
//
// Being here rather than in detectRequest is deliberate and load-bearing: exempt
// is consulted BEFORE the ban lookup, so "exempt" forgives a crawler that some
// other router already banned. Moving it later would silently turn that into
// "detected nothing, but still refused", which is the whole failure this policy
// exists to avoid.
func (s *settings) exemptFor(req *http.Request, res resolution, crawlers string) (string, bool) {
	if reason, ok := s.exempt(req, res); ok {
		return reason, true
	}
	if crawlers == crawlersExempt && s.crawlerMatcher != nil {
		if ua := req.UserAgent(); ua != "" && s.crawlerMatcher.match(ua) {
			return exemptCrawler, true
		}
	}
	return "", false
}

// detectRequest runs the detectors that can decide before the backend is touched.
// A hit here means the request is never proxied at all, which is the whole point:
// a probe for /wp-login.php should cost the backend nothing.
func (rt *runtime) detectRequest(s *settings, crawlers string, req *http.Request, res resolution, now time.Time) *detection {
	path := req.URL.Path

	// Honeypots first: one map lookup, and a hit is unambiguous. No legitimate
	// client requests a path that exists only as a trap.
	if s.honeyEnabled {
		if _, hit := s.honeyPaths[path]; hit {
			return &detection{detector: detectorHoneypot, rule: path}
		}
	}

	// One pre-compiled alternation regexp over every signature. Under Yaegi a loop
	// over N regexps costs N interpreted iterations; this costs one native call.
	if s.sigEnabled && s.sigMatcher.match(path) && !s.sigExclude.match(path) {
		return &detection{detector: detectorSignature, rule: s.sigMatcher.which(path)}
	}

	if s.uaEnabled {
		ua := req.UserAgent()
		if ua == "" {
			if s.uaBanEmpty {
				return &detection{detector: detectorUserAgent, rule: "(no user-agent)"}
			}
		} else if s.uaMatcher.match(ua) {
			return &detection{detector: detectorUserAgent, rule: s.uaMatcher.which(ua)}
		} else if (crawlers == crawlersBan || crawlers == crawlersBlock) &&
			s.crawlerMatcher != nil && s.crawlerMatcher.match(ua) {
			// Reported as its own detector, not as "user-agent": a commercial
			// crawler refused by policy is not the same finding as a scanner, and
			// filing them together made the detector statistics lie. What the
			// caller does with this — ban, or refuse on this router only — depends
			// on the policy; see handler.ServeHTTP.
			return &detection{detector: detectorCrawler, rule: s.crawlerMatcher.which(ua)}
		}
	}

	if s.payload.Enabled {
		if s.payload.ScanQuery {
			// Both forms are checked, and both are necessary. The raw query is where
			// encoded-traversal patterns like %2e%2e%2f live; the decoded query is
			// where everything else does, because "UNION%20SELECT" on the wire only
			// looks like SQL injection once the percent-encoding is removed. Checking
			// only one of the two is trivially evaded by choosing the other encoding.
			if q := req.URL.RawQuery; q != "" {
				if s.payloadMatch.match(q) {
					return &detection{detector: detectorPayload, rule: s.payloadMatch.which(q)}
				}
				if decoded := unescapeLenient(q); decoded != q && s.payloadMatch.match(decoded) {
					return &detection{detector: detectorPayload, rule: s.payloadMatch.which(decoded)}
				}
			}
		}
		if s.payload.ScanBody {
			if body, ok := peekBody(req, s.payload.MaxBodyBytes); ok && s.payloadMatch.match(body) {
				return &detection{detector: detectorPayload, rule: s.payloadMatch.which(body)}
			}
		}
	}

	if s.rate.Enabled && rt.counters.noteRequest(res.key, now, s.rate.RPS, s.rate.Burst) {
		return &detection{
			detector: detectorRateAbuse,
			rule:     fmt.Sprintf("more than %d req/s (burst %d)", s.rate.RPS, s.rate.Burst),
		}
	}

	// Reputation is consulted from cache only. The lookup itself happens in the
	// background: a third-party API must never be able to add latency to, or stall,
	// a user's request.
	if score, ok := rt.notifier().score(res.client.String()); ok {
		if threshold := rt.notifier().minConfidence(); score >= threshold {
			return &detection{
				detector: detectorReputation,
				rule:     fmt.Sprintf("abuseipdb confidence %d (threshold %d)", score, threshold),
			}
		}
	}

	return nil
}

// detectResponse runs the detectors that need to know what the backend answered.
// These necessarily act one request late: the decision for request N can only be
// enforced from request N+1 onwards.
func (rt *runtime) detectResponse(s *settings, req *http.Request, res resolution, status int, now time.Time) *detection {
	path := req.URL.Path

	if s.brute.Enabled && s.bruteCodes.has(status) {
		if s.brutePaths == nil || s.brutePaths.match(path) {
			if rt.counters.noteAuthFailure(res.key, now, s.brute.Capacity, s.bruteWindow) {
				return &detection{
					detector: detectorBruteForce,
					rule:     fmt.Sprintf("%d authentication failures within %s", s.brute.Capacity, s.bruteWindow),
				}
			}
		}
	}

	if s.badPaths.Enabled && s.badPathsCodes.has(status) {
		if rt.counters.noteBadPath(res.key, path, now, s.badPaths.Capacity, s.badPathsLeak) {
			return &detection{
				detector: detectorBadPaths,
				rule:     fmt.Sprintf("%d distinct failing paths (leak %s)", s.badPaths.Capacity, s.badPathsLeak),
			}
		}
	}

	return nil
}

// unescapeLenient percent-decodes a query string the way a permissive backend
// would: every valid %XX escape and every '+' is decoded, and anything malformed
// is left exactly as it was.
//
// url.QueryUnescape refuses the WHOLE string at the first malformed escape, and
// net/url never validates RawQuery, so "?z=%zz&id=1%20UNION%20SELECT..." switched
// the decoded check off with three characters: the raw form does not match because
// %20 is not whitespace, and the decoded form was never looked at. The comment
// above the call says checking only one form is trivially evaded; a strict decoder
// collapsed both checks into one. Decoding leniently keeps both in force.
func unescapeLenient(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+':
			out = append(out, ' ')
		case c == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]):
			out = append(out, unHex(s[i+1])<<4|unHex(s[i+2]))
			i += 2
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unHex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// peekBody reads up to max bytes of the request body for payload inspection and
// puts them back so the backend still receives the full request.
//
// Deliberately conservative. Bodies of unknown length (chunked transfer) and
// bodies larger than the limit are skipped entirely rather than partially read:
// buffering an upload of unknown size inside the reverse proxy is exactly the
// memory-exhaustion bug this plugin exists to prevent, and a partial read that
// silently truncates a large POST would corrupt it.
func peekBody(req *http.Request, max int) (string, bool) {
	if req.Body == nil || req.Body == http.NoBody {
		return "", false
	}
	if req.ContentLength <= 0 || req.ContentLength > int64(max) {
		return "", false
	}

	buf, err := io.ReadAll(io.LimitReader(req.Body, int64(max)))
	if err != nil {
		return "", false
	}
	_ = req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(buf))
	return string(buf), true
}
