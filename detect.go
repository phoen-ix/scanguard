package scanguard

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Detector names. These appear in the event log, the admin UI, webhook payloads
// and AbuseIPDB category mapping, so they are part of the public interface.
const (
	detectorSignature  = "signature"
	detectorHoneypot   = "honeypot"
	detectorUserAgent  = "user-agent"
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

// detectRequest runs the detectors that can decide before the backend is touched.
// A hit here means the request is never proxied at all, which is the whole point:
// a probe for /wp-login.php should cost the backend nothing.
func (rt *runtime) detectRequest(s *settings, req *http.Request, res resolution, now time.Time) *detection {
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
				if decoded, err := url.QueryUnescape(q); err == nil && decoded != q && s.payloadMatch.match(decoded) {
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
	if score, ok := rt.notifier.score(res.client.String()); ok {
		if threshold := rt.notifier.minConfidence(); score >= threshold {
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
