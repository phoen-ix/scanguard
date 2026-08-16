package scanguard

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const headerXFF = "X-Forwarded-For"

// resolution is the outcome of deciding who a request actually came from.
type resolution struct {
	// client is the address we believe is the real client.
	client netip.Addr
	// key is client aggregated to the configured prefix width. It is what bans and
	// counters are stored under.
	key netip.Prefix
	// peer is the TCP peer that opened the connection to Traefik.
	peer netip.Addr
	// source records how client was determined, for the audit log.
	source string
	// bannable is false when we could not identify the client with enough
	// confidence to act. Refusing to ban is always the safe direction: the
	// alternative is banning your own CDN edge or load balancer and taking the
	// site down for every legitimate user at once.
	bannable bool
}

// resolve determines the true client address for a request.
//
// Traefik never rewrites req.RemoteAddr — its forwardedheaders middleware only
// mutates headers — so RemoteAddr is always the TCP peer: the CDN edge, the load
// balancer, or the Kubernetes node when one of those is in front. PROXY protocol
// on the entrypoint is the only mechanism that actually replaces it.
//
// The rule enforced here: forwarded headers are believed only when the peer that
// sent them is itself listed in clientIP.trustedProxies. Anything else is a
// remote "ban any IP you name" primitive, which is a live vulnerability in the
// most popular comparable plugin.
func (s *settings) resolve(req *http.Request) resolution {
	res := resolution{source: "peer"}

	peer, ok := parsePeer(req.RemoteAddr)
	if !ok {
		// Without a parseable peer there is nothing safe to act on.
		warnOnce(s.instanceName, "unparseable-remoteaddr",
			"could not parse req.RemoteAddr; no source can be identified for this route",
			map[string]interface{}{"remoteAddr": req.RemoteAddr})
		return res
	}
	res.peer = peer
	res.client = peer
	res.key = banKey(peer, s.ipv4Prefix, s.ipv6Prefix)
	res.bannable = true

	// The common case: Traefik is the edge, nothing is trusted, the peer is the
	// client. Costs one length check.
	if len(s.trustedProxies) == 0 {
		return res
	}
	if !containsAddr(s.trustedProxies, peer) {
		return res
	}

	// The peer is a trusted proxy, so its forwarded headers may be believed.
	if s.clientIPHeader != "" {
		if addr, found := firstAddrIn(req.Header.Get(s.clientIPHeader)); found {
			res.client = addr
			res.key = banKey(addr, s.ipv4Prefix, s.ipv6Prefix)
			res.source = s.clientIPHeader
			return res
		}
	}

	// Fall back to X-Forwarded-For, read right to left, skipping hops that are
	// themselves trusted proxies. This mirrors Traefik's own pool strategy: the
	// rightmost untrusted entry is the last hop we cannot vouch for, and therefore
	// the furthest we can attribute the request.
	//
	// Note that at middleware time XFF does NOT yet contain Traefik's own hop —
	// Traefik appends that during proxying — so depth-counting logic borrowed from
	// backend-side reasoning counts a different chain than the backend sees.
	sawHeader := false
	for _, raw := range req.Header.Values(headerXFF) {
		if raw != "" {
			sawHeader = true
		}
		parts := strings.Split(raw, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			addr, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
			if err != nil {
				continue
			}
			addr = addr.Unmap().WithZone("")
			if containsAddr(s.trustedProxies, addr) {
				continue
			}
			res.client = addr
			res.key = banKey(addr, s.ipv4Prefix, s.ipv6Prefix)
			res.source = headerXFF
			return res
		}
	}

	if !sawHeader && s.clientIPHeader == "" {
		// Almost always a Traefik-side misconfiguration rather than a scanguard one.
		// If entryPoints.<name>.forwardedHeaders.trustedIPs is not set, Traefik
		// DELETES every X-Forwarded-* header before any middleware runs, so a
		// correctly-configured scanguard sees nothing and silently bans nobody.
		warnOnce(s.instanceName, "no-forwarded-headers",
			"the peer is a trusted proxy but the request carries no forwarded headers; "+
				"set entryPoints.<name>.forwardedHeaders.trustedIPs (or enable proxyProtocol) "+
				"on the Traefik entrypoint, otherwise Traefik strips those headers before scanguard runs "+
				"and no client can ever be identified",
			map[string]interface{}{"peer": peer.String()})
	}

	// The peer is trusted and no untrusted client could be identified. Banning the
	// peer would ban the proxy itself, so this request is observed but not
	// attributable.
	res.client = peer
	res.key = banKey(peer, s.ipv4Prefix, s.ipv6Prefix)
	res.source = "trusted-proxy-unattributable"
	res.bannable = false
	return res
}

// parsePeer extracts the address from a net/http RemoteAddr. It accepts
// "1.2.3.4:5678", "[::1]:5678" and a bare address, and drops any zone so that
// two connections from the same host compare equal.
func parsePeer(remoteAddr string) (netip.Addr, bool) {
	if remoteAddr == "" {
		return netip.Addr{}, false
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

// firstAddrIn parses the leftmost address from a possibly comma-separated header
// value. Single-value client-IP headers such as Cf-Connecting-Ip carry exactly
// one address, but a misbehaving upstream may append.
func firstAddrIn(value string) (netip.Addr, bool) {
	if value == "" {
		return netip.Addr{}, false
	}
	if idx := strings.IndexByte(value, ','); idx >= 0 {
		value = value[:idx]
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap().WithZone(""), true
}

// containsAddr reports whether addr falls inside any of the prefixes.
func containsAddr(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// banKey aggregates an address to the configured prefix width.
//
// This is both a correctness and a memory-safety measure. Banning a single IPv6
// /128 is close to useless because one host normally owns an entire /64 and can
// rotate through it freely. Aggregating before insertion also bounds the state
// table by prefix count rather than by address count, which is what stops a
// distributed or /64-wide scan from exhausting memory.
func banKey(addr netip.Addr, v4Bits, v6Bits int) netip.Prefix {
	addr = addr.Unmap().WithZone("")
	bits := v6Bits
	if addr.Is4() {
		bits = v4Bits
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.PrefixFrom(addr, addr.BitLen())
	}
	return p
}
