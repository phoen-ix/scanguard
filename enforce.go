package scanguard

import (
	"fmt"
	"net/http"
	"net/netip"
	"time"
)

// banDuration picks the rung of the escalation ladder for a given offence count.
// Offences beyond the end of the ladder stay on the last rung, which is how a
// ladder ending in "0" becomes a permanent ban for persistent offenders.
func (s *settings) banDuration(offence int) time.Duration {
	if len(s.escalation) == 0 {
		return time.Hour
	}
	idx := offence - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s.escalation) {
		idx = len(s.escalation) - 1
	}
	return s.escalation[idx]
}

// activeBan reads the ban currently in force for a source, from whichever list
// this instance writes to. A dry run keeps its bans in the shadow list.
func (rt *runtime) activeBan(s *settings, key netip.Prefix, now time.Time) (Ban, bool) {
	if s.dryRun {
		return rt.shadow.get(key, now)
	}
	return rt.store().get(key, now)
}

// applyBan records a ban for a detected source and returns it.
//
// In dry-run mode everything happens except the write: the event is logged, the
// UI shows it, notifications fire with DryRun set. That is what makes dry-run
// useful for tuning rules on live traffic — you see exactly what would have been
// banned without banning anybody.
func (rt *runtime) applyBan(s *settings, res resolution, det *detection, req *http.Request, now time.Time) Ban {
	offence, fresh := rt.counters.recordOffence(res.key, now, s.decay, s.banDuration)
	if !fresh {
		// Another request from the same burst already banned this source. Carrying
		// on would overwrite that ban with an identical one and emit a second ban
		// event: sixteen concurrent probes produced sixteen "banned source" lines
		// and sixteen console entries for what is one ban.
		if existing, ok := rt.activeBan(s, res.key, now); ok {
			return existing
		}
		return Ban{}
	}
	duration := s.banDuration(offence)

	ban := Ban{
		Key:      res.key.String(),
		Detector: det.detector,
		Rule:     det.rule,
		Reason:   det.detector + ": " + det.rule,
		Created:  now.UTC(),
		Offences: offence,
		LastPath: truncate(req.URL.Path, 512),
		LastUA:   truncate(req.UserAgent(), 256),
		Country:  rt.geo().lookup(res.client.String()),
	}
	if duration != permanent {
		ban.Expires = now.Add(duration).UTC()
	}
	// The ban window was recorded inside recordOffence, in the same critical
	// section as the increment — see the comment there. Decay is measured from the
	// end of the ban, not from the offence that caused it, otherwise the ban's own
	// duration counts as good behaviour and the ladder cannot climb past the rung
	// whose length equals the decay period.

	rt.stats.Detections.Add(1)
	rt.topDetectors.add(det.detector)
	// The rule, not just the detector name. "signature fired 1027 times" cannot
	// tell you which of 61 signatures earned its place and which have never
	// matched anything; the pattern that fired can.
	rt.topRules.add(det.detector + ": " + det.rule)

	rt.putBan(s, ban)

	rt.record(Event{
		Kind:     eventBan,
		Key:      ban.Key,
		Client:   res.client.String(),
		Detector: det.detector,
		Rule:     det.rule,
		Method:   req.Method,
		Host:     req.Host,
		Path:     req.URL.Path,
		UA:       req.UserAgent(),
		BanFor:   formatDuration(duration),
		DryRun:   s.dryRun,
		Country:  ban.Country,
	})

	// host, method and ua because the access log may have no Host column: without
	// them a ban on a multi-site Traefik could not be traced to the site it hit.
	logWarn(rt.name, "banned source", map[string]interface{}{
		"key":      ban.Key,
		"client":   res.client.String(),
		"detector": det.detector,
		"rule":     det.rule,
		"host":     truncate(req.Host, 253),
		"method":   req.Method,
		"path":     req.URL.Path,
		"ua":       ban.LastUA,
		"offence":  offence,
		"duration": formatDuration(duration),
		"dryRun":   s.dryRun,
		"ipSource": res.source,
	})

	if s.subnet.Enabled {
		rangeKey := banKey(res.client, s.subnet.IPv4Prefix, s.subnet.IPv6Prefix)
		if n, trip := rt.counters.noteSubnetBan(rangeKey, res.key, now, s.subnet.Threshold, s.subnetWindow, s.dryRun); trip {
			rt.applySubnetBan(s, rangeKey, n, res, req, now)
		}
	}
	return ban
}

// putBan writes a ban to the list this instance enforces from.
//
// A dry run records the ban in the shadow list instead of the real one. It is
// still a ban as far as every counter and every report is concerned — it just
// cannot reject anything, and it never reaches disk or Redis. Without this the
// source is re-detected on its next request and the ladder runs away; see the
// comment on runtime.shadow.
func (rt *runtime) putBan(s *settings, ban Ban) {
	if s.dryRun {
		if err := rt.shadow.put(ban); err != nil {
			logWarn(rt.name, "could not record dry-run ban", map[string]interface{}{
				"key":   ban.Key,
				"error": err.Error(),
			})
			return
		}
		rt.stats.BansIssued.Add(1)
		return
	}
	if err := rt.store().put(ban); err != nil {
		logWarn(rt.name, "could not record ban", map[string]interface{}{
			"key":   ban.Key,
			"error": err.Error(),
		})
		return
	}
	rt.stats.BansIssued.Add(1)
	// Persist immediately on a ban-list change. Counter updates deliberately do
	// not trigger a write — rewriting the snapshot on every counter bump under a
	// 404 flood would burn through IOPS or an SD card.
	if fs, ok := rt.store().(*fileStore); ok {
		if err := fs.flush(); err != nil {
			logWarn(rt.name, "could not persist state", map[string]interface{}{"error": err.Error()})
		}
	}
}

// applySubnetBan bans rangeKey once enforcement.subnet.threshold of its sources
// have been banned within the window. Only applyBan calls it, so only automatic
// bans count: banManual and the crawler "block" policy never get there.
//
// The range climbs its own escalation ladder, keyed by the range. The event has
// no Client, so reportAbuse skips it: a range is never reported to AbuseIPDB, and
// the member whose ban tripped it has already been reported on its own.
func (rt *runtime) applySubnetBan(s *settings, rangeKey netip.Prefix, members int, res resolution, req *http.Request, now time.Time) {
	// The same refusal an operator's range ban gets: never over the allowlist or
	// a trusted proxy. Said once per range, because the range keeps tripping.
	if status, msg := refuseDangerousBan(s, rangeKey); status != 0 {
		warnOnce(rt.name, "subnet-refused:"+rangeKey.String(), "range escalation skipped a protected range",
			map[string]interface{}{"key": rangeKey.String(), "reason": msg})
		return
	}
	offence, fresh := rt.counters.recordOffence(rangeKey, now, s.decay, s.banDuration)
	if !fresh {
		return
	}
	duration := s.banDuration(offence)
	rule := fmt.Sprintf("%d sources in %s within %s", s.subnet.Threshold, rangeKey, formatDuration(s.subnetWindow))

	ban := Ban{
		Key:      rangeKey.String(),
		Detector: detectorSubnet,
		Rule:     rule,
		Reason:   detectorSubnet + ": " + rule,
		Created:  now.UTC(),
		Offences: offence,
		LastPath: truncate(req.URL.Path, 512),
		LastUA:   truncate(req.UserAgent(), 256),
	}
	if duration != permanent {
		ban.Expires = now.Add(duration).UTC()
	}
	rt.putBan(s, ban)

	rt.stats.Detections.Add(1)
	rt.topDetectors.add(detectorSubnet)
	rt.topRules.add(detectorSubnet + ": " + rule)

	rt.record(Event{
		Kind:     eventBan,
		Key:      ban.Key,
		Detector: detectorSubnet,
		Rule:     rule,
		Method:   req.Method,
		Host:     req.Host,
		Path:     req.URL.Path,
		UA:       req.UserAgent(),
		BanFor:   formatDuration(duration),
		DryRun:   s.dryRun,
	})

	logWarn(rt.name, "banned range", map[string]interface{}{
		"key":      ban.Key,
		"members":  members,
		"detector": detectorSubnet,
		"rule":     rule,
		"offence":  offence,
		"duration": formatDuration(duration),
		"dryRun":   s.dryRun,
		"client":   res.client.String(),
		"host":     truncate(req.Host, 253),
		"method":   req.Method,
		"path":     req.URL.Path,
		"ua":       ban.LastUA,
	})
}

// banManual records an operator-initiated ban from the admin UI.
func (rt *runtime) banManual(s *settings, key netip.Prefix, duration time.Duration, reason, actor string) Ban {
	now := time.Now()
	ban := Ban{
		Key:      key.String(),
		Detector: detectorManual,
		Reason:   reason,
		Created:  now.UTC(),
		Manual:   true,
		Actor:    actor,
		Offences: rt.counters.offences(key),
	}
	if duration != permanent {
		ban.Expires = now.Add(duration).UTC()
	}

	if err := rt.store().put(ban); err != nil {
		logWarn(rt.name, "could not record manual ban", map[string]interface{}{"key": ban.Key, "error": err.Error()})
		return ban
	}
	rt.stats.BansManual.Add(1)
	if fs, ok := rt.store().(*fileStore); ok {
		_ = fs.flush()
	}

	rt.record(Event{
		Kind:     eventBan,
		Key:      ban.Key,
		Detector: detectorManual,
		Rule:     reason,
		BanFor:   formatDuration(duration),
		Actor:    actor,
	})
	return ban
}

// reject terminates a request for a banned source without calling next, so the
// backend never sees it.
//
// Traefik has no deny-list middleware and no way to hand it a ban list, so
// returning a status code from here is the entire enforcement mechanism. Dropping
// the packet at the firewall requires a privileged helper outside Traefik — see
// the webhook notifier.
func (rt *runtime) reject(s *settings, rw http.ResponseWriter, req *http.Request) {
	if s.tarpitEnabled {
		rt.tarpit(s, req)
	}

	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Rejections are not something a cache should ever remember on the client's behalf.
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(s.rejectStatus)

	body := s.rejectBody
	if body == "" {
		body = http.StatusText(s.rejectStatus)
	}
	_, _ = rw.Write([]byte(body + "\n"))
}

// tarpit delays a rejected request to waste the scanner's time.
//
// Two safety valves, both mandatory. The semaphore caps how many requests may be
// held at once, because every tarpitted request pins a Traefik goroutine and a
// socket — an attacker with a thousand connections would otherwise turn this into
// a denial of service against the host running it. And the delay aborts as soon
// as the client disconnects, so a scanner that hangs up does not keep paying for
// a goroutine it no longer cares about.
func (rt *runtime) tarpit(s *settings, req *http.Request) {
	// Loaded once: the console can swap this channel when the cap changes, and
	// releasing into a different channel than we acquired from would corrupt the
	// accounting for every request in flight.
	sem, _ := rt.tarpitSem.Load().(chan struct{})
	if sem == nil {
		return
	}

	select {
	case sem <- struct{}{}:
	default:
		// At capacity: reject immediately rather than queueing.
		return
	}
	defer func() { <-sem }()

	timer := time.NewTimer(s.tarpitDelay)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-req.Context().Done():
	}
}
