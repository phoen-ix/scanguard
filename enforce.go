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
func (rt *runtime) applyBan(s *settings, res resolution, det *detection, f requestFacts, now time.Time) Ban {
	ban, issued := rt.issueBan(s, res.key, res.client.String(), det, f, now)
	if !issued {
		return ban
	}

	// host, method and ua because the access log may have no Host column: without
	// them a ban on a multi-site Traefik could not be traced to the site it hit.
	logWarn(rt.name, "banned source", map[string]interface{}{
		"key":      ban.Key,
		"client":   res.client.String(),
		"detector": det.detector,
		"rule":     det.rule,
		"host":     truncate(f.host, 253),
		"method":   truncate(f.method, maxMethodLen),
		"path":     truncate(f.path, 512),
		"ua":       ban.LastUA,
		"offence":  ban.Offences,
		"duration": ban.durationLabel(),
		"dryRun":   s.dryRun,
		"ipSource": res.source,
	})

	if s.subnet.Enabled {
		rangeKey := banKey(res.client, s.subnet.IPv4Prefix, s.subnet.IPv6Prefix)
		if n, trip := rt.counters.noteSubnetBan(rangeKey, res.key, now, s.subnet.Threshold, s.subnetWindow, s.dryRun); trip {
			rt.applySubnetBan(s, rangeKey, n, res, f, now)
		}
	}
	return ban
}

// durationLabel renders the length of the ban as the event log and the log
// line show it.
func (b Ban) durationLabel() string {
	if b.Permanent() {
		return formatDuration(permanent)
	}
	return formatDuration(b.Expires.Sub(b.Created))
}

// issueBan is the one place a detection becomes a ban: it advances the ladder,
// writes the ban at the rung reached, counts it and records the event. applyBan
// (a source) and applySubnetBan (a range) both go through it; they used to carry
// two copies of this sequence, and the copies had drifted apart.
//
// client is the address the ban is for, or "" for a range: a range has no single
// client, so its event carries none and reportAbuse skips it — the member whose
// ban tripped the range has already been reported on its own.
//
// issued is false when nothing was written: the ladder says the source is still
// inside its last ban and either a sibling request is writing that ban right
// now, or it is in the list already (returned as ban).
func (rt *runtime) issueBan(s *settings, key netip.Prefix, client string, det *detection, f requestFacts, now time.Time) (ban Ban, issued bool) {
	offence, fresh := rt.counters.recordOffence(key, now, s.decay, s.banDuration)
	if !fresh {
		// The ladder says this source is still inside its last ban. Two cases.
		//
		// Not recorded yet: another request from the same burst is writing the
		// ban right now. Carrying on would overwrite it with an identical one and
		// emit a second ban event — sixteen concurrent probes produced sixteen
		// "banned source" lines and sixteen console entries for what is one ban.
		// banRecorded is checked FIRST, because it is set only after the put, so
		// a true here means the list was written and can be consulted.
		if !rt.counters.banRecorded(key) {
			return Ban{}, false
		}
		if existing, ok := rt.activeBan(s, key, now); ok {
			return existing, false
		}
		// Recorded, and gone: the list evicted it at store.maxEntries, a dry run
		// was switched off after the shadow list took it, or another replica
		// lifted it. Until now this request was still refused — the detection
		// stands — but nothing was written, logged or shown, and the source was
		// re-detected on every request for the rest of its rung, invisibly.
		// Re-issue the ban at the current rung; the ladder does not move.
		//
		// One request does the re-issuing. The claim flips banRecorded off under
		// the counters' lock, so a sibling that noticed the gap at the same
		// moment takes the "not recorded yet" branch above and stands down, the
		// same way a burst does. Without the claim, two requests could both pass
		// the lookup above before either had put, and the re-issue was two bans
		// and two events.
		if !rt.counters.claimReissue(key) {
			return Ban{}, false
		}
	}
	duration := s.banDuration(offence)

	ban = Ban{
		Key:      key.String(),
		Detector: det.detector,
		Rule:     det.rule,
		Reason:   det.detector + ": " + det.rule,
		Created:  now.UTC(),
		Offences: offence,
		LastPath: truncate(f.path, 512),
		LastUA:   truncate(f.ua, 256),
	}
	if client != "" {
		ban.Country = rt.geo().lookup(client)
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

	if rt.putBan(s, ban) {
		rt.counters.markBanRecorded(key)
	}

	rt.record(Event{
		Kind:     eventBan,
		Key:      ban.Key,
		Client:   client,
		Detector: det.detector,
		Rule:     det.rule,
		Method:   f.method,
		Host:     f.host,
		Path:     f.path,
		UA:       f.ua,
		BanFor:   formatDuration(duration),
		Expires:  ban.expiresAt(),
		DryRun:   s.dryRun,
		Country:  ban.Country,
	})
	return ban, true
}

// expiresAt is the ban's expiry for an event, nil for a permanent ban.
func (b Ban) expiresAt() *time.Time {
	if b.Permanent() {
		return nil
	}
	exp := b.Expires
	return &exp
}

// putBan writes a ban to the list this instance enforces from, and reports
// whether it got there.
//
// A dry run records the ban in the shadow list instead of the real one. It is
// still a ban as far as every counter and every report is concerned — it just
// cannot reject anything, and it never reaches disk or Redis. Without this the
// source is re-detected on its next request and the ladder runs away; see the
// comment on runtime.shadow.
func (rt *runtime) putBan(s *settings, ban Ban) bool {
	if s.dryRun {
		if err := rt.shadow.put(ban); err != nil {
			logWarn(rt.name, "could not record dry-run ban", map[string]interface{}{
				"key":   ban.Key,
				"error": err.Error(),
			})
			return false
		}
		rt.stats.BansIssued.Add(1)
		return true
	}
	if err := rt.store().put(ban); err != nil {
		logWarn(rt.name, "could not record ban", map[string]interface{}{
			"key":   ban.Key,
			"error": err.Error(),
		})
		return false
	}
	rt.stats.BansIssued.Add(1)
	// Persist on a ban-list change, batched by store.flushDebounce: every write
	// marshals the whole table, and a scan bans one source after another.
	// Counter updates never trigger a write — rewriting the snapshot on every
	// counter bump under a 404 flood would burn through IOPS or an SD card.
	if fs, ok := rt.store().(*fileStore); ok {
		fs.scheduleFlush(s.flushDebounce)
	}
	return true
}

// applySubnetBan bans rangeKey once enforcement.subnet.threshold of its sources
// have been banned within the window. Only applyBan calls it, so only automatic
// bans count: banManual and the crawler "block" policy never get there.
//
// The range climbs its own escalation ladder, keyed by the range. The event has
// no Client, so reportAbuse skips it: a range is never reported to AbuseIPDB, and
// the member whose ban tripped it has already been reported on its own.
func (rt *runtime) applySubnetBan(s *settings, rangeKey netip.Prefix, members int, res resolution, f requestFacts, now time.Time) {
	// The same refusal an operator's range ban gets: never over the allowlist or
	// a trusted proxy. Said once per range, because the range keeps tripping.
	if status, msg := refuseDangerousBan(s, rangeKey); status != 0 {
		warnOnce(rt.name, "subnet-refused:"+rangeKey.String(), "range escalation skipped a protected range",
			map[string]interface{}{"key": rangeKey.String(), "reason": msg})
		return
	}
	det := &detection{
		detector: detectorSubnet,
		rule:     fmt.Sprintf("%d sources in %s within %s", s.subnet.Threshold, rangeKey, formatDuration(s.subnetWindow)),
	}
	ban, issued := rt.issueBan(s, rangeKey, "", det, f, now)
	if !issued {
		return
	}

	logWarn(rt.name, "banned range", map[string]interface{}{
		"key":      ban.Key,
		"members":  members,
		"detector": detectorSubnet,
		"rule":     det.rule,
		"offence":  ban.Offences,
		"duration": ban.durationLabel(),
		"dryRun":   s.dryRun,
		"client":   res.client.String(),
		"host":     truncate(f.host, 253),
		"method":   truncate(f.method, maxMethodLen),
		"path":     truncate(f.path, 512),
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
	// Tell the ladder, the way seed() does when this same ban is replayed after
	// a restart. Left out, the source came back at one rung in-process and at
	// another after a restart during the ban.
	rt.counters.noteManualBan(key, ban.Expires, now)
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
		Expires:  ban.expiresAt(),
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

	rw.Header().Set("Content-Type", s.rejectType)
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
