package scanguard

import (
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

// applyBan records a ban for a detected source and returns it.
//
// In dry-run mode everything happens except the write: the event is logged, the
// UI shows it, notifications fire with DryRun set. That is what makes dry-run
// useful for tuning rules on live traffic — you see exactly what would have been
// banned without banning anybody.
func (rt *runtime) applyBan(s *settings, res resolution, det *detection, req *http.Request, now time.Time) Ban {
	offence := rt.counters.recordOffence(res.key, now, s.decay)
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
		Country:  rt.geo.lookup(res.client.String()),
	}
	if duration != permanent {
		ban.Expires = now.Add(duration).UTC()
	}

	rt.stats.Detections.Add(1)
	rt.topDetectors.add(det.detector)
	rt.topSources.add(res.key.String())
	rt.topPaths.add(req.URL.Path)

	if !s.dryRun {
		if err := rt.store.put(ban); err != nil {
			logWarn(rt.name, "could not record ban", map[string]interface{}{
				"key":   ban.Key,
				"error": err.Error(),
			})
		} else {
			rt.stats.BansIssued.Add(1)
			// Persist immediately on a ban-list change. Counter updates deliberately
			// do not trigger a write — rewriting the snapshot on every counter bump
			// under a 404 flood would burn through IOPS or an SD card.
			if fs, ok := rt.store.(*fileStore); ok {
				if err := fs.flush(); err != nil {
					logWarn(rt.name, "could not persist state", map[string]interface{}{"error": err.Error()})
				}
			}
		}
	}

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

	logWarn(rt.name, "banned source", map[string]interface{}{
		"key":      ban.Key,
		"client":   res.client.String(),
		"detector": det.detector,
		"rule":     det.rule,
		"path":     req.URL.Path,
		"offence":  offence,
		"duration": formatDuration(duration),
		"dryRun":   s.dryRun,
		"ipSource": res.source,
	})

	return ban
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

	if err := rt.store.put(ban); err != nil {
		logWarn(rt.name, "could not record manual ban", map[string]interface{}{"key": ban.Key, "error": err.Error()})
		return ban
	}
	rt.stats.BansManual.Add(1)
	if fs, ok := rt.store.(*fileStore); ok {
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
