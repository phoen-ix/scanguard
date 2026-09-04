// Package scanguard is a Traefik middleware plugin that detects HTTP
// vulnerability scanning, bans the source, and serves its own web GUI for
// inspecting and managing those bans.
//
// It is built for Traefik v3 and runs under the Yaegi interpreter, which shapes
// several decisions that would look odd in ordinary Go: the admin UI is a string
// constant rather than an embedded asset because //go:embed does not work under
// Yaegi and fails silently; the Redis client is hand-written because mainstream
// ones do not survive interpretation; long-lived state lives in a process-global
// registry because Traefik re-runs New for every router on every configuration
// reload and never calls anything on the way out.
package scanguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// disableEnv is an out-of-band kill switch, read at construction time. It exists
// for the case where the thing you have locked yourself out of is the admin GUI:
// set it, restart Traefik, and scanguard becomes a pass-through without any
// configuration edit.
const disableEnv = "SCANGUARD_DISABLE"

// New creates a scanguard middleware instance.
//
// Traefik calls this once per router that references the middleware, and again
// for every one of them on each dynamic-configuration reload. It must therefore
// be cheap, idempotent, and must never panic: a panic here takes down the whole
// configuration, not just this route.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		return nil, errors.New("scanguard: no configuration supplied")
	}
	if next == nil {
		return nil, errors.New("scanguard: no next handler supplied")
	}

	if v := os.Getenv(disableEnv); v == "1" || strings.EqualFold(v, "true") {
		logWarn(config.InstanceName, "disabled by "+disableEnv+"; requests pass through unchecked", nil)
		return next, nil
	}

	s, err := config.parse()
	if err != nil {
		return nil, fmt.Errorf("scanguard (%s): %w", name, err)
	}
	if !s.enabled {
		return next, nil
	}

	rt, err := acquireRuntime(s, config, configFingerprint(config))
	if err != nil {
		return nil, fmt.Errorf("scanguard (%s): %w", name, err)
	}

	// s is this middleware's OWN parsed settings. acquireRuntime may merge a
	// sibling console's admin block into the shared object, so adminServeHere has
	// to be read here, before that happens.
	return &handler{next: next, rt: rt, name: name, uiMode: s.uiMode, servePrefix: s.adminServeHere}, nil
}

// handler is the per-router middleware. It holds no durable state: that lives on
// the shared runtime, because this struct is discarded and rebuilt whenever any
// container on the host starts or stops.
//
// uiMode is the one exception, and it has to be per-handler rather than on the
// shared settings: the console and the detector are two middleware definitions
// sharing one runtime, and a global uiMode flag would put the detector into
// console mode the moment the console was constructed.
//
// servePrefix is the second exception, for exactly the same reason. It records
// whether THIS middleware definition was itself configured to answer the admin
// surface, captured from its own parsed settings before inheritAdmin merges the
// console's admin block into the shared object. Reading the shared adminEnabled
// here instead would mean that configuring the console once, on its own guarded
// router, silently opened an unguarded copy of it on every route the detector
// protects.
type handler struct {
	next        http.Handler
	rt          *runtime
	name        string
	uiMode      bool
	servePrefix bool
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	s := h.rt.settings()
	if s == nil {
		h.next.ServeHTTP(rw, req)
		return
	}

	// Admin surface. In uiMode this instance serves only the console and never
	// calls next, so it belongs on its own router.
	if s.adminEnabled && (h.servePrefix || s.adminServeShared) {
		if h.uiMode || strings.HasPrefix(req.URL.Path, s.adminPrefix) {
			h.rt.serveAdmin(s, h.uiMode, rw, req)
			return
		}
	} else if h.uiMode {
		http.NotFound(rw, req)
		return
	}

	now := time.Now()
	h.rt.stats.Requests.Add(1)
	h.rt.topHosts.add(req.Host)

	res := s.resolve(req)

	// Allowlists and unattributable requests short-circuit before any detector
	// runs, so a bad rule can never lock out an exempt source.
	if reason, ok := s.exempt(req, res); ok {
		h.rt.stats.Skipped.Add(1)
		h.rt.topExempt.add(reason)
		h.next.ServeHTTP(rw, req)
		return
	}

	// "Most probed paths" and "Top sources" are fed here, from every request that
	// a detector could have acted on — not from applyBan.
	//
	// Fed from applyBan they ranked only the request that happened to trip a ban,
	// which on a live deployment was 1,907 of 294,526 rejected requests: less than
	// one percent of the traffic, ranked under a label promising all of it. The
	// giveaway was /robots.txt topping "most probed paths", which was crawler ban
	// volume rather than probing. Both tallies are capped and pruned, so the
	// attacker-controlled key space stays bounded (see tally).
	h.rt.topPaths.add(req.URL.Path)
	h.rt.topSources.add(res.key.String())

	// The hot path proper: one map lookup under a read lock.
	//
	// A dry run consults its shadow list here as well, and a hit ends the request
	// the same way — recorded, counted, then passed to the backend instead of
	// rejected. Skipping the detectors for an already-banned source is the whole
	// point: enforcement only ever detects a source once, so a dry run that kept
	// detecting would report an escalation ladder that enforcement would never
	// have climbed.
	ban, banned := h.rt.store().get(res.key, now)
	if banned {
		h.rt.store().countHit(res.key)
	} else if s.dryRun {
		if ban, banned = h.rt.shadow.get(res.key, now); banned {
			h.rt.shadow.countHit(res.key)
		}
	}
	if banned {
		h.rt.stats.Rejected.Add(1)
		h.rt.events.add(Event{
			Kind:     eventReject,
			Key:      ban.Key,
			Client:   res.client.String(),
			Detector: ban.Detector,
			Rule:     ban.Rule,
			Method:   req.Method,
			Host:     req.Host,
			Path:     req.URL.Path,
			UA:       req.UserAgent(),
			Status:   s.rejectStatus,
			DryRun:   s.dryRun,
		})
		if !s.dryRun {
			h.rt.reject(s, rw, req)
			return
		}
		h.next.ServeHTTP(rw, req)
		return
	}

	if det := h.rt.detectRequest(s, req, res, now); det != nil {
		h.rt.applyBan(s, res, det, req, now)
		if !s.dryRun {
			h.rt.stats.Rejected.Add(1)
			h.rt.reject(s, rw, req)
			return
		}
	}

	// Response observation is opt-in and skipped for protocol upgrades, so a
	// WebSocket handshake reaches the backend holding the original ResponseWriter
	// and can still be hijacked.
	if s.observeResponse && s.needsResponse && !isUpgrade(req) {
		obs := newResponseObserver(rw, s.instanceName)
		h.next.ServeHTTP(obs, req)

		if det := h.rt.detectResponse(s, req, res, obs.status, time.Now()); det != nil {
			// The response is already on its way to the client, so this ban takes
			// effect from the source's next request. That is inherent to any
			// status-based detector, not something to work around.
			h.rt.applyBan(s, res, det, req, time.Now())
		}
		return
	}

	h.next.ServeHTTP(rw, req)
}
