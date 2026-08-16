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

	rt, err := acquireRuntime(s, config, fingerprintOf(config))
	if err != nil {
		return nil, fmt.Errorf("scanguard (%s): %w", name, err)
	}

	return &handler{next: next, rt: rt, name: name, uiMode: s.uiMode}, nil
}

// handler is the per-router middleware. It holds no durable state: that lives on
// the shared runtime, because this struct is discarded and rebuilt whenever any
// container on the host starts or stops.
//
// uiMode is the one exception, and it has to be per-handler rather than on the
// shared settings: the console and the detector are two middleware definitions
// sharing one runtime, and a global uiMode flag would put the detector into
// console mode the moment the console was constructed.
type handler struct {
	next   http.Handler
	rt     *runtime
	name   string
	uiMode bool
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	s := h.rt.settings()
	if s == nil {
		h.next.ServeHTTP(rw, req)
		return
	}

	// Admin surface. In uiMode this instance serves only the console and never
	// calls next, so it belongs on its own router.
	if s.adminEnabled {
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

	res := s.resolve(req)

	// Allowlists and unattributable requests short-circuit before any detector
	// runs, so a bad rule can never lock out an exempt source.
	if s.exempt(req, res) {
		h.rt.stats.Skipped.Add(1)
		h.next.ServeHTTP(rw, req)
		return
	}

	// The hot path proper: one map lookup under a read lock.
	if ban, banned := h.rt.store.get(res.key, now); banned {
		h.rt.store.countHit(res.key)
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
		})
		h.rt.reject(s, rw, req)
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
