package scanguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Traefik calls New() once for every router that references the middleware, and
// again for every router on every dynamic-configuration reload — starting or
// stopping any Docker container is enough to trigger one. There is no Close or
// Shutdown hook; Traefik's own source notes that it "does not Close the
// middleware when creating a new instance on a configuration change".
//
// So nothing durable can live on the handler struct. It lives here instead, in a
// process-global registry keyed by instance name, and every handler holds a
// pointer to the shared runtime rather than owning any state itself.
var (
	registryMu sync.Mutex
	registry   = map[string]*runtime{}
)

// runtime is the shared, long-lived state for one instance name.
type runtime struct {
	name string

	// cfg holds the current *settings. It is an atomic.Value rather than a mutex
	// because it is read on every request and written only on a config reload.
	cfg atomic.Value

	// Two middleware definitions routinely share one instance name: the detector
	// attached to your routers, and the UI-mode instance serving the console. They
	// configure different halves of the same runtime, so each is tracked
	// separately. Collapsing them into one fingerprint would make whichever was
	// constructed last silently overwrite the other's settings — which is exactly
	// the trap the comparable CrowdSec plugin documents and does not solve.
	detectFP         string
	uiFP             string
	storeFingerprint string

	store    banStore
	counters *counters
	events   *eventLog

	topPaths     *tally
	topSources   *tally
	topDetectors *tally

	notifier *notifier
	geo      *geoCache

	stats stats

	// mu guards baseConfig and overrides. It is never taken on the request path:
	// readers there go through cfg, which is atomic.
	mu sync.Mutex
	// baseConfig is the detector instance's configuration exactly as Traefik
	// decoded it. Keeping it lets the console's rule edits be re-layered and
	// re-validated through the ordinary parse path instead of mutating live
	// settings in place.
	baseConfig *Config
	overrides  *Overrides
	// overridesLoaded records that persisted rule edits have been read from the
	// store. It is separate from `overrides` being non-nil, because "there were
	// none saved" and "we have not looked yet" must not be confused.
	overridesLoaded bool

	janitorOnce sync.Once
	// tarpitSem caps concurrent tarpitted requests. Without it a scanner holding a
	// thousand connections turns the tarpit into a self-inflicted denial of service,
	// because every delayed request pins a Traefik goroutine and a socket.
	//
	// It is an atomic.Value holding a channel rather than a plain field because the
	// console can change the cap at runtime. Swapping the channel is safe only
	// because tarpit() loads it once and releases into that same one, so requests
	// already in flight drain through the old channel.
	tarpitSem atomic.Value
}

// stats are cheap process counters surfaced by the admin API.
type stats struct {
	Requests   atomic.Int64
	Rejected   atomic.Int64
	Detections atomic.Int64
	BansIssued atomic.Int64
	BansManual atomic.Int64
	Unbans     atomic.Int64
	Expired    atomic.Int64
	Skipped    atomic.Int64
	StartedAt  time.Time
}

// acquireRuntime returns the shared runtime for this instance name, creating it
// on first use and updating its configuration on subsequent calls.
func acquireRuntime(s *settings, cfg *Config, fp string) (*runtime, error) {
	registryMu.Lock()
	defer registryMu.Unlock()

	rt, exists := registry[s.instanceName]
	if !exists {
		store, err := newBanStore(s)
		if err != nil {
			return nil, err
		}
		rt = &runtime{
			name:             s.instanceName,
			storeFingerprint: storeFingerprint(s),
			store:            store,
			counters:         newCounters(s.maxEntries),
			events:           newEventLog(s.eventLogSize),
			topPaths:         newTally(1000),
			topSources:       newTally(1000),
			topDetectors:     newTally(64),
			notifier:         newNotifier(s),
			geo:              newGeoCache(s),
		}
		rt.stats.StartedAt = time.Now().UTC()
		if s.uiMode {
			rt.uiFP = fp
		} else {
			rt.detectFP = fp
			if base, cerr := cloneConfig(cfg); cerr == nil {
				base.normalizeDefaults()
				rt.baseConfig = base
			}
		}
		rt.applySettings(s)
		registry[s.instanceName] = rt

		effective := rt.restoreOverrides(s)

		logInfo(s.instanceName, "scanguard initialised", map[string]interface{}{
			"store":           store.backend(),
			"dryRun":          effective.dryRun,
			"observeResponse": effective.observeResponse && effective.needsResponse,
			"signatures":      effective.sigMatcher.size(),
			"userAgents":      effective.uaMatcher.size(),
			"honeypots":       len(effective.honeyPaths),
			"trustedProxies":  len(effective.trustedProxies),
			"adminEnabled":    effective.adminEnabled,
			"ruleOverrides":   rt.overrides.sections(),
		})
		rt.startJanitor()
		return rt, nil
	}

	// A UI-mode instance is a view onto the runtime, not a configurer of it. It
	// contributes the admin surface and nothing else, so a console that declares
	// only `uiMode: true` and a token cannot wipe out the detector's rules.
	if s.uiMode {
		if rt.uiFP == fp {
			return rt, nil
		}
		merged := *rt.settings()
		merged.adminEnabled = s.adminEnabled
		merged.adminPrefix = s.adminPrefix
		merged.adminToken = s.adminToken
		merged.adminSSO = s.adminSSO
		merged.adminReadOnly = s.adminReadOnly
		merged.eventLogSize = s.eventLogSize
		rt.uiFP = fp
		rt.applySettings(&merged)
		logInfo(s.instanceName, "admin console configuration applied", nil)
		return rt, nil
	}

	if rt.detectFP == fp {
		return rt, nil
	}

	// A detection instance configures everything except the admin surface, which
	// it inherits from the console instance when it has not been given one.
	merged := *s
	inheritAdmin(&merged, rt.settings())

	if newFP := storeFingerprint(s); newFP != rt.storeFingerprint {
		store, err := newBanStore(s)
		if err != nil {
			return nil, err
		}
		// Carry the live ban list across a backend change rather than dropping it.
		for _, b := range rt.store.list(time.Now()) {
			_ = store.put(b)
		}
		logInfo(s.instanceName, "state backend reconfigured", map[string]interface{}{
			"from": rt.store.backend(),
			"to":   store.backend(),
		})
		rt.store = store
		rt.storeFingerprint = newFP
	}

	rt.detectFP = fp
	rt.notifier = newNotifier(&merged)
	rt.geo = newGeoCache(&merged)
	rt.applySettings(&merged)

	// The file configuration changed underneath the console's edits. Re-layer them
	// on the new base so a Traefik reload does not silently discard rules somebody
	// set from the browser.
	rt.mu.Lock()
	if base, cerr := cloneConfig(cfg); cerr == nil {
		base.normalizeDefaults()
		rt.baseConfig = base
	}
	// baseConfig may have only just become available — if Traefik built the console
	// instance before this one, the startup restore could not run yet.
	rt.loadStoredOverridesLocked()

	ov := rt.overrides
	if !ov.empty() {
		if relayered, rerr := rt.rebuildLocked(ov); rerr == nil {
			rt.applySettings(relayered)
		} else {
			logWarn(s.instanceName, "console rule overrides no longer apply to the reloaded configuration; "+
				"running the file configuration instead",
				map[string]interface{}{"error": rerr.Error()})
		}
	}
	rt.mu.Unlock()

	logInfo(s.instanceName, "configuration reloaded", map[string]interface{}{
		"dryRun":        merged.dryRun,
		"ruleOverrides": ov.sections(),
	})
	return rt, nil
}

// inheritAdmin copies the admin surface from src to dst when dst has none. The
// console and the detector are separate middleware definitions sharing one
// runtime, and each configures a different half of it.
func inheritAdmin(dst, src *settings) {
	if src == nil || !src.adminEnabled || dst.adminEnabled {
		return
	}
	dst.adminEnabled = src.adminEnabled
	dst.adminPrefix = src.adminPrefix
	dst.adminToken = src.adminToken
	dst.adminSSO = src.adminSSO
	dst.adminReadOnly = src.adminReadOnly
	dst.eventLogSize = src.eventLogSize
}

// applySettings publishes new effective settings to the request path and resizes
// anything sized from them.
func (rt *runtime) applySettings(s *settings) {
	rt.cfg.Store(s)

	if cur, ok := rt.tarpitSem.Load().(chan struct{}); !ok || cap(cur) != s.tarpitMax {
		rt.tarpitSem.Store(make(chan struct{}, s.tarpitMax))
	}
}

// rebuildLocked re-derives effective settings from the file configuration plus
// the console's edits.
//
// Everything goes back through Config.parse, which means an edit made in the
// browser is validated by exactly the same code that validates the file at
// startup — a broken regex or a nonsensical duration is rejected before it can
// reach the request path, and the running configuration is left untouched.
func (rt *runtime) rebuildLocked(ov *Overrides) (*settings, error) {
	if rt.baseConfig == nil {
		return nil, errors.New("no detection middleware has been configured for this instance yet")
	}
	cfg, err := applyOverrides(rt.baseConfig, ov)
	if err != nil {
		return nil, err
	}
	s, err := cfg.parse()
	if err != nil {
		return nil, err
	}
	inheritAdmin(s, rt.settings())
	return s, nil
}

// restoreOverrides applies rule edits persisted by a previous run.
func (rt *runtime) restoreOverrides(fallback *settings) *settings {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if s := rt.loadStoredOverridesLocked(); s != nil {
		return s
	}
	return fallback
}

// loadStoredOverridesLocked applies persisted rule edits, once, as soon as it is
// possible to do so. It returns the new settings, or nil if nothing was applied.
// The caller holds rt.mu.
//
// The "as soon as possible" part is the whole point, and it is subtle. Restoring
// an override means re-validating it against the file configuration, which only
// the DETECTION middleware supplies — a uiMode instance has no baseConfig. Traefik
// builds middleware in map-iteration order, so on any given startup the console
// instance may well be constructed first. When it is, this cannot run yet.
//
// Attempting it once at runtime creation is therefore not enough: it silently
// loses every saved rule edit on roughly half of all restarts, depending on which
// middleware Traefik happened to build first. So the attempt is deferred until
// baseConfig exists, and both construction paths call this.
//
// A failure to apply is never fatal. Persisted state that a newer build of the
// plugin rejects would otherwise take the whole Traefik configuration down at
// startup, leaving the operator no console to fix it from — so the edits are
// dropped, loudly, and the file configuration runs.
func (rt *runtime) loadStoredOverridesLocked() *settings {
	if rt.overridesLoaded || rt.baseConfig == nil {
		// No baseConfig yet means the detection middleware has not been built. Leave
		// the flag alone so the attempt happens when it is.
		return nil
	}
	rt.overridesLoaded = true

	stored := rt.store.loadOverrides()
	if stored.empty() {
		return nil
	}

	s, err := rt.rebuildLocked(stored)
	if err != nil {
		logWarn(rt.name, "saved console rule changes could not be applied and have been ignored; "+
			"the file configuration is in force",
			map[string]interface{}{"error": err.Error(), "savedAt": stored.Updated})
		return nil
	}
	rt.overrides = stored
	rt.applySettings(s)
	logInfo(rt.name, "restored rule changes made from the console", map[string]interface{}{
		"sections": stored.sections(),
		"savedAt":  stored.Updated,
		"actor":    stored.Actor,
	})
	return s
}

// settings returns the current configuration. One atomic load per request.
func (rt *runtime) settings() *settings {
	if v := rt.cfg.Load(); v != nil {
		if s, ok := v.(*settings); ok {
			return s
		}
	}
	return nil
}

// startJanitor launches the single background goroutine for this instance.
//
// It deliberately does NOT honour the context Traefik passes to New(): that
// context is cancelled on every configuration reload, so a janitor tied to it
// would die the first time any container on the host restarted, and sync.Once
// would prevent it from ever coming back. One goroutine per instance name for the
// life of the process is the correct lifetime, and there is no Close hook to
// respect anyway.
//
// The interval is deliberately coarse. Ban expiry is already handled lazily on
// the request path by Ban.active, so this loop exists only to reclaim memory and
// persist state — and high-frequency tickers in interpreted plugins have a
// history of leaking into Traefik out-of-memory kills.
func (rt *runtime) startJanitor() {
	rt.janitorOnce.Do(func() {
		go func() {
			defer recoverPanic(rt.name, "janitor")

			interval := 30 * time.Second
			if s := rt.settings(); s != nil && s.snapshotInterval > interval {
				interval = s.snapshotInterval
			}
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for range ticker.C {
				rt.tick()
			}
		}()
	})
}

// tick is one janitor pass. It is wrapped in its own recover so that a bug here
// costs one missed sweep instead of the entire Traefik process.
func (rt *runtime) tick() {
	defer recoverPanic(rt.name, "janitor tick")

	s := rt.settings()
	if s == nil {
		return
	}
	now := time.Now()

	for _, b := range rt.store.sweep(now) {
		rt.stats.Expired.Add(1)
		rt.events.add(Event{
			Kind:     eventUnban,
			Key:      b.Key,
			Detector: b.Detector,
			Actor:    "expiry",
			Time:     now.UTC(),
		})
	}

	idle := s.decay
	if idle < time.Hour {
		idle = time.Hour
	}
	rt.counters.sweep(now, idle)

	if err := rt.store.flush(); err != nil {
		logWarn(rt.name, "could not persist state", map[string]interface{}{"error": err.Error()})
	}
	if r, ok := rt.store.(interface{ refresh() error }); ok {
		if err := r.refresh(); err != nil {
			logWarn(rt.name, "could not refresh shared ban list", map[string]interface{}{"error": err.Error()})
		}
		// Only after a refresh can the store hold a rule set this replica has not
		// seen, so this is where a rule change made on another replica lands.
		rt.syncOverrides()
	}
	rt.geo.sweep(now)
}

// record adds an event to the ring buffer and forwards it to notifiers.
func (rt *runtime) record(e Event) Event {
	stored := rt.events.add(e)
	if e.Kind == eventBan || e.Kind == eventUnban {
		rt.notifier.dispatch(stored)
	}
	return stored
}

// unban removes a ban by hand and clears the source's counters.
//
// Clearing the counters is not incidental: leaving the escalation ladder in place
// would re-ban the source at the next rung on its very next request, which is not
// what an operator clicking "Unblock" means.
func (rt *runtime) unban(key netip.Prefix, actor string) bool {
	existed, err := rt.store.delete(key)
	if err != nil {
		logWarn(rt.name, "could not remove ban", map[string]interface{}{"key": key.String(), "error": err.Error()})
		return false
	}
	rt.counters.forget(key)
	if !existed {
		return false
	}

	rt.stats.Unbans.Add(1)
	rt.record(Event{Kind: eventUnban, Key: key.String(), Actor: actor})
	if fs, ok := rt.store.(*fileStore); ok {
		_ = fs.flush()
	}
	return true
}

// setOverrides validates and applies rule changes made from the console.
//
// It returns an error without touching the running configuration when the edit
// does not parse, so a mistyped regular expression in the browser produces a
// message in the browser rather than a middleware that has stopped detecting.
func (rt *runtime) setOverrides(ov *Overrides, actor string) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	// Keep only the sections that genuinely differ from the file, so the console
	// takes ownership of what was edited and nothing more.
	ov.prune(rt.baseConfig)
	if ov.empty() {
		ov = nil
	}

	s, err := rt.rebuildLocked(ov)
	if err != nil {
		return err
	}
	if ov != nil {
		ov.Updated = time.Now().UTC()
		ov.Actor = actor
	}

	rt.overrides = ov
	rt.applySettings(s)

	if err := rt.store.saveOverrides(ov); err != nil {
		logWarn(rt.name, "rule changes are live but could not be saved; they will be lost on restart",
			map[string]interface{}{"error": err.Error()})
	}
	// Persist immediately rather than waiting for the janitor: an operator who
	// edits a rule and restarts Traefik a second later should not lose the edit.
	if fs, ok := rt.store.(*fileStore); ok {
		if err := fs.flush(); err != nil {
			logWarn(rt.name, "could not persist rule changes", map[string]interface{}{"error": err.Error()})
		}
	}

	logInfo(rt.name, "rule set changed from the console", map[string]interface{}{
		"actor":      actor,
		"sections":   ov.sections(),
		"dryRun":     s.dryRun,
		"signatures": s.sigMatcher.size(),
		"userAgents": s.uaMatcher.size(),
		"honeypots":  len(s.honeyPaths),
	})
	return nil
}

// rulesView returns what the console needs to render the editor: the effective
// configuration, what the file says, and which sections the console has taken over.
func (rt *runtime) rulesView() (effective, fromFile editableConfig, ov *Overrides, err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.baseConfig == nil {
		return effective, fromFile, nil, errors.New("no detection middleware has been configured for this instance yet")
	}
	merged, err := applyOverrides(rt.baseConfig, rt.overrides)
	if err != nil {
		return effective, fromFile, nil, err
	}
	return editableFrom(merged), editableFrom(rt.baseConfig), rt.overrides.clone(), nil
}

// syncOverrides adopts a rule set changed by another replica.
//
// Only the shared backends can produce one — with a local store the value read
// back is the value this process wrote, so the timestamp matches and nothing
// happens.
func (rt *runtime) syncOverrides() {
	stored := rt.store.loadOverrides()

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if sameOverrideStamp(rt.overrides, stored) {
		return
	}
	s, err := rt.rebuildLocked(stored)
	if err != nil {
		logWarn(rt.name, "a rule set from the shared store could not be applied and has been ignored",
			map[string]interface{}{"error": err.Error()})
		return
	}
	rt.overrides = stored
	rt.applySettings(s)
	logInfo(rt.name, "adopted a rule set changed on another replica", map[string]interface{}{
		"sections": stored.sections(),
		"actor":    stored.Actor,
		"savedAt":  stored.Updated,
	})
}

func sameOverrideStamp(a, b *Overrides) bool {
	if a.empty() && b.empty() {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Updated.Equal(b.Updated)
}

// storeFingerprint captures the fields that require rebuilding the state backend.
func storeFingerprint(s *settings) string {
	return fingerprintOf(map[string]interface{}{
		"backend":   s.storeBackend,
		"path":      s.storePath,
		"redisAddr": s.redis.Address,
		"redisDB":   s.redis.DB,
		"redisKey":  s.redis.KeyPrefix,
		"max":       s.maxEntries,
	})
}

// fingerprintOf hashes any JSON-encodable value into a short stable string.
func fingerprintOf(v interface{}) string {
	buf, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:8])
}
