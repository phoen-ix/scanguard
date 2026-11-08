package scanguard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"strconv"
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
	// Every WRITE happens under mu (see applySettings): the reload path and the
	// console's rule edits used to publish under different locks, and a token
	// rotation arriving while a rule was being saved lost one of the two.
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
	// notifyFingerprint and geoFingerprint decide whether a reload rebuilds the
	// notifier and the geo cache. Both carry state worth keeping across a reload
	// — the AbuseIPDB report dedupe and score cache, a week of country lookups —
	// and a reload that changed a honeypot path used to throw it away.
	notifyFingerprint string
	geoFingerprint    string

	// depsV holds the three things a configuration reload replaces: the ban store,
	// the notifier and the geo cache. They are swapped while requests are reading
	// them, so they live behind an atomic rather than in plain fields.
	//
	// settings already had this treatment (see cfg above); these three did not.
	// The reload path wrote them under registryMu while the request path read them
	// under nothing at all — a real race on a host where the docker provider
	// watches a socket and every container start rebuilds the router tree, and one
	// the race detector reproduces in a few hundred milliseconds once a test
	// actually reloads under traffic.
	//
	// One atomic holding all three, not three atomics: a reload replaces them
	// together, and a request that read the new store and the old notifier would
	// be observing a configuration that never existed.
	//
	// It holds a *runtimeDeps and the load asserts that concrete pointer type.
	// Yaegi cannot reliably assert an interface value out of an atomic.Value, nor
	// assert to an anonymous interface — both segfault the plugin at load time
	// while compiling and passing -race perfectly. Pointer-to-struct is the shape
	// cfg already proves works under the interpreter.
	depsV atomic.Value

	counters *counters
	events   *eventLog

	// shadow holds the bans a DRY RUN would have written. It exists because
	// without it a dry run cannot answer the only question it is asked.
	//
	// The enforcing path bans a source once and rejects everything after that, so
	// the source is detected exactly once. A dry run writes no ban, so the same
	// source is detected again on every subsequent request and climbs the
	// escalation ladder each time — one observed source reached offence 514 and a
	// reported duration of 30d where enforcement would have said 1h. Every number
	// a dry run produced was therefore inflated by however long the scan ran.
	//
	// Deliberately a private memStore rather than the real store: a dry run must never
	// write a ban to disk or to Redis, because flipping dryRun off afterwards
	// would silently enforce bans that were only ever hypothetical.
	shadow *memStore

	topPaths     *tally
	topSources   *tally
	topDetectors *tally
	// topRules ranks the individual rule that fired, not just the detector that
	// owns it, so an operator can see which patterns are earning their place and
	// which have never matched anything. Keyed "detector: rule".
	topRules *tally
	// Fed on EVERY request rather than only on a detection, so the console can
	// break "requests seen" and "exempt" down instead of showing a bare number.
	// Both are bounded tallies, never per-item records: the event log is a fixed
	// ring precisely so attack volume cannot leak memory, and a per-request log
	// would hand that back. Host cardinality is the number of vhosts served;
	// exemption reasons are a closed set of five.
	topHosts  *tally
	topExempt *tally

	stats stats

	// authLogMu and authLogAt throttle the "admin authentication failed" log line
	// to one a minute; the count itself is in stats.AuthFailures.
	authLogMu sync.Mutex
	authLogAt time.Time

	// mu guards baseConfig, overrides and every publication of cfg. It is never
	// taken on the request path: readers there go through cfg, which is atomic.
	mu sync.Mutex
	// baseConfig is the detector instance's configuration exactly as Traefik
	// decoded it. Keeping it lets the console's rule edits be re-layered and
	// re-validated through the ordinary parse path instead of mutating live
	// settings in place.
	baseConfig *Config
	overrides  *Overrides
	// overridesStale is set when the saved console edits no longer apply to the
	// file configuration a reload brought in. They are kept, so the console can
	// show what the operator saved, but the file configuration is what runs;
	// the rule editor says so instead of listing them as in force.
	overridesStale string
	// overridesUnsaved is set when the last rule save applied here but could
	// not be persisted or published (a Redis outage, an unwritable snapshot),
	// so the console can say so instead of "Rules applied". A shared backend
	// publishes the set on its next refresh and syncOverrides clears this when
	// it sees the stamps agree.
	overridesUnsaved string
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

// runtimeDeps is the set of collaborators a configuration reload replaces
// wholesale. Treated as immutable once published: a reload builds a new one and
// swaps it in, so a request holding the old one keeps a consistent view.
type runtimeDeps struct {
	store    banStore
	notifier *notifier
	geo      *geoCache
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
	// AuthFailures counts rejected admin credentials. Every mutation the console
	// performs is logged; the attempts to reach it were not, so token guessing
	// against the gate was invisible.
	AuthFailures atomic.Int64
	// NotifyDropped counts ban and unban events no notifier delivered because
	// the delivery queue was full; see notifier.dispatch.
	NotifyDropped atomic.Int64
	StartedAt     time.Time
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
			name:              s.instanceName,
			storeFingerprint:  storeFingerprint(s),
			notifyFingerprint: notifyFingerprint(s),
			geoFingerprint:    geoFingerprint(s),
			counters:          newCounters(s.maxEntries),
			shadow:            newMemStore(s.maxEntries),
			events:            newEventLog(s.eventLogSize),
			topPaths:          newTally(1000),
			topSources:        newTally(1000),
			topDetectors:      newTally(64),
			topRules:          newTally(512),
			topHosts:          newTally(1000),
			topExempt:         newTally(16),
		}
		rt.setDeps(store, rt.newNotifier(s), newGeoCache(s))
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
		rt.mu.Lock()
		rt.applySettings(s)
		rt.mu.Unlock()
		rt.seedLadder(store, time.Now())
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
		// Read, merge and publish under mu, so a rule save on the other path
		// cannot interleave and lose either the token or the rule.
		rt.mu.Lock()
		merged := *rt.settings()
		merged.adminEnabled = s.adminEnabled
		merged.adminPrefix = s.adminPrefix
		merged.adminToken = s.adminToken
		merged.adminSSO = s.adminSSO
		merged.adminReadOnly = s.adminReadOnly
		merged.eventLogSize = s.eventLogSize
		// The console's block is where serveOnDetectionRoutes is documented to be
		// declared. Not carrying it here meant the flag worked only when Traefik
		// happened to build the console before the detector.
		merged.adminServeShared = s.adminServeShared
		rt.uiFP = fp
		rt.applySettings(&merged)
		rt.mu.Unlock()
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
		// Carry the live ban list across a backend change rather than dropping
		// it. Only the bans the new backend does not already hold: a file or
		// Redis store arrives with its own, and re-putting those cost one write
		// (one Redis round trip) per ban for nothing.
		now := time.Now()
		for _, b := range rt.store().list(now) {
			if k, perr := netip.ParsePrefix(b.Key); perr == nil {
				if _, held := store.get(k, now); held {
					continue
				}
			}
			_ = store.put(b)
		}
		logInfo(s.instanceName, "state backend reconfigured", map[string]interface{}{
			"from": rt.store().backend(),
			"to":   store.backend(),
		})
		// The console's saved rules travel with the bans. They used to stay
		// behind: the new store held none, loadStoredOverridesLocked had already
		// run, so a file backend's next snapshot wrote `overrides: null` and the
		// edits were gone on restart, while a Redis backend's next tick adopted
		// the empty shared set and reverted them with a misleading log line.
		rt.mu.Lock()
		rt.carryOverridesLocked(store)
		rt.mu.Unlock()
		rt.setDeps(store, rt.notifier(), rt.geo())
		rt.storeFingerprint = newFP
		// The new backend may have brought persisted bans with it — this is the
		// ordinary startup path whenever Traefik builds the console (memory store,
		// no store block of its own) before the detector (file or Redis). The
		// ladder was seeded only on the creation path, from the console's empty
		// store, so on those restarts every persisted offence count was lost.
		rt.seedLadder(store, time.Now())
	}

	// The notifier and the geo cache are rebuilt only when their own settings
	// changed; see the fingerprint fields.
	n := rt.notifier()
	if newFP := notifyFingerprint(&merged); newFP != rt.notifyFingerprint {
		n = rt.newNotifier(&merged)
		rt.notifyFingerprint = newFP
	}
	g := rt.geo()
	if newFP := geoFingerprint(&merged); newFP != rt.geoFingerprint {
		g = newGeoCache(&merged)
		rt.geoFingerprint = newFP
	}
	rt.detectFP = fp
	rt.setDeps(rt.store(), n, g)

	// The file configuration changed underneath the console's edits. Re-layer them
	// on the new base so a Traefik reload does not silently discard rules somebody
	// set from the browser.
	//
	// Everything is worked out first and published ONCE. The plain file
	// configuration used to be published here and the re-layered one a few
	// statements later; requests in between ran without the console's rules,
	// including a console-set dryRun, so real bans were written in what the
	// console showed as a dry run.
	rt.mu.Lock()
	if base, cerr := cloneConfig(cfg); cerr == nil {
		base.normalizeDefaults()
		rt.baseConfig = base
	}
	effective := &merged
	// baseConfig may have only just become available — if Traefik built the console
	// instance before this one, the startup restore could not run yet.
	if restored := rt.loadStoredOverridesLocked(); restored != nil {
		effective = restored
	} else if !rt.overrides.empty() {
		if relayered, rerr := rt.rebuildLocked(rt.overrides); rerr == nil {
			effective = relayered
			rt.overridesStale = ""
		} else {
			rt.overridesStale = rerr.Error()
			logWarn(s.instanceName, "console rule overrides no longer apply to the reloaded configuration; "+
				"running the file configuration instead",
				map[string]interface{}{"error": rerr.Error()})
		}
	}
	rt.applySettings(effective)
	ov := rt.overrides
	rt.mu.Unlock()

	logInfo(s.instanceName, "configuration reloaded", map[string]interface{}{
		"dryRun":        effective.dryRun,
		"ruleOverrides": ov.sections(),
	})
	return rt, nil
}

// newNotifier builds a notifier that counts its drops into this runtime's
// stats, where the console can show them.
func (rt *runtime) newNotifier(s *settings) *notifier {
	n := newNotifier(s)
	n.dropped = &rt.stats.NotifyDropped
	return n
}

// carryOverridesLocked saves the console's rule edits into a store that is
// about to replace the current one. The caller holds mu.
//
// A local backend (memory, file) takes the live set unconditionally: what the
// console shows as in force is the truth for this process. A shared backend
// takes it only when it holds none, because another replica's set is that
// replica's to own; syncOverrides adopts it on the next janitor tick and says so.
func (rt *runtime) carryOverridesLocked(store banStore) {
	if rt.overrides.empty() {
		return
	}
	if store.backend() == "redis" && !store.loadOverrides().empty() {
		logInfo(rt.name, "the new state backend already holds a rule set; it will be adopted on the next refresh", nil)
		return
	}
	if err := store.saveOverrides(rt.overrides); err != nil {
		logWarn(rt.name, "console rule changes could not be carried to the new state backend",
			map[string]interface{}{"error": err.Error()})
	}
}

// inheritAdmin copies the admin surface from src to dst when dst has none. The
// console and the detector are separate middleware definitions sharing one
// runtime, and each configures a different half of it.
//
// It deliberately does NOT copy adminServeHere. That field answers "does THIS
// middleware answer the admin surface", which is a per-middleware decision and is
// carried on the handler, not here. Copying it was the bug: a console configured
// on its own guarded router turned every detector route into a second, unguarded
// entrance to the same console. What is copied below is only what the shared
// runtime genuinely needs to know — the token, the prefix, the ring size — so the
// console instance can serve, and so serveAdmin can authenticate.
//
// adminServeShared IS copied, because it is the explicit opt-in back into that
// behaviour and has to reach the detection handlers to have any effect.
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
	dst.adminServeShared = src.adminServeShared
}

// applySettings publishes new effective settings to the request path and resizes
// anything sized from them. The caller holds mu.
func (rt *runtime) applySettings(s *settings) {
	rt.cfg.Store(s)

	if cur, ok := rt.tarpitSem.Load().(chan struct{}); !ok || cap(cur) != s.tarpitMax {
		rt.tarpitSem.Store(make(chan struct{}, s.tarpitMax))
	}

	// The rings were sized once, at runtime creation, from whichever middleware
	// Traefik happened to build first. admin.eventLogSize lives on the console's
	// block, so when the detector came first the setting silently did nothing.
	rt.events.resize(s.eventLogSize)

	// store.maxEntries sizes three tables. A change used to rebuild the whole
	// store (it was part of the store fingerprint) and re-put every ban into the
	// new one, one Redis round trip each, under registryMu; the cap is applied
	// in place instead, and these are no-ops when it is unchanged.
	if st := rt.store(); st != nil {
		st.setMax(s.maxEntries)
	}
	if rt.counters != nil {
		rt.counters.setMax(s.maxEntries)
	}
	if rt.shadow != nil {
		rt.shadow.setMax(s.maxEntries)
	}

	// The store has to know how wide the detector's own keys are, so it can tell
	// an operator's range ban from an ordinary one. Both widths are editable, so
	// this is re-applied on every configuration change rather than set once.
	subV4 := 0
	subV6 := 0
	if s.subnet.Enabled {
		subV4 = s.subnet.IPv4Prefix
		subV6 = s.subnet.IPv6Prefix
	}
	if st := rt.store(); st != nil {
		st.setKeyWidths(s.ipv4Prefix, s.ipv6Prefix, subV4, subV6)
	}
	if rt.shadow != nil {
		rt.shadow.setKeyWidths(s.ipv4Prefix, s.ipv6Prefix, subV4, subV6)
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
		rt.applySettings(s)
		return s
	}
	return fallback
}

// loadStoredOverridesLocked reads persisted rule edits, once, as soon as it is
// possible to do so, and returns the settings they produce for the caller to
// publish — or nil if nothing applied. The caller holds rt.mu.
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

	stored := rt.store().loadOverrides()
	if stored.empty() {
		return nil
	}
	if err := stored.compatible(); err != nil {
		// Sections are replaced wholesale, so a blob from a build with a different
		// editable schema would layer zero values over the file for every field
		// added since. Refused rather than applied; the operator can replace it by
		// saving from the console, or drop it with DELETE /api/rules.
		logWarn(rt.name, "saved console rule changes were written by a different version of the rule "+
			"schema and have been ignored; the file configuration is in force. Save the rules again "+
			"from the console to replace them, or DELETE /api/rules to discard them",
			map[string]interface{}{"error": err.Error(), "savedAt": stored.Updated, "sections": stored.sections()})
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
	rt.overridesStale = ""
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

// deps returns the collaborators published by the last configuration apply.
func (rt *runtime) deps() *runtimeDeps {
	d, _ := rt.depsV.Load().(*runtimeDeps)
	return d
}

// setDeps publishes a new set. Called only from acquireRuntime, under registryMu.
func (rt *runtime) setDeps(store banStore, n *notifier, g *geoCache) {
	rt.depsV.Store(&runtimeDeps{store: store, notifier: n, geo: g})
}

// store returns the live ban store.
func (rt *runtime) store() banStore {
	if d := rt.deps(); d != nil {
		return d.store
	}
	return nil
}

// notifier returns the live notifier.
func (rt *runtime) notifier() *notifier {
	if d := rt.deps(); d != nil {
		return d.notifier
	}
	return nil
}

// geo returns the live geo cache.
func (rt *runtime) geo() *geoCache {
	if d := rt.deps(); d != nil {
		return d.geo
	}
	return nil
}

// seedLadder replays the persisted ban list into the escalation counters, so a
// restart does not reset every repeat offender to the first rung.
//
// KNOWN GAP: it restores only sources whose ban is still LIVE. store.list
// excludes expired bans and restore() drops them on load, so a source whose ban
// has expired but whose decay window is still open loses its ladder position
// across a restart and comes back at rung 1. Measured on a live deployment: all
// seven "offence N then offence 1 inside the decay window" transitions in a
// nine-day sample straddled a restart, and none occurred anywhere else in 211
// hours — so the effect is real, bounded, and only as frequent as restarts are.
//
// Fixing it means retaining expired bans for `decay` purely so their ladder
// position can be replayed, which changes what list/sweep/restore mean and how
// maxEntries eviction counts. That is the most delicate part of this codebase
// and deserves its own change rather than a corner of one.
func (rt *runtime) seedLadder(store banStore, now time.Time) {
	seeded := 0
	for _, b := range store.list(now) {
		key, err := netip.ParsePrefix(b.Key)
		if err != nil {
			continue
		}
		rt.counters.seed(key, b.Offences, b.Created, b.Expires, now)
		if b.Offences > 0 {
			seeded++
		}
	}
	if seeded > 0 {
		logInfo(rt.name, "restored escalation ladder from persisted bans",
			map[string]interface{}{"sources": seeded})
	}
}

// janitorFloor is the shortest janitor period. Ban expiry is already handled
// lazily on the request path by Ban.active, so the loop exists only to reclaim
// memory and persist state — and high-frequency tickers in interpreted plugins
// have a history of leaking into Traefik out-of-memory kills.
const janitorFloor = 30 * time.Second

// janitorInterval derives the period from the CURRENT settings, so a reload
// that changes store.snapshotInterval takes effect, and so the value is the
// detector's whichever middleware Traefik happened to build first. It used to
// be read once, when the goroutine started: with the console built first the
// detector's value was ignored for the life of the process, and values under
// the floor were raised to it without a word.
func (rt *runtime) janitorInterval() time.Duration {
	s := rt.settings()
	if s == nil {
		return janitorFloor
	}
	if s.snapshotInterval < janitorFloor {
		warnOnce(rt.name, "snapshot-interval-floored",
			"store.snapshotInterval is below the 30s minimum; the janitor runs every 30s",
			map[string]interface{}{"configured": s.snapshotInterval.String()})
		return janitorFloor
	}
	return s.snapshotInterval
}

// startJanitor launches the single background goroutine for this instance.
//
// It deliberately does NOT honour the context Traefik passes to New(): that
// context is cancelled on every configuration reload, so a janitor tied to it
// would die the first time any container on the host restarted, and sync.Once
// would prevent it from ever coming back. One goroutine per instance name for the
// life of the process is the correct lifetime, and there is no Close hook to
// respect anyway.
func (rt *runtime) startJanitor() {
	rt.janitorOnce.Do(func() {
		go func() {
			defer recoverPanic(rt.name, "janitor")

			interval := rt.janitorInterval()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()

			for range ticker.C {
				rt.tick()
				if next := rt.janitorInterval(); next != interval {
					interval = next
					ticker.Reset(interval)
				}
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

	// Through record, not events.add: an unban by expiry is an unban, and a
	// webhook consumer that adds a firewall rule on "ban" needs the matching
	// "unban" to take it out again. Recorded straight into the ring, these never
	// reached a notifier, so only manual unbans were ever delivered.
	//
	// With a shared store every replica sweeps the same lapsed entry, so the
	// event is recorded in every console but notifiers hear it from the one
	// replica whose claim succeeded.
	for _, b := range rt.store().sweep(now) {
		rt.stats.Expired.Add(1)
		e := Event{
			Kind:     eventUnban,
			Key:      b.Key,
			Detector: b.Detector,
			Actor:    "expiry",
			Time:     now.UTC(),
		}
		if rt.store().claimExpiry(b.Key) {
			rt.record(e)
		} else {
			rt.events.add(e)
		}
	}

	// The shadow list expires on the same schedule as the real one, so a dry run
	// re-detects a source once its hypothetical ban would have run out — which is
	// exactly what enforcement would have done. Delivered with DryRun set, like
	// the would-ban that preceded it.
	for _, b := range rt.shadow.sweep(now) {
		rt.record(Event{
			Kind:     eventUnban,
			Key:      b.Key,
			Detector: b.Detector,
			Actor:    "expiry",
			DryRun:   true,
			Time:     now.UTC(),
		})
	}

	idle := s.decay
	if idle < time.Hour {
		idle = time.Hour
	}
	// A range's member count is bucket state on the range's own record, which is
	// touched only when a member is banned. Swept sooner than the window, the
	// count would restart in the middle of it.
	if s.subnet.Enabled && s.subnetWindow > idle {
		idle = s.subnetWindow
	}
	rt.counters.sweep(now, idle, s.decay)

	if err := rt.store().flush(); err != nil {
		logWarn(rt.name, "could not persist state", map[string]interface{}{"error": err.Error()})
	}
	if err := rt.store().refresh(); err != nil {
		logWarn(rt.name, "could not refresh shared ban list", map[string]interface{}{"error": err.Error()})
	}
	if rt.store().backend() == "redis" {
		// Only after a refresh can the store hold a rule set this replica has not
		// seen, so this is where a rule change made on another replica lands.
		rt.syncOverrides()
	}
	rt.geo().sweep(now)
}

// record adds an event to the ring buffer and forwards it to notifiers.
func (rt *runtime) record(e Event) Event {
	stored := rt.events.add(e)
	if e.Kind == eventBan || e.Kind == eventUnban {
		rt.notifier().dispatch(stored)
	}
	return stored
}

// unban removes a ban by hand and clears the source's counters.
//
// Clearing the counters is not incidental: leaving the escalation ladder in place
// would re-ban the source at the next rung on its very next request, which is not
// what an operator clicking "Unblock" means.
func (rt *runtime) unban(key netip.Prefix, actor string) bool {
	existed, err := rt.store().delete(key)
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
	if fs, ok := rt.store().(*fileStore); ok {
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
	rt.overridesStale = ""
	rt.overridesUnsaved = ""
	rt.applySettings(s)

	if err := rt.store().saveOverrides(ov); err != nil {
		rt.overridesUnsaved = err.Error()
		logWarn(rt.name, "rule changes are live but could not be saved",
			map[string]interface{}{"error": err.Error()})
	}
	// Persist immediately rather than waiting for the janitor: an operator who
	// edits a rule and restarts Traefik a second later should not lose the edit.
	if fs, ok := rt.store().(*fileStore); ok {
		if err := fs.flush(); err != nil {
			rt.overridesUnsaved = err.Error()
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
// configuration, what the file says, which sections the console has taken over,
// and — when a reload invalidated them — why those sections are NOT in force.
func (rt *runtime) rulesView() (v rulesViewData, err error) {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	if rt.baseConfig == nil {
		return v, errors.New("no detection middleware has been configured for this instance yet")
	}
	v.fromFile = editableFrom(rt.baseConfig)
	v.overrides = rt.overrides.clone()
	v.stale = rt.overridesStale
	v.unsaved = rt.overridesUnsaved
	if rt.overridesStale != "" {
		// The saved edits do not apply to the current file configuration, so the
		// file configuration is what runs. Reporting the layered set as effective
		// told the operator rules were in force that were not.
		v.effective = v.fromFile
		return v, nil
	}
	merged, err := applyOverrides(rt.baseConfig, rt.overrides)
	if err != nil {
		return v, err
	}
	v.effective = editableFrom(merged)
	return v, nil
}

// rulesViewData is what rulesView hands the API.
type rulesViewData struct {
	effective, fromFile editableConfig
	overrides           *Overrides
	stale, unsaved      string
}

// syncOverrides adopts a rule set changed by another replica.
//
// Only the shared backends can produce one — with a local store the value read
// back is the value this process wrote, so the timestamp matches and nothing
// happens.
func (rt *runtime) syncOverrides() {
	stored := rt.store().loadOverrides()

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if sameOverrideStamp(rt.overrides, stored) {
		// The shared store holds what this replica runs, so a save that could
		// not be published at the time has been published since.
		rt.overridesUnsaved = ""
		return
	}
	if err := stored.compatible(); err != nil {
		// Another replica runs a different build. Its rule set is neither applied
		// nor touched — it is that replica's to own — and this is said once per
		// saved version rather than once per janitor tick.
		warnOnce(rt.name, "overrides-schema:"+stored.Updated.UTC().Format(time.RFC3339Nano),
			"the shared rule set was written by a different version of the rule schema and is "+
				"ignored on this replica; the file configuration is in force here",
			map[string]interface{}{"error": err.Error(), "savedAt": stored.Updated})
		return
	}
	s, err := rt.rebuildLocked(stored)
	if err != nil {
		logWarn(rt.name, "a rule set from the shared store could not be applied and has been ignored",
			map[string]interface{}{"error": err.Error()})
		return
	}
	rt.overrides = stored
	rt.overridesStale = ""
	rt.overridesUnsaved = ""
	rt.applySettings(s)
	if stored == nil {
		logInfo(rt.name, "console rule changes were reverted on another replica; the file configuration is back in force", nil)
		return
	}
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

// storeFingerprint captures the fields that require rebuilding the state
// backend: the backend itself and the connection details the ACTIVE backend
// reads. A file path means nothing to a Redis store and a Redis address nothing
// to a file store, and store.maxEntries is applied in place by applySettings.
//
// A map rather than a struct, and hashed through mapFingerprint's concrete
// parameter type — see configFingerprint for why the distinction matters.
func storeFingerprint(s *settings) string {
	m := map[string]string{"backend": s.storeBackend}
	switch s.storeBackend {
	case "file":
		m["path"] = s.storePath
	case "redis":
		m["redisAddr"] = s.redis.Address
		m["redisDB"] = strconv.Itoa(s.redis.DB)
		m["redisKey"] = s.redis.KeyPrefix
		// The credential and the deadline are connection state the client is
		// built with; left out, a rotated Redis password needed a Traefik restart.
		m["redisPassword"] = s.redis.Password
		m["redisTimeout"] = s.redisTimeout.String()
	}
	return mapFingerprint(m)
}

// notifyFingerprint captures what a notifier is built from.
func notifyFingerprint(s *settings) string {
	cfg, err := json.Marshal(&s.notify)
	if err != nil {
		return ""
	}
	return mapFingerprint(map[string]string{
		"instance": s.instanceName,
		"notify":   string(cfg),
		"timeout":  s.notifyTimeout.String(),
		"cacheTTL": s.abuseCacheTTL.String(),
	})
}

// geoFingerprint captures what a geo cache is built from.
func geoFingerprint(s *settings) string {
	return mapFingerprint(map[string]string{
		"instance": s.instanceName,
		"enabled":  strconv.FormatBool(s.geoEnabled),
		"provider": s.geoProvider,
		"ttl":      s.geoCacheTTL.String(),
	})
}

// configFingerprint hashes a whole plugin configuration. acquireRuntime compares
// it to decide whether a Traefik reload actually changed anything.
//
// The parameter is *Config, NOT interface{}, and that is the entire point. Yaegi
// empties an interpreted struct when it passes through an interface{} parameter:
// json.Marshal then returns "{}" — with a nil error — so every configuration
// hashed to sha256("{}") and compared equal. acquireRuntime therefore took its
// "nothing changed" branch on every reload, and NO configuration change in the
// dynamic file ever reached the running middleware. Not the admin token, not the
// allowlist, not a detector threshold. It failed silently and looked like Traefik
// refusing to reload; only a Traefik restart, which builds the runtime from
// scratch, applied anything.
//
// Compiled Go marshals the same value correctly through interface{}, so `go test`
// cannot see this. tools/yaegi-smoke asserts the reload path end to end instead.
//
// Keep every fingerprint helper's parameter concretely typed for the same reason,
// and never route one through a shared interface{} helper again.
//
// detectors.userAgent.crawlers is EXCLUDED from the hash. It is the one
// per-router setting (see handler.crawlers), so the intended configuration is two
// middleware definitions sharing an instanceName and differing only in that
// value. Hashing it would make them look like two different configurations, so
// every reload would rebuild and republish the shared settings twice — once per
// sibling, in whatever order Traefik built them.
//
// A DECLARED policy would survive that anyway, because each handler captures its
// own value in New(). What the exclusion actually buys is: no pointless settings
// churn on every reload, and a stable value for the instance-wide fallback that
// definitions stating no policy inherit. Excluding it makes the two siblings hash
// equal, so the shared settings simply stay put.
//
// Definitions that differ in anything ELSE still fight, exactly as before. Keep
// siblings identical apart from this one key.
func configFingerprint(c *Config) string {
	// Shallow copy: Detectors and UserAgent are struct values, so blanking the
	// field on the copy cannot touch the caller's config. Slices are shared but
	// never mutated here. Same idiom as inheritAdmin, which Yaegi already runs.
	stripped := *c
	stripped.Detectors.UserAgent.Crawlers = ""
	buf, err := json.Marshal(&stripped)
	if err != nil {
		return ""
	}
	return hashOf(buf)
}

// mapFingerprint hashes a plain string map. Concretely typed, as above.
func mapFingerprint(m map[string]string) string {
	buf, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return hashOf(buf)
}

// hashOf reduces already-encoded bytes to a short stable string.
func hashOf(buf []byte) string {
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:8])
}
