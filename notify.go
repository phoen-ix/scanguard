package scanguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// notifySem caps how many outbound notification requests may be in flight across
// the whole process. It is package-level on purpose: a configuration reload
// replaces the notifier, and a worker pool owned by the notifier would leak its
// goroutines on every reload. When the semaphore is saturated, notifications are
// dropped rather than queued — the alternative under a ban flood is spawning an
// unbounded number of goroutines inside the reverse proxy.
var notifySem = make(chan struct{}, 32)

// notifier pushes ban and unban events outside the plugin.
//
// Every send happens off the request path. A slow webhook must never add latency
// to a user's request, and a webhook that is down must never be able to stall
// Traefik.
type notifier struct {
	instance string
	webhooks []WebhookConfig
	chat     ChatConfig
	abuse    AbuseIPDBConfig
	timeout  time.Duration
	client   *http.Client

	// reported deduplicates AbuseIPDB submissions: reporting the same address
	// repeatedly is both rude and rate-limited.
	mu       sync.Mutex
	reported map[string]time.Time
	scores   map[string]abuseScore
	cacheTTL time.Duration
	inflight map[string]struct{}

	// abuseBase is the AbuseIPDB API root. It is a field rather than a constant so
	// the tests can point it at an httptest server: outbound calls that only ever
	// run against a live third party are outbound calls nobody has actually tested.
	abuseBase string
}

// abuseIPDBBase is the real API root.
const abuseIPDBBase = "https://api.abuseipdb.com"

type abuseScore struct {
	confidence int
	fetched    time.Time
}

func newNotifier(s *settings) *notifier {
	return &notifier{
		instance:  s.instanceName,
		webhooks:  s.notify.Webhooks,
		chat:      s.notify.Chat,
		abuse:     s.notify.AbuseIPDB,
		timeout:   s.notifyTimeout,
		client:    &http.Client{Timeout: s.notifyTimeout},
		reported:  make(map[string]time.Time),
		scores:    make(map[string]abuseScore),
		inflight:  make(map[string]struct{}),
		cacheTTL:  s.abuseCacheTTL,
		abuseBase: abuseIPDBBase,
	}
}

func (n *notifier) enabled() bool {
	if n == nil {
		return false
	}
	return len(n.webhooks) > 0 || n.chat.Kind != "" || (n.abuse.Enabled && n.abuse.Report)
}

// dispatch queues an event for delivery and returns immediately.
func (n *notifier) dispatch(e Event) {
	if !n.enabled() {
		return
	}
	select {
	case notifySem <- struct{}{}:
	default:
		// Saturated. Dropping a notification is strictly better than growing an
		// unbounded goroutine population inside Traefik.
		return
	}

	go func() {
		defer func() { <-notifySem }()
		defer recoverPanic(n.instance, "notifier")
		n.send(e)
	}()
}

func (n *notifier) send(e Event) {
	for _, w := range n.webhooks {
		if !wantsEvent(w.Events, e.Kind) {
			continue
		}
		n.sendWebhook(w, e)
	}
	if n.chat.Kind != "" && wantsEvent(n.chat.Events, e.Kind) {
		n.sendChat(e)
	}
	if n.abuse.Enabled && n.abuse.Report && e.Kind == eventBan && !e.DryRun {
		n.reportAbuse(e)
	}
}

// wantsEvent reports whether a target subscribes to this event kind. An empty
// filter means "ban and unban", which is what almost everyone wants.
func wantsEvent(filter []string, kind string) bool {
	if len(filter) == 0 {
		return kind == eventBan || kind == eventUnban
	}
	for _, f := range filter {
		if strings.EqualFold(strings.TrimSpace(f), kind) {
			return true
		}
	}
	return false
}

// sendWebhook posts the event as JSON. This is also the integration point for OS
// firewall enforcement: a small privileged helper container subscribes here and
// applies nftables rules, because os/exec does not exist under the Yaegi
// interpreter and Traefik cannot manipulate the host firewall itself.
func (n *notifier) sendWebhook(w WebhookConfig, e Event) {
	payload, err := json.Marshal(map[string]interface{}{
		"source":   "scanguard",
		"instance": n.instance,
		"event":    e,
	})
	if err != nil {
		return
	}

	method := strings.ToUpper(strings.TrimSpace(w.Method))
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequest(method, w.URL, bytes.NewReader(payload))
	if err != nil {
		logWarn(n.instance, "webhook request could not be built", map[string]interface{}{"url": w.URL, "error": err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "scanguard")
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		logWarn(n.instance, "webhook delivery failed", map[string]interface{}{"url": w.URL, "error": err.Error()})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		logWarn(n.instance, "webhook rejected the event", map[string]interface{}{
			"url":    w.URL,
			"status": resp.StatusCode,
		})
	}
}

func (n *notifier) sendChat(e Event) {
	text := describeEvent(e)

	var (
		body        []byte
		contentType = "application/json"
		err         error
	)
	switch strings.ToLower(n.chat.Kind) {
	case "discord":
		body, err = json.Marshal(map[string]string{"content": text})
	case "slack":
		body, err = json.Marshal(map[string]string{"text": text})
	case "gotify":
		body, err = json.Marshal(map[string]interface{}{
			"title":    "scanguard",
			"message":  text,
			"priority": 5,
		})
	case "ntfy":
		body = []byte(text)
		contentType = "text/plain"
	default:
		return
	}
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, n.chat.URL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "scanguard")
	if strings.EqualFold(n.chat.Kind, "ntfy") {
		req.Header.Set("Title", "scanguard")
		req.Header.Set("Tags", "shield")
	}

	resp, err := n.client.Do(req)
	if err != nil {
		logWarn(n.instance, "chat notification failed", map[string]interface{}{"kind": n.chat.Kind, "error": err.Error()})
		return
	}
	defer func() { _ = resp.Body.Close() }()
}

func describeEvent(e Event) string {
	switch e.Kind {
	case eventBan:
		msg := fmt.Sprintf("🛡️ scanguard banned %s (%s)", e.Key, e.Detector)
		if e.Path != "" {
			msg += fmt.Sprintf(" for %s %s", e.Method, e.Path)
		}
		if e.BanFor != "" {
			msg += fmt.Sprintf(" — %s", e.BanFor)
		}
		if e.Country != "" {
			msg += fmt.Sprintf(" [%s]", e.Country)
		}
		return msg
	case eventUnban:
		who := e.Actor
		if who == "" {
			who = "unknown"
		}
		return fmt.Sprintf("✅ scanguard unbanned %s (by %s)", e.Key, who)
	default:
		return fmt.Sprintf("scanguard %s: %s", e.Kind, e.Key)
	}
}

// abuseCategories maps a detector to AbuseIPDB category IDs.
// 14 = Port Scan, 18 = Brute-Force, 19 = Bad Web Bot, 21 = Web App Attack.
func abuseCategories(detector string) string {
	switch detector {
	case detectorBruteForce:
		return "18"
	case detectorUserAgent:
		return "19"
	case detectorRateAbuse:
		return "18,19"
	case detectorPayload:
		return "21"
	default:
		return "21,14"
	}
}

func (n *notifier) reportAbuse(e Event) {
	ip := e.Client
	if ip == "" {
		return
	}

	n.mu.Lock()
	if last, seen := n.reported[ip]; seen && time.Since(last) < 15*time.Minute {
		n.mu.Unlock()
		return
	}
	n.reported[ip] = time.Now()
	if len(n.reported) > 10000 {
		n.reported = map[string]time.Time{ip: time.Now()}
	}
	n.mu.Unlock()

	comment := fmt.Sprintf("Blocked by scanguard: %s", e.Detector)
	if e.Path != "" {
		comment += fmt.Sprintf(" (%s %s)", e.Method, e.Path)
	}

	form := url.Values{}
	form.Set("ip", ip)
	form.Set("categories", abuseCategories(e.Detector))
	form.Set("comment", truncate(comment, 900))

	req, err := http.NewRequest(http.MethodPost, n.abuseBase+"/api/v2/report",
		strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Key", n.abuse.APIKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.client.Do(req)
	if err != nil {
		logWarn(n.instance, "abuseipdb report failed", map[string]interface{}{"error": err.Error()})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		logWarn(n.instance, "abuseipdb rejected the report", map[string]interface{}{"status": resp.StatusCode})
	}
}

// score returns a cached AbuseIPDB confidence for an address.
//
// It never blocks. On a cache miss it schedules a background fetch and reports
// "unknown", because putting a third-party API call on the request path would
// hand that API the ability to add latency to — or stall — every request.
func (n *notifier) score(ip string) (int, bool) {
	if n == nil || !n.abuse.Enabled || !n.abuse.Check || ip == "" {
		return 0, false
	}

	n.mu.Lock()
	entry, ok := n.scores[ip]
	fresh := ok && time.Since(entry.fetched) < n.cacheTTL
	if !fresh {
		if _, busy := n.inflight[ip]; !busy {
			n.inflight[ip] = struct{}{}
			go func() {
				defer recoverPanic(n.instance, "abuseipdb check")
				n.fetchScore(ip)
			}()
		}
	}
	n.mu.Unlock()

	if fresh {
		return entry.confidence, true
	}
	return 0, false
}

func (n *notifier) fetchScore(ip string) {
	defer func() {
		n.mu.Lock()
		delete(n.inflight, ip)
		n.mu.Unlock()
	}()

	endpoint := n.abuseBase + "/api/v2/check?maxAgeInDays=90&ipAddress=" + url.QueryEscape(ip)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Key", n.abuse.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return
	}

	var payload struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return
	}

	n.mu.Lock()
	if len(n.scores) > 20000 {
		n.scores = make(map[string]abuseScore)
	}
	n.scores[ip] = abuseScore{confidence: payload.Data.AbuseConfidenceScore, fetched: time.Now()}
	n.mu.Unlock()
}

// minConfidence is the threshold above which a cached AbuseIPDB score is treated
// as a detection in its own right.
func (n *notifier) minConfidence() int {
	if n == nil {
		return 0
	}
	if n.abuse.MinConfidence <= 0 {
		return 75
	}
	return n.abuse.MinConfidence
}

// formatDuration renders a ban duration for humans and for the event log.
func formatDuration(d time.Duration) string {
	if d == permanent {
		return "permanent"
	}
	if d < time.Minute {
		return strconv.Itoa(int(d.Seconds())) + "s"
	}
	if d < time.Hour {
		return strconv.Itoa(int(d.Minutes())) + "m"
	}
	if d < 24*time.Hour {
		return strconv.Itoa(int(d.Hours())) + "h"
	}
	return strconv.Itoa(int(d.Hours()/24)) + "d"
}
