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
	"sync/atomic"
	"time"
)

// Delivery runs through one package-level queue drained by a fixed pool of
// workers. Package-level on purpose: a configuration reload replaces the
// notifier, and a pool owned by the notifier would leak its goroutines on every
// reload. Each job carries the notifier it was queued by, so a reload mid-flight
// delivers the old event with the old notifier's targets, which is correct.
//
// It used to be a semaphore with no queue: a slot or a drop. The janitor records
// every expired ban of a tick in one tight loop, so any scan that banned more
// than 32 sources inside a thirty-second window expired them in one tick an hour
// later, and every unban past the 32nd was dropped — silently, with no counter
// and no log line — while docs/webhooks.md promised a firewall helper the unban
// for every ban. The queue absorbs a tick's worth of expiries; a drop is still
// possible under a sustained flood against a slow endpoint, and is now counted
// (stats.notifyDropped) and logged.
const (
	notifyQueueSize = 1024
	notifyWorkers   = 8
)

type notifyJob struct {
	n *notifier
	e Event
}

var (
	notifyQueue     = make(chan notifyJob, notifyQueueSize)
	notifyStartOnce sync.Once
	// notifyDropWarnMu and notifyDropWarnAt throttle the queue-full warning to
	// one a minute, with the number dropped since the last one.
	notifyDropWarnMu   sync.Mutex
	notifyDropWarnAt   time.Time
	notifyDroppedSince int64
	// notifyPending counts events queued or being delivered: raised before the
	// send into the queue, lowered when the delivery returns (or the event is
	// dropped). Zero means nothing is in flight anywhere.
	notifyPending atomic.Int64
)

func startNotifyWorkers() {
	notifyStartOnce.Do(func() {
		for i := 0; i < notifyWorkers; i++ {
			go func() {
				for job := range notifyQueue {
					func() {
						defer notifyPending.Add(-1)
						defer recoverPanic(job.n.instance, "notifier")
						job.n.send(job.e)
					}()
				}
			}()
		}
	})
}

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
	client   *http.Client

	// dropped counts events this notifier could not queue. The runtime points
	// it at stats.NotifyDropped so the console can show it; a notifier built
	// on its own counts into a counter of its own.
	dropped *atomic.Int64

	// reported deduplicates AbuseIPDB submissions: reporting the same address
	// repeatedly is both rude and rate-limited.
	mu       sync.Mutex
	reported map[string]time.Time
	scores   map[string]abuseScore
	cacheTTL time.Duration
	inflight map[string]struct{}

	// abuseBase is the AbuseIPDB API root (notify.abuseipdb.endpoint). A
	// setting rather than a constant so the tests and the interpreter smoke test
	// can point it at an httptest server: outbound calls that only ever run
	// against a live third party are outbound calls nobody has actually tested.
	abuseBase string
}

// abuseIPDBBase is the real API root.
const abuseIPDBBase = "https://api.abuseipdb.com"

type abuseScore struct {
	confidence int
	fetched    time.Time
	// failed marks a negative-cache entry: the lookup did not succeed, and the
	// address is not asked about again until abuseFailureTTL has passed.
	failed bool
}

// rememberFailure records that a lookup for ip did not produce a score.
func (n *notifier) rememberFailure(ip string) {
	n.mu.Lock()
	n.scores[ip] = abuseScore{fetched: time.Now(), failed: true}
	n.mu.Unlock()
}

func newNotifier(s *settings) *notifier {
	return &notifier{
		instance:  s.instanceName,
		webhooks:  s.notify.Webhooks,
		chat:      s.notify.Chat,
		abuse:     s.notify.AbuseIPDB,
		client:    &http.Client{Timeout: s.notifyTimeout},
		dropped:   new(atomic.Int64),
		reported:  make(map[string]time.Time),
		scores:    make(map[string]abuseScore),
		inflight:  make(map[string]struct{}),
		cacheTTL:  s.abuseCacheTTL,
		abuseBase: s.abuseEndpoint,
	}
}

func (n *notifier) enabled() bool {
	if n == nil {
		return false
	}
	return len(n.webhooks) > 0 || n.chat.Kind != "" || (n.abuse.Enabled && n.abuse.Report)
}

// dispatch queues an event for delivery and returns immediately. With the
// queue full the event is dropped, counted and (throttled) logged: growing an
// unbounded goroutine population inside Traefik is the worse outcome.
func (n *notifier) dispatch(e Event) {
	if !n.enabled() {
		return
	}
	startNotifyWorkers()
	notifyPending.Add(1)
	select {
	case notifyQueue <- notifyJob{n: n, e: e}:
	default:
		notifyPending.Add(-1)
		n.dropped.Add(1)
		noteNotifyDrop(n.instance)
	}
}

func noteNotifyDrop(instance string) {
	notifyDropWarnMu.Lock()
	notifyDroppedSince++
	throttled := time.Since(notifyDropWarnAt) < time.Minute
	dropped := notifyDroppedSince
	if !throttled {
		notifyDropWarnAt = time.Now()
		notifyDroppedSince = 0
	}
	notifyDropWarnMu.Unlock()
	if throttled {
		return
	}
	logWarn(instance, "notification queue is full; ban and unban events are being dropped and a webhook "+
		"consumer may now be out of step with the ban list",
		map[string]interface{}{"dropped": dropped, "queue": notifyQueueSize})
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

// webhookPayload is the body of a webhook delivery. A named struct, like every
// admin response: a map[string]interface{} holding the Event encodes the event
// as {} under Yaegi, and the smoke test could not have told (see RulesResponse).
type webhookPayload struct {
	Source   string `json:"source"`
	Instance string `json:"instance"`
	Event    Event  `json:"event"`
}

// sendWebhook posts the event as JSON. This is also the integration point for OS
// firewall enforcement: a small privileged helper container subscribes here and
// applies nftables rules, because os/exec does not exist under the Yaegi
// interpreter and Traefik cannot manipulate the host firewall itself.
func (n *notifier) sendWebhook(w WebhookConfig, e Event) {
	payload, err := json.Marshal(webhookPayload{Source: "scanguard", Instance: n.instance, Event: e})
	if err != nil {
		return
	}

	method := strings.ToUpper(strings.TrimSpace(w.Method))
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequest(method, w.URL, bytes.NewReader(payload))
	if err != nil {
		logWarn(n.instance, "webhook request could not be built", map[string]interface{}{"url": redactURL(w.URL), "error": errText(err)})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "scanguard")
	for k, v := range w.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		logWarn(n.instance, "webhook delivery failed", map[string]interface{}{"url": redactURL(w.URL), "error": errText(err)})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		logWarn(n.instance, "webhook rejected the event", map[string]interface{}{
			"url":    redactURL(w.URL),
			"status": resp.StatusCode,
		})
	}
}

// errText renders a transport error without the URL that net/http folds into
// it. http.Client.Do wraps every failure in a *url.Error whose Error() embeds
// the full request URL — "Post \"https://discord.com/api/webhooks/1234/s3cr3t\":
// dial tcp ..." — so logging err.Error() beside redactURL printed the credential
// the redaction was added to hide.
func errText(err error) string {
	if ue, ok := err.(*url.Error); ok && ue.Err != nil {
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
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
		// allowed_mentions with nothing in parse: the text embeds the request
		// path, which the attacker chose, and "/@everyone/wp-login.php" pinged
		// the whole channel.
		body, err = json.Marshal(discordMessage{Content: text, AllowedMentions: discordMentions{Parse: []string{}}})
	case "slack":
		// Slack's message text is mrkdwn; a path carrying <!channel> is a
		// channel-wide ping unless the control characters are escaped.
		body, err = json.Marshal(map[string]string{"text": slackEscape(text)})
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
		logWarn(n.instance, "chat notification failed", map[string]interface{}{"kind": n.chat.Kind, "error": errText(err)})
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		// A deleted Discord webhook answers 404 forever; said in the log, as the
		// generic webhook path already did, instead of failing silently.
		logWarn(n.instance, "chat endpoint rejected the notification", map[string]interface{}{
			"kind":   n.chat.Kind,
			"status": resp.StatusCode,
		})
	}
}

// discordMessage and discordMentions are the Discord webhook body. Named
// structs for the reason webhookPayload is one.
type discordMessage struct {
	Content         string          `json:"content"`
	AllowedMentions discordMentions `json:"allowed_mentions"`
}

type discordMentions struct {
	Parse []string `json:"parse"`
}

// slackEscape applies Slack's three required escapes to text destined for a
// message body.
func slackEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	return strings.ReplaceAll(s, ">", "&gt;")
}

func describeEvent(e Event) string {
	switch e.Kind {
	case eventBan:
		verb := "banned"
		if e.DryRun {
			// The webhook payload carries dryRun and the console says "(dry)";
			// the chat message used to announce a stream of bans that did not
			// happen during exactly the dry-run rollout the README recommends.
			verb = "would have banned (dry run)"
		}
		msg := fmt.Sprintf("🛡️ scanguard %s %s (%s)", verb, e.Key, e.Detector)
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
		if e.DryRun {
			return fmt.Sprintf("✅ scanguard dry-run ban on %s ran out (by %s)", e.Key, who)
		}
		return fmt.Sprintf("✅ scanguard unbanned %s (by %s)", e.Key, who)
	default:
		return fmt.Sprintf("scanguard %s: %s", e.Kind, e.Key)
	}
}

// abuseCategories maps a detector to AbuseIPDB category IDs, or "" for a
// detector whose bans are not AbuseIPDB's business.
// 18 = Brute-Force, 19 = Bad Web Bot, 21 = Web App Attack.
//
// Two detectors are never reported. A crawler refused by policy is a commercial
// crawler, not an attacker, and filing AhrefsBot as a web-app attack is a false
// report under the operator's name. A reputation ban exists because AbuseIPDB
// said the address was bad; reporting it back is a feedback loop that confirms
// AbuseIPDB's own score to it. Port Scan (14) is gone from the default: an HTTP
// probe is not a port scan.
func abuseCategories(detector string) string {
	switch detector {
	case detectorCrawler, detectorReputation, detectorManual:
		return ""
	case detectorBruteForce:
		return "18"
	case detectorUserAgent, detectorUARotation:
		return "19"
	case detectorRateAbuse:
		return "18,19"
	default:
		return "21"
	}
}

func (n *notifier) reportAbuse(e Event) {
	ip := e.Client
	if ip == "" {
		return
	}
	categories := abuseCategories(e.Detector)
	if categories == "" {
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
	form.Set("categories", categories)
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
		logWarn(n.instance, "abuseipdb report failed", map[string]interface{}{"error": errText(err)})
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		logWarn(n.instance, "abuseipdb rejected the report", map[string]interface{}{"status": resp.StatusCode})
	}
}

// redactURL reduces a webhook URL to scheme and host for logging. Discord and
// Slack webhook URLs carry their credential in the path, and a transient outage
// used to write it to the Traefik log stream on every failed delivery.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(unparseable url)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// abuseInflightMax bounds concurrent reputation lookups, exactly as geoInflightMax
// does for country lookups. Without it every unseen source spawned its own
// outbound request: a distributed scan across ten thousand addresses meant ten
// thousand concurrent HTTPS calls from inside the reverse proxy.
const abuseInflightMax = 4

// abuseFailureTTL is how long a failed lookup is remembered as "unknown". The free
// tier allows a thousand checks a day, so once it starts answering 429 every later
// request from that address would otherwise retry — a storm that never converges
// because nothing was ever cached.
const abuseFailureTTL = time.Hour

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
	ttl := n.cacheTTL
	if ok && entry.failed {
		ttl = abuseFailureTTL
	}
	fresh := ok && time.Since(entry.fetched) < ttl
	if !fresh {
		if _, busy := n.inflight[ip]; !busy && len(n.inflight) < abuseInflightMax {
			n.inflight[ip] = struct{}{}
			go func() {
				defer recoverPanic(n.instance, "abuseipdb check")
				n.fetchScore(ip)
			}()
		}
	}
	n.mu.Unlock()

	if fresh && !entry.failed {
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
		n.rememberFailure(ip)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		n.rememberFailure(ip)
		return
	}

	var payload struct {
		Data struct {
			AbuseConfidenceScore int `json:"abuseConfidenceScore"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		// A body that is not the documented shape is a failed lookup too, and is
		// remembered as one, or the address was asked about again on every
		// request.
		n.rememberFailure(ip)
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

// formatDuration renders a ban duration for humans and for the event log:
// "1h", "1d", "7d", and for anything that is not a whole unit the exact value,
// "1h30m", "1d12h". It used to truncate to the largest whole unit, so a 90m rung
// was reported as "1h" and a 36h one as "1d" — in banFor, which is the only
// duration a webhook helper is given, and in the ban log line.
func formatDuration(d time.Duration) string {
	if d == permanent {
		return "permanent"
	}
	if d < time.Second {
		return "0s"
	}
	d = d.Round(time.Second)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	minutes := int(d / time.Minute)
	seconds := int((d - time.Duration(minutes)*time.Minute) / time.Second)

	var sb strings.Builder
	if days > 0 {
		sb.WriteString(strconv.Itoa(days) + "d")
	}
	if hours > 0 {
		sb.WriteString(strconv.Itoa(hours) + "h")
	}
	if minutes > 0 {
		sb.WriteString(strconv.Itoa(minutes) + "m")
	}
	if seconds > 0 {
		sb.WriteString(strconv.Itoa(seconds) + "s")
	}
	return sb.String()
}
