package scanguard

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// redisStore shares the ban list across Traefik replicas.
//
// Two design notes worth keeping in mind before changing anything here:
//
//  1. There is no third-party client. Mainstream Go Redis clients do not survive
//     the Yaegi interpreter — they lean on unsafe, heavy generics and reflection —
//     which is why the CrowdSec bouncer's author had to write a minimal one too.
//     This speaks just enough RESP2 to do the job, using nothing but net and bufio.
//
//  2. The request path never waits for the network. Redis is the authority, but
//     a local memStore is the read cache and a background poll refreshes it, the
//     way CrowdSec's stream mode works. That keeps a per-request lookup at one
//     map read. A ban is PUBLISHED off the request path as well, by a bounded
//     goroutine that never dials: with Redis down, a banning request used to wait
//     a full dial timeout, and the next one behind it another, serialised on the
//     client's mutex. Only the janitor dials, and what could not be published
//     waits in `pending` for it. A Redis outage therefore degrades to
//     per-replica enforcement rather than to an outage of its own.
type redisStore struct {
	*memStore
	client *respClient
	prefix string
	// unbanPrefix namespaces the expiry-notification claims; see claimExpiry.
	unbanPrefix string
	// overridesKey holds the console's rule edits, so a rule change made on one
	// replica reaches the others on their next refresh, exactly like a ban does.
	overridesKey string
	instance     string
	failOpen     bool

	// pending is what this replica owes Redis: bans whose SET failed or was
	// never attempted because Redis was unreachable, keys whose DEL failed, and
	// a rule set whose SET failed. refresh() settles the debt before it reads,
	// so a ban made during an outage reaches the other replicas once Redis is
	// back instead of being dropped by the next cache swap, and an unban made
	// during one does not come back from Redis.
	pendingMu            sync.Mutex
	pendingPut           map[string]Ban
	pendingDel           map[string]struct{}
	overridesUnpublished bool
	pendingWarnAt        time.Time

	// publishSem bounds the goroutines publishing bans. A ban that finds no
	// free slot joins pending and waits for the janitor.
	publishSem chan struct{}
}

// redisPublishers is how many bans may be in flight to Redis at once.
const redisPublishers = 8

// unbanClaimTTL is how long an expiry-notification claim is held in Redis:
// long enough for every replica's janitor to pass the expiry, short enough
// that the key costs nothing.
const unbanClaimTTL = 2 * time.Minute

func newRedisStore(s *settings) (*redisStore, error) {
	client := &respClient{
		addr:     s.redis.Address,
		password: s.redis.Password,
		db:       s.redis.DB,
		timeout:  s.redisTimeout,
	}
	rs := &redisStore{
		memStore:     newMemStore(s.maxEntries),
		client:       client,
		prefix:       s.redis.KeyPrefix + "ban:",
		unbanPrefix:  s.redis.KeyPrefix + "unban:",
		overridesKey: s.redis.KeyPrefix + "overrides",
		instance:     s.instanceName,
		failOpen:     s.failOpen,
		pendingPut:   make(map[string]Ban),
		pendingDel:   make(map[string]struct{}),
		publishSem:   make(chan struct{}, redisPublishers),
	}

	if err := rs.refresh(); err != nil {
		if !rs.failOpen {
			return nil, fmt.Errorf("store.redis: initial load failed and store.failOpen is false: %w", err)
		}
		logWarn(rs.instance, "could not load bans from redis at startup; continuing with an empty local cache",
			map[string]interface{}{"address": s.redis.Address, "error": err.Error()})
	}
	return rs, nil
}

func (r *redisStore) backend() string { return "redis" }

// put records the ban locally at once and publishes it to Redis off the
// request path. The local write is what this replica enforces from; the
// publication is what the other replicas will.
func (r *redisStore) put(b Ban) error {
	if err := r.memStore.put(b); err != nil {
		return err
	}
	select {
	case r.publishSem <- struct{}{}:
		go func() {
			defer func() { <-r.publishSem }()
			defer recoverPanic(r.instance, "redis publish")
			r.publishBan(b)
		}()
	default:
		r.deferPut(b)
	}
	return nil
}

// banArgs is the SET command for a ban, or nil for one that has already lapsed.
func (r *redisStore) banArgs(b Ban) ([]string, error) {
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	args := []string{"SET", r.prefix + b.Key, string(payload)}
	if !b.Permanent() {
		ttl := time.Until(b.Expires)
		if ttl <= 0 {
			return nil, nil
		}
		args = append(args, "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	}
	return args, nil
}

// publishBan writes one ban to Redis without ever dialing. Anything that goes
// wrong parks the ban in pending for the janitor's refresh to publish.
func (r *redisStore) publishBan(b Ban) {
	args, err := r.banArgs(b)
	if err != nil || args == nil {
		return
	}
	if _, err := r.client.doConnected(args...); err != nil {
		r.deferPut(b)
		r.warnPending(err)
	}
}

func (r *redisStore) deferPut(b Ban) {
	r.pendingMu.Lock()
	r.pendingPut[b.Key] = b
	delete(r.pendingDel, b.Key)
	r.pendingMu.Unlock()
}

// warnPending says, at most once a minute, that bans are being held back.
func (r *redisStore) warnPending(err error) {
	r.pendingMu.Lock()
	throttled := time.Since(r.pendingWarnAt) < time.Minute
	if !throttled {
		r.pendingWarnAt = time.Now()
	}
	waiting := len(r.pendingPut) + len(r.pendingDel)
	r.pendingMu.Unlock()
	if throttled {
		return
	}
	logWarn(r.instance, "could not publish to redis; changes are enforced on this replica only until the next refresh publishes them",
		map[string]interface{}{"error": err.Error(), "pending": waiting})
}

// delete removes the ban locally and from Redis. Existence is answered from the
// DEL reply as well as the local cache: a ban another replica wrote seconds ago
// is in Redis but not yet in this replica's cache, and "No ban found" for it was
// wrong, and emitted no unban event.
func (r *redisStore) delete(key netip.Prefix) (bool, error) {
	existed, err := r.memStore.delete(key)
	if err != nil {
		return existed, err
	}
	r.pendingMu.Lock()
	delete(r.pendingPut, key.String())
	r.pendingMu.Unlock()

	reply, derr := r.client.doConnected("DEL", r.prefix+key.String())
	if derr != nil {
		r.pendingMu.Lock()
		r.pendingDel[key.String()] = struct{}{}
		r.pendingMu.Unlock()
		r.warnPending(derr)
		return existed, nil
	}
	return existed || reply.str == "1", nil
}

func (r *redisStore) flush() error { return nil }

// saveOverrides records the console's rule edits locally and publishes them.
// A failed publication is an error the caller hears about — the console used to
// report "Rules applied" while the next refresh adopted the stale shared copy
// and reverted the edit — and is retried by refresh until it succeeds or a
// newer set arrives from another replica.
func (r *redisStore) saveOverrides(ov *Overrides) error {
	if err := r.memStore.saveOverrides(ov); err != nil {
		return err
	}
	if err := r.publishOverrides(ov); err != nil {
		r.pendingMu.Lock()
		r.overridesUnpublished = true
		r.pendingMu.Unlock()
		return fmt.Errorf("rule changes apply on this replica only until redis is reachable: %w", err)
	}
	r.pendingMu.Lock()
	r.overridesUnpublished = false
	r.pendingMu.Unlock()
	return nil
}

func (r *redisStore) publishOverrides(ov *Overrides) error {
	payload, err := json.Marshal(ov)
	if err != nil {
		return err
	}
	_, err = r.client.do("SET", r.overridesKey, string(payload))
	return err
}

// claimExpiry decides which replica announces that a ban has expired. Every
// replica's janitor sweeps its own cache and finds the same lapsed entry, so
// without a claim one expiry was N webhooks and N chat messages. SET NX on a
// short-lived key lets exactly one through. With Redis unreachable every
// replica claims: duplicates beat silence for a firewall helper waiting on
// the unban.
func (r *redisStore) claimExpiry(key string) bool {
	reply, err := r.client.doConnected("SET", r.unbanPrefix+key, "1", "NX", "PX",
		strconv.FormatInt(unbanClaimTTL.Milliseconds(), 10))
	if err != nil {
		return true
	}
	return !reply.null
}

// refresh rebuilds the local cache from Redis. It is called by the janitor
// goroutine, never from the request path, and it is the only caller that dials.
func (r *redisStore) refresh() error {
	start := time.Now()
	if err := r.client.connect(); err != nil {
		return err
	}
	r.settlePending()
	r.refreshOverrides()

	keys, err := r.client.scan(r.prefix + "*")
	if err != nil {
		return err
	}

	now := time.Now()
	var bans []Ban
	// An empty keyspace is an answer, not a condition to skip: the last ban was
	// unbanned on another replica, or expired, and this replica must stop
	// enforcing it. Returning early here kept the local cache as it was, so an
	// unban never propagated once it emptied the keyspace.
	if len(keys) > 0 {
		values, err := r.client.mget(keys)
		if err != nil {
			return err
		}
		bans = make([]Ban, 0, len(values))
		for _, raw := range values {
			if raw == "" {
				continue
			}
			var b Ban
			if err := json.Unmarshal([]byte(raw), &b); err != nil {
				continue
			}
			if b.active(now) {
				bans = append(bans, b)
			}
		}
	}

	// One atomic swap; see memStore.replaceAll for why not empty-then-restore.
	// Two kinds of local entry survive it although Redis does not hold them: a
	// ban put while SCAN and MGET were running, which Redis will hold by the
	// next refresh, and one that is still waiting to be published. Dropping
	// either re-detected the source and issued a duplicate ban event.
	r.pendingMu.Lock()
	pending := make(map[string]struct{}, len(r.pendingPut))
	for k := range r.pendingPut {
		pending[k] = struct{}{}
	}
	deleted := make(map[string]struct{}, len(r.pendingDel))
	for k := range r.pendingDel {
		deleted[k] = struct{}{}
	}
	r.pendingMu.Unlock()
	kept := bans[:0]
	for _, b := range bans {
		if _, gone := deleted[b.Key]; !gone {
			kept = append(kept, b)
		}
	}
	r.replaceAllKeeping(kept, now, func(local *Ban) bool {
		if _, waiting := pending[local.Key]; waiting {
			return true
		}
		return !local.Created.Before(start)
	})
	return nil
}

// settlePending publishes what earlier request-path calls could not. Failures
// stay pending for the next tick.
func (r *redisStore) settlePending() {
	r.pendingMu.Lock()
	puts := make([]Ban, 0, len(r.pendingPut))
	for _, b := range r.pendingPut {
		puts = append(puts, b)
	}
	dels := make([]string, 0, len(r.pendingDel))
	for k := range r.pendingDel {
		dels = append(dels, k)
	}
	r.pendingMu.Unlock()

	for _, b := range puts {
		args, err := r.banArgs(b)
		if err != nil || args == nil {
			r.pendingMu.Lock()
			delete(r.pendingPut, b.Key)
			r.pendingMu.Unlock()
			continue
		}
		if _, err := r.client.do(args...); err != nil {
			return
		}
		r.pendingMu.Lock()
		if cur, ok := r.pendingPut[b.Key]; ok && cur.Created.Equal(b.Created) {
			delete(r.pendingPut, b.Key)
		}
		r.pendingMu.Unlock()
	}
	for _, k := range dels {
		if _, err := r.client.do("DEL", r.prefix+k); err != nil {
			return
		}
		r.pendingMu.Lock()
		delete(r.pendingDel, k)
		r.pendingMu.Unlock()
	}
}

// refreshOverrides reconciles the shared rule set with the local one.
//
// Normally the shared copy wins: a save on another replica is adopted here on
// the next tick (runtime.syncOverrides notices the changed stamp). The one
// exception is a local set that could not be published yet: it is published
// now, unless the shared copy is NEWER, in which case the other replica's save
// stands and the unpublished one is dropped, loudly. Adopting the stale shared
// copy over an unpublished local save is what used to revert console edits
// with "adopted a rule set changed on another replica" as the only trace.
func (r *redisStore) refreshOverrides() {
	reply, err := r.client.do("GET", r.overridesKey)
	if err != nil {
		return
	}
	var shared *Overrides
	switch {
	case reply.null, reply.str == "", reply.str == "null":
		// A revert on any replica publishes JSON null: no console rules anywhere.
		// Decoded into an Overrides it became an empty rule set of schema version
		// 0, which every other replica refused as "a different version of the
		// rule schema" while it kept enforcing the reverted rules.
		shared = nil
	default:
		var ov Overrides
		if err := json.Unmarshal([]byte(reply.str), &ov); err != nil {
			logWarn(r.instance, "shared rule set in redis could not be decoded; keeping the local one",
				map[string]interface{}{"error": err.Error()})
			return
		}
		shared = &ov
	}

	r.pendingMu.Lock()
	unpublished := r.overridesUnpublished
	r.pendingMu.Unlock()
	if unpublished {
		local := r.memStore.loadOverrides()
		if shared == nil || local == nil || !shared.Updated.After(local.Updated) {
			if perr := r.publishOverrides(local); perr != nil {
				return
			}
			r.pendingMu.Lock()
			r.overridesUnpublished = false
			r.pendingMu.Unlock()
			logInfo(r.instance, "published the rule changes that were saved while redis was unreachable", nil)
			return
		}
		logWarn(r.instance, "rule changes saved on this replica while redis was unreachable were superseded by a newer set from another replica",
			map[string]interface{}{"savedAt": local.Updated, "sharedAt": shared.Updated})
		r.pendingMu.Lock()
		r.overridesUnpublished = false
		r.pendingMu.Unlock()
	}
	if reply.null || reply.str == "" {
		return
	}
	_ = r.memStore.saveOverrides(shared)
}

// respClient is a minimal, synchronous RESP2 client: one connection guarded by a
// mutex. Ban traffic is low volume, so a connection pool would be complexity
// without benefit.
//
// Two entry points: do dials when there is no connection and is for the janitor;
// doConnected never dials and is for the request path and the console, which
// must not wait a dial timeout on a Redis that is down.
type respClient struct {
	mu       sync.Mutex
	conn     net.Conn
	rw       *bufio.ReadWriter
	addr     string
	password string
	db       int
	timeout  time.Duration
}

// errRedisDown is what doConnected returns when there is no connection to use.
var errRedisDown = errors.New("redis: not connected; the next refresh will reconnect")

// redisReplyError is a `-ERR ...` reply from the server. The connection is
// healthy after one — Redis answered — so unlike an I/O or protocol error it
// must not drop the connection.
type redisReplyError struct{ msg string }

func (e *redisReplyError) Error() string { return "redis: " + e.msg }

func isReplyError(err error) bool {
	_, ok := err.(*redisReplyError)
	return ok
}

func (c *respClient) dialLocked() error {
	if c.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout("tcp", c.addr, c.timeout)
	if err != nil {
		return fmt.Errorf("dial redis %s: %w", c.addr, err)
	}
	c.conn = conn
	c.rw = bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))

	if c.password != "" {
		if _, err := c.commandLocked("AUTH", c.password); err != nil {
			c.closeLocked()
			return fmt.Errorf("redis AUTH failed: %w", err)
		}
	}
	if c.db != 0 {
		if _, err := c.commandLocked("SELECT", strconv.Itoa(c.db)); err != nil {
			c.closeLocked()
			return fmt.Errorf("redis SELECT %d failed: %w", c.db, err)
		}
	}
	return nil
}

func (c *respClient) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
		c.rw = nil
	}
}

// connect makes sure there is a connection, dialing if needed.
func (c *respClient) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dialLocked()
}

// do runs one command, dialing first if needed. A connection that sat idle
// through a Redis restart or a server-side idle timeout fails on its first use
// with an I/O error; that case gets one redial and one retry, so a janitor tick
// does not report an outage that is already over.
func (c *respClient) do(args ...string) (respValue, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fresh := c.conn == nil
	if err := c.dialLocked(); err != nil {
		return respValue{}, err
	}
	v, err := c.commandLocked(args...)
	if err == nil || isReplyError(err) {
		return v, err
	}
	// The connection is in an unknown state after a protocol or I/O error;
	// drop it so the next call starts clean.
	c.closeLocked()
	if fresh {
		return respValue{}, err
	}
	if derr := c.dialLocked(); derr != nil {
		return respValue{}, derr
	}
	v, err = c.commandLocked(args...)
	if err != nil && !isReplyError(err) {
		c.closeLocked()
	}
	return v, err
}

// doConnected runs one command on the existing connection and never dials.
func (c *respClient) doConnected(args ...string) (respValue, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn == nil {
		return respValue{}, errRedisDown
	}
	v, err := c.commandLocked(args...)
	if err != nil && !isReplyError(err) {
		c.closeLocked()
	}
	return v, err
}

func (c *respClient) commandLocked(args ...string) (respValue, error) {
	if err := c.conn.SetDeadline(time.Now().Add(c.timeout)); err != nil {
		return respValue{}, err
	}

	var sb strings.Builder
	sb.WriteString("*")
	sb.WriteString(strconv.Itoa(len(args)))
	sb.WriteString("\r\n")
	for _, a := range args {
		sb.WriteString("$")
		sb.WriteString(strconv.Itoa(len(a)))
		sb.WriteString("\r\n")
		sb.WriteString(a)
		sb.WriteString("\r\n")
	}
	if _, err := c.rw.WriteString(sb.String()); err != nil {
		return respValue{}, err
	}
	if err := c.rw.Flush(); err != nil {
		return respValue{}, err
	}
	return readReply(c.rw.Reader)
}

// scan walks the keyspace with SCAN, which unlike KEYS does not block the server.
func (c *respClient) scan(pattern string) ([]string, error) {
	cursor := "0"
	out := []string{}
	for i := 0; ; i++ {
		v, err := c.do("SCAN", cursor, "MATCH", pattern, "COUNT", "500")
		if err != nil {
			return nil, err
		}
		if len(v.arr) != 2 {
			return nil, errors.New("redis SCAN returned an unexpected reply shape")
		}
		cursor = v.arr[0].str
		for _, k := range v.arr[1].arr {
			out = append(out, k.str)
		}
		if cursor == "0" {
			return out, nil
		}
		// A pathological keyspace must not spin here forever.
		if i > 10000 {
			return out, errors.New("redis SCAN did not terminate")
		}
	}
}

func (c *respClient) mget(keys []string) ([]string, error) {
	out := make([]string, 0, len(keys))
	// MGET with an unbounded argument list can exceed the server's buffer, so batch.
	const batch = 256
	for start := 0; start < len(keys); start += batch {
		end := start + batch
		if end > len(keys) {
			end = len(keys)
		}
		args := append([]string{"MGET"}, keys[start:end]...)
		v, err := c.do(args...)
		if err != nil {
			return nil, err
		}
		for _, e := range v.arr {
			out = append(out, e.str)
		}
	}
	return out, nil
}

// respValue is a decoded RESP2 reply. Integer replies are kept as their text:
// the only count acted on is DEL's, compared as a string.
type respValue struct {
	str  string
	arr  []respValue
	null bool
}

func readReply(r *bufio.Reader) (respValue, error) {
	line, err := readLine(r)
	if err != nil {
		return respValue{}, err
	}
	if len(line) == 0 {
		return respValue{}, errors.New("redis: empty reply line")
	}

	kind, body := line[0], line[1:]
	switch kind {
	case '+':
		return respValue{str: body}, nil
	case '-':
		return respValue{str: body}, &redisReplyError{msg: body}
	case ':':
		if _, cerr := strconv.ParseInt(body, 10, 64); cerr != nil {
			return respValue{}, fmt.Errorf("redis: bad integer reply %q", body)
		}
		return respValue{str: body}, nil
	case '$':
		n, cerr := strconv.Atoi(body)
		if cerr != nil {
			return respValue{}, fmt.Errorf("redis: bad bulk length %q", body)
		}
		if n < 0 {
			return respValue{null: true}, nil
		}
		buf := make([]byte, n+2) // payload plus trailing CRLF
		if _, err := io.ReadFull(r, buf); err != nil {
			return respValue{}, err
		}
		return respValue{str: string(buf[:n])}, nil
	case '*':
		n, cerr := strconv.Atoi(body)
		if cerr != nil {
			return respValue{}, fmt.Errorf("redis: bad array length %q", body)
		}
		if n < 0 {
			return respValue{null: true}, nil
		}
		items := make([]respValue, 0, n)
		for i := 0; i < n; i++ {
			item, err := readReply(r)
			if err != nil {
				return respValue{}, err
			}
			items = append(items, item)
		}
		return respValue{arr: items}, nil
	default:
		return respValue{}, fmt.Errorf("redis: unknown reply type %q", string(kind))
	}
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
