package scanguard

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
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
//  2. The request path never touches the network. Redis is the authority, but a
//     local memStore is the read cache and a background poll refreshes it, the way
//     CrowdSec's stream mode works. That keeps a per-request lookup at one map
//     read, and means a Redis outage degrades to per-replica enforcement rather
//     than to an outage of its own.
type redisStore struct {
	*memStore
	client *respClient
	prefix string
	// overridesKey holds the console's rule edits, so a rule change made on one
	// replica reaches the others on their next refresh, exactly like a ban does.
	overridesKey string
	instance     string
	failOpen     bool
}

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
		overridesKey: s.redis.KeyPrefix + "overrides",
		instance:     s.instanceName,
		failOpen:     s.failOpen,
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

func (r *redisStore) put(b Ban) error {
	if err := r.memStore.put(b); err != nil {
		return err
	}

	payload, err := json.Marshal(b)
	if err != nil {
		return err
	}
	args := []string{"SET", r.prefix + b.Key, string(payload)}
	if !b.Permanent() {
		ttl := time.Until(b.Expires)
		if ttl <= 0 {
			return nil
		}
		args = append(args, "PX", strconv.FormatInt(ttl.Milliseconds(), 10))
	}
	if _, err := r.client.do(args...); err != nil {
		logWarn(r.instance, "could not publish ban to redis; it is enforced on this replica only",
			map[string]interface{}{"key": b.Key, "error": err.Error()})
	}
	return nil
}

func (r *redisStore) delete(key netip.Prefix) (bool, error) {
	existed, err := r.memStore.delete(key)
	if err != nil {
		return existed, err
	}
	if _, derr := r.client.do("DEL", r.prefix+key.String()); derr != nil {
		logWarn(r.instance, "could not remove ban from redis; it may return on the next refresh",
			map[string]interface{}{"key": key.String(), "error": derr.Error()})
	}
	return existed, nil
}

func (r *redisStore) flush() error { return nil }

func (r *redisStore) saveOverrides(ov *Overrides) error {
	if err := r.memStore.saveOverrides(ov); err != nil {
		return err
	}
	payload, err := json.Marshal(ov)
	if err != nil {
		return err
	}
	if _, err := r.client.do("SET", r.overridesKey, string(payload)); err != nil {
		logWarn(r.instance, "could not publish rule changes to redis; they apply on this replica only",
			map[string]interface{}{"error": err.Error()})
	}
	return nil
}

// refresh rebuilds the local cache from Redis. It is called by the janitor
// goroutine, never from the request path.
func (r *redisStore) refresh() error {
	r.refreshOverrides()

	keys, err := r.client.scan(r.prefix + "*")
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}

	values, err := r.client.mget(keys)
	if err != nil {
		return err
	}

	now := time.Now()
	bans := make([]Ban, 0, len(values))
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

	r.mu.Lock()
	r.bans = make(map[netip.Prefix]*Ban, len(bans))
	r.mu.Unlock()
	r.restore(bans, now)
	return nil
}

// refreshOverrides pulls the shared rule set into the local cache. A failure is
// not fatal: the replica keeps running whatever it already had.
func (r *redisStore) refreshOverrides() {
	reply, err := r.client.do("GET", r.overridesKey)
	if err != nil {
		return
	}
	if reply.null || reply.str == "" {
		return
	}
	var ov Overrides
	if err := json.Unmarshal([]byte(reply.str), &ov); err != nil {
		logWarn(r.instance, "shared rule set in redis could not be decoded; keeping the local one",
			map[string]interface{}{"error": err.Error()})
		return
	}
	_ = r.memStore.saveOverrides(&ov)
}

// respClient is a minimal, synchronous RESP2 client: one connection guarded by a
// mutex, redialed on any error. Ban traffic is low volume, so a connection pool
// would be complexity without benefit.
type respClient struct {
	mu       sync.Mutex
	conn     net.Conn
	rw       *bufio.ReadWriter
	addr     string
	password string
	db       int
	timeout  time.Duration
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

func (c *respClient) do(args ...string) (respValue, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.dialLocked(); err != nil {
		return respValue{}, err
	}
	v, err := c.commandLocked(args...)
	if err != nil {
		// The connection is in an unknown state after a protocol or I/O error;
		// drop it so the next call starts clean.
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

// respValue is a decoded RESP2 reply.
type respValue struct {
	kind byte
	str  string
	num  int64
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
		return respValue{kind: kind, str: body}, nil
	case '-':
		return respValue{kind: kind, str: body}, fmt.Errorf("redis: %s", body)
	case ':':
		n, cerr := strconv.ParseInt(body, 10, 64)
		if cerr != nil {
			return respValue{}, fmt.Errorf("redis: bad integer reply %q", body)
		}
		return respValue{kind: kind, num: n}, nil
	case '$':
		n, cerr := strconv.Atoi(body)
		if cerr != nil {
			return respValue{}, fmt.Errorf("redis: bad bulk length %q", body)
		}
		if n < 0 {
			return respValue{kind: kind, null: true}, nil
		}
		buf := make([]byte, n+2) // payload plus trailing CRLF
		if _, err := readFull(r, buf); err != nil {
			return respValue{}, err
		}
		return respValue{kind: kind, str: string(buf[:n])}, nil
	case '*':
		n, cerr := strconv.Atoi(body)
		if cerr != nil {
			return respValue{}, fmt.Errorf("redis: bad array length %q", body)
		}
		if n < 0 {
			return respValue{kind: kind, null: true}, nil
		}
		items := make([]respValue, 0, n)
		for i := 0; i < n; i++ {
			item, err := readReply(r)
			if err != nil {
				return respValue{}, err
			}
			items = append(items, item)
		}
		return respValue{kind: kind, arr: items}, nil
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

func readFull(r *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
