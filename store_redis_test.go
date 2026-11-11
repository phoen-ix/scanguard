package scanguard

// The RESP client and the Redis backend's refresh logic had no unit coverage:
// only the e2e happy path, under real Traefik and real Redis, ever touched
// them. fakeRedis is a RESP2 server on a loopback port that speaks exactly the
// subset the backend uses, with knobs for the failure modes the e2e harness
// cannot produce: a dropped connection, an outage, a paginated SCAN.

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeRedis struct {
	ln net.Listener

	mu     sync.Mutex
	data   map[string]string
	expiry map[string]time.Time
	cmds   []string

	// conns counts accepted connections, so a test can tell a redial from a
	// reused connection.
	conns atomic.Int32
	// down makes the server accept and immediately close every connection and
	// drop the ones it holds: an outage without giving the port up.
	down atomic.Bool
	// closeAfter, when positive, closes a connection after that many commands,
	// the way a server-side idle timeout or a Redis restart does.
	closeAfter int
	// scanPage is how many keys one SCAN reply carries.
	scanPage int
	username string
	password string

	live   sync.Mutex
	active map[net.Conn]struct{}
}

func newFakeRedis(t *testing.T) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return serveFakeRedis(t, ln)
}

// newFakeRedisTLS is newFakeRedis behind TLS, with a certificate for
// "redis.test" signed by a throwaway CA; the CA's PEM path is returned.
func newFakeRedisTLS(t *testing.T) (*fakeRedis, string) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "scanguard test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "redis.test"},
		DNSNames:  []string{"redis.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	return serveFakeRedis(t, ln), caPath
}

func serveFakeRedis(t *testing.T, ln net.Listener) *fakeRedis {
	t.Helper()
	f := &fakeRedis{
		ln:       ln,
		data:     make(map[string]string),
		expiry:   make(map[string]time.Time),
		scanPage: 1000,
		active:   make(map[net.Conn]struct{}),
	}
	go f.serve()
	t.Cleanup(func() { _ = ln.Close(); f.dropAll() })
	return f
}

func (f *fakeRedis) addr() string { return f.ln.Addr().String() }

func (f *fakeRedis) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		if f.down.Load() {
			_ = conn.Close()
			continue
		}
		f.conns.Add(1)
		f.live.Lock()
		f.active[conn] = struct{}{}
		f.live.Unlock()
		go f.handle(conn)
	}
}

func (f *fakeRedis) dropAll() {
	f.live.Lock()
	for c := range f.active {
		_ = c.Close()
		delete(f.active, c)
	}
	f.live.Unlock()
}

// outage takes the server down (connections dropped, new ones refused by
// closing) and returns the function that brings it back.
func (f *fakeRedis) outage() func() {
	f.down.Store(true)
	f.dropAll()
	return func() { f.down.Store(false) }
}

func (f *fakeRedis) handle(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		f.live.Lock()
		delete(f.active, conn)
		f.live.Unlock()
	}()
	r := bufio.NewReader(conn)
	served := 0
	for {
		req, err := readReply(r)
		if err != nil {
			return
		}
		args := make([]string, 0, len(req.arr))
		for _, a := range req.arr {
			args = append(args, a.str)
		}
		if len(args) == 0 {
			return
		}
		f.mu.Lock()
		f.cmds = append(f.cmds, strings.ToUpper(args[0]))
		reply := f.dispatch(args)
		f.mu.Unlock()
		if _, err := conn.Write([]byte(reply)); err != nil {
			return
		}
		served++
		if f.closeAfter > 0 && served >= f.closeAfter {
			return
		}
	}
}

func bulk(s string) string { return "$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n" }
func respInt(n int) string { return ":" + strconv.Itoa(n) + "\r\n" }
func respArr(items []string) string {
	var sb strings.Builder
	sb.WriteString("*" + strconv.Itoa(len(items)) + "\r\n")
	for _, it := range items {
		sb.WriteString(it)
	}
	return sb.String()
}

const (
	respOK   = "+OK\r\n"
	respNull = "$-1\r\n"
)

// liveKeys returns the unexpired keys, sorted. The caller holds mu.
func (f *fakeRedis) liveKeys() []string {
	now := time.Now()
	keys := make([]string, 0, len(f.data))
	for k := range f.data {
		if exp, ok := f.expiry[k]; ok && !exp.After(now) {
			delete(f.data, k)
			delete(f.expiry, k)
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (f *fakeRedis) dispatch(args []string) string {
	switch strings.ToUpper(args[0]) {
	case "AUTH":
		user, pass := "default", ""
		switch len(args) {
		case 2:
			pass = args[1]
		case 3:
			user, pass = args[1], args[2]
		}
		wantUser := f.username
		if wantUser == "" {
			wantUser = "default"
		}
		if f.password != "" && (user != wantUser || pass != f.password) {
			return "-WRONGPASS invalid username-password pair or user is disabled.\r\n"
		}
		return respOK
	case "SELECT", "PING":
		return respOK
	case "SET":
		if len(args) < 3 {
			return "-ERR wrong number of arguments for 'set'\r\n"
		}
		key, val := args[1], args[2]
		var px time.Duration
		nx := false
		for i := 3; i < len(args); i++ {
			switch strings.ToUpper(args[i]) {
			case "PX":
				if i+1 < len(args) {
					ms, _ := strconv.Atoi(args[i+1])
					px = time.Duration(ms) * time.Millisecond
					i++
				}
			case "NX":
				nx = true
			}
		}
		f.liveKeys()
		if _, exists := f.data[key]; nx && exists {
			return respNull
		}
		f.data[key] = val
		delete(f.expiry, key)
		if px > 0 {
			f.expiry[key] = time.Now().Add(px)
		}
		return respOK
	case "GET":
		f.liveKeys()
		if v, ok := f.data[args[1]]; ok {
			return bulk(v)
		}
		return respNull
	case "DEL":
		f.liveKeys()
		n := 0
		for _, k := range args[1:] {
			if _, ok := f.data[k]; ok {
				delete(f.data, k)
				delete(f.expiry, k)
				n++
			}
		}
		return respInt(n)
	case "MGET":
		f.liveKeys()
		items := make([]string, 0, len(args)-1)
		for _, k := range args[1:] {
			if v, ok := f.data[k]; ok {
				items = append(items, bulk(v))
			} else {
				items = append(items, respNull)
			}
		}
		return respArr(items)
	case "SCAN":
		cursor, _ := strconv.Atoi(args[1])
		pattern := "*"
		for i := 2; i+1 < len(args); i += 2 {
			if strings.ToUpper(args[i]) == "MATCH" {
				pattern = args[i+1]
			}
		}
		var matching []string
		for _, k := range f.liveKeys() {
			if globMatch(pattern, k) {
				matching = append(matching, k)
			}
		}
		end := cursor + f.scanPage
		if end >= len(matching) {
			end = len(matching)
		}
		page := make([]string, 0, end-cursor)
		for _, k := range matching[cursor:end] {
			page = append(page, bulk(k))
		}
		next := "0"
		if end < len(matching) {
			next = strconv.Itoa(end)
		}
		return respArr([]string{bulk(next), respArr(page)})
	default:
		return "-ERR unknown command '" + args[0] + "'\r\n"
	}
}

// globMatch is the slice of Redis glob syntax the backend uses: a literal
// prefix and a trailing star. path.Match would not do — its star stops at "/",
// and every ban key has one.
func globMatch(pattern, key string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(key, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == key
}

func (f *fakeRedis) get(key string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.liveKeys()
	v, ok := f.data[key]
	return v, ok
}

func (f *fakeRedis) set(key, val string) {
	f.mu.Lock()
	f.data[key] = val
	delete(f.expiry, key)
	f.mu.Unlock()
}

func (f *fakeRedis) count(cmd string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.cmds {
		if c == cmd {
			n++
		}
	}
	return n
}

// eventually polls cond for up to two seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func redisSettings(t *testing.T, f *fakeRedis, mutate func(*Config)) *settings {
	t.Helper()
	return mustSettings(t, func(c *Config) {
		c.InstanceName = t.Name()
		c.Store.Backend = "redis"
		c.Store.Redis.Address = f.addr()
		c.Store.Redis.KeyPrefix = "t:"
		c.Store.Redis.Timeout = "500ms"
		c.Store.FailOpen = true
		if mutate != nil {
			mutate(c)
		}
	})
}

func TestRedisStorePublishesAndLoadsBans(t *testing.T) {
	f := newFakeRedis(t)
	s := redisSettings(t, f, nil)
	a, err := newRedisStore(s)
	if err != nil {
		t.Fatalf("newRedisStore: %v", err)
	}
	now := time.Now()
	if err := a.put(ban("203.0.113.1/32", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if err := a.put(ban("203.0.113.2/32", time.Time{})); err != nil {
		t.Fatal(err)
	}
	eventually(t, "both bans in redis", func() bool {
		_, ok1 := f.get("t:ban:203.0.113.1/32")
		_, ok2 := f.get("t:ban:203.0.113.2/32")
		return ok1 && ok2
	})
	f.mu.Lock()
	_, timed := f.expiry["t:ban:203.0.113.1/32"]
	_, perm := f.expiry["t:ban:203.0.113.2/32"]
	f.mu.Unlock()
	if !timed || perm {
		t.Errorf("expiry set: timed=%v permanent=%v, want true/false", timed, perm)
	}

	// A second replica sees them on its first refresh.
	b, err := newRedisStore(s)
	if err != nil {
		t.Fatalf("second replica: %v", err)
	}
	if _, ok := b.get(key("203.0.113.1/32"), now); !ok {
		t.Error("the other replica did not load the timed ban")
	}
	if _, ok := b.get(key("203.0.113.2/32"), now.Add(1000*time.Hour)); !ok {
		t.Error("the other replica did not load the permanent ban")
	}
	if a.backend() != "redis" {
		t.Errorf("backend = %q", a.backend())
	}
}

func TestRedisScanPaginatesAndMGETBatches(t *testing.T) {
	f := newFakeRedis(t)
	f.scanPage = 50
	now := time.Now()
	for i := 0; i < 600; i++ {
		b := ban(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256), now.Add(time.Hour))
		f.set("t:ban:"+b.Key, mustJSON(t, b))
	}
	f.set("other:ban:10.9.9.0/24", mustJSON(t, ban("10.9.9.0/24", now.Add(time.Hour))))

	s := redisSettings(t, f, nil)
	r, err := newRedisStore(s)
	if err != nil {
		t.Fatalf("newRedisStore: %v", err)
	}
	if got := r.size(); got != 600 {
		t.Fatalf("loaded %d bans, want 600 (and not the other prefix's)", got)
	}
	if n := f.count("SCAN"); n < 12 {
		t.Errorf("SCAN was called %d times for 600 keys in pages of 50, want the cursor followed", n)
	}
	if n := f.count("MGET"); n < 3 {
		t.Errorf("MGET was called %d times for 600 keys, want batches of 256", n)
	}
}

func mustJSON(t *testing.T, b Ban) string {
	t.Helper()
	args, err := (&redisStore{prefix: ""}).banArgs(b)
	if err != nil || args == nil {
		t.Fatalf("banArgs: %v %v", args, err)
	}
	return args[2]
}

// A connection that the server closed — a Redis restart, an idle timeout — is
// redialed once and the command retried, so a janitor tick does not report an
// outage that is already over.
func TestRedisRedialsAfterAStaleConnection(t *testing.T) {
	f := newFakeRedis(t)
	f.closeAfter = 3
	s := redisSettings(t, f, nil)
	r, err := newRedisStore(s)
	if err != nil {
		t.Fatalf("newRedisStore: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := r.refresh(); err != nil {
			t.Fatalf("refresh %d failed although the server was up: %v", i, err)
		}
	}
	if n := f.conns.Load(); n < 2 {
		t.Errorf("only %d connections were made across server-side closes, want redials", n)
	}
}

// A `-ERR` reply means Redis answered: the connection is healthy and is kept.
func TestRedisErrorReplyKeepsTheConnection(t *testing.T) {
	f := newFakeRedis(t)
	s := redisSettings(t, f, nil)
	r, err := newRedisStore(s)
	if err != nil {
		t.Fatalf("newRedisStore: %v", err)
	}
	before := f.conns.Load()
	if _, err := r.client.do("BOGUS"); err == nil || !isReplyError(err) {
		t.Fatalf("BOGUS returned %v, want a reply error", err)
	}
	if _, err := r.client.do("PING"); err != nil {
		t.Fatal(err)
	}
	if f.conns.Load() != before {
		t.Error("an error reply dropped the connection")
	}
}

// With Redis down, a ban is enforced locally at once, costs the request no
// dial, and is published by the janitor's refresh when Redis is back instead
// of being dropped by the cache swap.
func TestRedisOutageQueuesPublishesForTheNextRefresh(t *testing.T) {
	f := newFakeRedis(t)
	s := redisSettings(t, f, nil)
	r, err := newRedisStore(s)
	if err != nil {
		t.Fatalf("newRedisStore: %v", err)
	}
	restore := f.outage()

	now := time.Now()
	started := time.Now()
	if err := r.put(ban("203.0.113.5/32", now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(started); took > 200*time.Millisecond {
		t.Errorf("put took %v during an outage; the request path must not wait for Redis", took)
	}
	if _, ok := r.get(key("203.0.113.5/32"), now); !ok {
		t.Fatal("the ban is not enforced locally during the outage")
	}
	eventually(t, "the ban to be parked", func() bool {
		r.pendingMu.Lock()
		defer r.pendingMu.Unlock()
		return len(r.pendingPut) == 1
	})
	if err := r.refresh(); err == nil {
		t.Fatal("refresh succeeded during the outage")
	}
	if _, ok := r.get(key("203.0.113.5/32"), now); !ok {
		t.Fatal("a failed refresh dropped the local ban")
	}

	restore()
	if err := r.refresh(); err != nil {
		t.Fatalf("refresh after the outage: %v", err)
	}
	if _, ok := f.get("t:ban:203.0.113.5/32"); !ok {
		t.Error("the parked ban was not published once Redis was back")
	}
	if _, ok := r.get(key("203.0.113.5/32"), now); !ok {
		t.Error("the refresh that published the ban dropped it locally")
	}
	r.pendingMu.Lock()
	left := len(r.pendingPut)
	r.pendingMu.Unlock()
	if left != 0 {
		t.Errorf("%d bans still pending after publication", left)
	}
}

// A ban put while the refresh's SCAN and MGET were running is not in the list
// Redis returned, and the swap used to drop it until the next refresh — the
// source was re-detected and a duplicate ban event issued.
func TestReplaceAllKeepsEntriesCreatedDuringTheRefresh(t *testing.T) {
	now := time.Now()
	start := now.Add(-time.Second)
	m := newMemStore(100)
	old := ban("203.0.113.6/32", now.Add(time.Hour))
	old.Created = start.Add(-time.Hour)
	fresh := ban("203.0.113.7/32", now.Add(time.Hour))
	fresh.Created = start.Add(time.Millisecond)
	_ = m.put(old)
	_ = m.put(fresh)

	m.replaceAllKeeping(nil, now, func(b *Ban) bool { return !b.Created.Before(start) })
	if _, ok := m.get(key("203.0.113.6/32"), now); ok {
		t.Error("an entry Redis no longer holds survived the swap")
	}
	if _, ok := m.get(key("203.0.113.7/32"), now); !ok {
		t.Error("an entry created during the refresh was dropped by the swap")
	}
}

// An unban made during an outage must not come back from Redis on the next
// refresh, and existence is answered from the DEL reply when the ban was
// written by another replica and never reached this cache.
func TestRedisDeleteSurvivesAnOutageAndReadsTheReply(t *testing.T) {
	f := newFakeRedis(t)
	s := redisSettings(t, f, nil)
	r, err := newRedisStore(s)
	if err != nil {
		t.Fatalf("newRedisStore: %v", err)
	}
	now := time.Now()

	// Another replica's ban, not in this cache.
	f.set("t:ban:203.0.113.8/32", mustJSON(t, ban("203.0.113.8/32", now.Add(time.Hour))))
	existed, err := r.delete(key("203.0.113.8/32"))
	if err != nil || !existed {
		t.Errorf("deleting a ban held only in redis: existed=%v err=%v, want true", existed, err)
	}
	if _, ok := f.get("t:ban:203.0.113.8/32"); ok {
		t.Error("DEL did not reach redis")
	}

	// A local ban, unbanned during an outage.
	_ = r.put(ban("203.0.113.9/32", now.Add(time.Hour)))
	eventually(t, "the ban in redis", func() bool { _, ok := f.get("t:ban:203.0.113.9/32"); return ok })
	restore := f.outage()
	existed, err = r.delete(key("203.0.113.9/32"))
	if err != nil || !existed {
		t.Fatalf("delete during the outage: existed=%v err=%v", existed, err)
	}
	restore()
	if err := r.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, ok := f.get("t:ban:203.0.113.9/32"); ok {
		t.Error("the pending DEL was not applied once redis was back")
	}
	if _, ok := r.get(key("203.0.113.9/32"), now); ok {
		t.Error("the unbanned source came back from redis")
	}
}

// Saving rules while Redis is unreachable is an error the console hears about,
// and the set is published on the next refresh unless another replica saved a
// newer one meanwhile.
func TestRedisOverridesSaveReportsFailureAndRepublishes(t *testing.T) {
	f := newFakeRedis(t)
	s := redisSettings(t, f, nil)
	r, err := newRedisStore(s)
	if err != nil {
		t.Fatalf("newRedisStore: %v", err)
	}
	restore := f.outage()
	dry := true
	ov := &Overrides{Version: overridesVersion, Updated: time.Now().UTC(), DryRun: &dry}
	if err := r.saveOverrides(ov); err == nil {
		t.Fatal("saveOverrides reported success while redis was unreachable")
	}
	if got := r.loadOverrides(); got == nil || got.DryRun == nil {
		t.Fatal("the set was not kept locally")
	}
	restore()
	if err := r.refresh(); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, ok := f.get("t:overrides"); !ok {
		t.Fatal("the unpublished rule set was not published once redis was back")
	}

	// Another replica adopts it...
	other, err := newRedisStore(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := other.loadOverrides(); got == nil || got.DryRun == nil || !got.Updated.Equal(ov.Updated) {
		t.Errorf("the other replica loaded %+v", got)
	}

	// ...and a newer save on that replica during this one's outage wins.
	restore = f.outage()
	older := &Overrides{Version: overridesVersion, Updated: time.Now().UTC(), DryRun: &dry}
	_ = r.saveOverrides(older)
	restore()
	off := false
	newer := &Overrides{Version: overridesVersion, Updated: time.Now().UTC().Add(time.Second), DryRun: &off}
	if err := other.saveOverrides(newer); err != nil {
		t.Fatal(err)
	}
	if err := r.refresh(); err != nil {
		t.Fatal(err)
	}
	if got := r.loadOverrides(); got == nil || got.DryRun == nil || *got.DryRun {
		t.Errorf("the newer shared set was not adopted over the unpublished local one: %+v", got)
	}
}

// One expiry, one announcement: the first replica to claim a key wins and the
// others stay quiet. Without Redis every replica claims.
func TestRedisExpiryClaimIsOnePerKey(t *testing.T) {
	f := newFakeRedis(t)
	s := redisSettings(t, f, nil)
	a, err := newRedisStore(s)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newRedisStore(s)
	if err != nil {
		t.Fatal(err)
	}
	if !a.claimExpiry("203.0.113.10/32") {
		t.Error("the first claim was refused")
	}
	if b.claimExpiry("203.0.113.10/32") {
		t.Error("the second replica also claimed the same expiry")
	}
	if !b.claimExpiry("203.0.113.11/32") {
		t.Error("a claim for a different key was refused")
	}
	f.outage()
	if !a.claimExpiry("203.0.113.12/32") {
		t.Error("with redis down a claim must succeed; duplicates beat silence")
	}
}

// AUTH and the glob-safe prefix end to end.
func TestRedisAuthAndPrefix(t *testing.T) {
	f := newFakeRedis(t)
	f.password = "hunter2-hunter2"
	s := redisSettings(t, f, func(c *Config) { c.Store.Redis.Password = "hunter2-hunter2" })
	r, err := newRedisStore(s)
	if err != nil {
		t.Fatalf("newRedisStore: %v", err)
	}
	if err := r.refresh(); err != nil {
		t.Fatal(err)
	}
	wrong := redisSettings(t, f, func(c *Config) {
		c.Store.Redis.Password = "wrong-password-0"
		c.Store.FailOpen = false
	})
	if _, err := newRedisStore(wrong); err == nil {
		t.Error("a wrong password with failOpen false did not fail the store")
	}
}

// The Redis password is kept out of the hashed store fingerprint and compared
// on its own, so a rotation must still rebuild the store, and a reload that
// leaves the store block alone must keep it.
func TestARotatedRedisPasswordRebuildsTheStore(t *testing.T) {
	f := newFakeRedis(t)
	f.password = "first-password-0123"
	withRedis := func(password, honeypot string) func(*Config) {
		return func(c *Config) {
			c.Store.Backend = "redis"
			c.Store.Redis.Address = f.addr()
			c.Store.Redis.Password = password
			c.Store.Redis.Timeout = "500ms"
			c.Store.FailOpen = false
			c.Detectors.Honeypots.Paths = []string{honeypot}
		}
	}
	_, rt := consoleHandler(t, withRedis("first-password-0123", "/trap-a"))
	store := rt.store()

	reloadDetector(t, t.Name(), withRedis("first-password-0123", "/trap-b"))
	if rt.store() != store {
		t.Error("a reload that left the store block alone rebuilt the store")
	}

	// failOpen is false, so the new store connects with the new password or
	// the reload fails.
	f.mu.Lock()
	f.password = "second-password-0123"
	f.mu.Unlock()
	reloadDetector(t, t.Name(), withRedis("second-password-0123", "/trap-b"))
	if rt.store() == store {
		t.Error("a password-only change did not rebuild the store")
	}
}

// An ACL user authenticates with AUTH user pass; a wrong user is refused.
func TestRedisACLUsername(t *testing.T) {
	f := newFakeRedis(t)
	f.username = "scanguard"
	f.password = "acl-password-0123"
	ok := redisSettings(t, f, func(c *Config) {
		c.Store.Redis.Username = "scanguard"
		c.Store.Redis.Password = "acl-password-0123"
		c.Store.FailOpen = false
	})
	if _, err := newRedisStore(ok); err != nil {
		t.Fatalf("the ACL user was refused: %v", err)
	}
	wrong := redisSettings(t, f, func(c *Config) {
		c.Store.Redis.Username = "someone-else"
		c.Store.Redis.Password = "acl-password-0123"
		c.Store.FailOpen = false
	})
	if _, err := newRedisStore(wrong); err == nil {
		t.Error("a wrong ACL user was accepted")
	}
	cfg := CreateConfig()
	cfg.Store.Backend = "redis"
	cfg.Store.Redis.Address = "127.0.0.1:6379"
	cfg.Store.Redis.Username = "scanguard"
	if _, err := cfg.parse(); err == nil {
		t.Error("a username without a password was accepted")
	}
}

// TLS: the certificate is verified against tlsCAFile under tlsServerName;
// without the CA, or under another name, the connection is refused.
func TestRedisTLS(t *testing.T) {
	f, caPath := newFakeRedisTLS(t)
	tlsSettings := func(name, ca string) *settings {
		return redisSettings(t, f, func(c *Config) {
			c.Store.Redis.TLS = true
			c.Store.Redis.TLSServerName = name
			c.Store.Redis.TLSCAFile = ca
			c.Store.FailOpen = false
		})
	}
	r, err := newRedisStore(tlsSettings("redis.test", caPath))
	if err != nil {
		t.Fatalf("TLS with the right CA and name failed: %v", err)
	}
	_ = r.put(ban("203.0.113.40/32", time.Now().Add(time.Hour)))
	eventually(t, "the ban in redis over TLS", func() bool { _, ok := f.get("t:ban:203.0.113.40/32"); return ok })

	if _, err := newRedisStore(tlsSettings("not-the-name.test", caPath)); err == nil {
		t.Error("a certificate for another name was accepted")
	}
	if _, err := newRedisStore(tlsSettings("redis.test", "")); err == nil {
		t.Error("a certificate from an unknown CA was accepted against the system roots")
	}

	bad := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(bad, []byte("not a certificate"), 0o600)
	cfg := CreateConfig()
	cfg.Store.Backend = "redis"
	cfg.Store.Redis.Address = f.addr()
	cfg.Store.Redis.TLS = true
	cfg.Store.Redis.TLSCAFile = bad
	if _, err := cfg.parse(); err == nil {
		t.Error("a CA file with no certificate was accepted")
	}
}
