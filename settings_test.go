package scanguard

// Settings that used to be hardcoded: extra crawler patterns, the rejection's
// content type, the geo timeout and negative cache, the snapshot debounce, and
// the saved-rules schema that had to grow for two of them.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCrawlerPatternsExtendTheBuiltIns(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Detectors.UserAgent.Crawlers = crawlersBlock
		c.Detectors.UserAgent.CrawlerPatterns = []string{`\bgptbot\b`}
	})
	gpt := map[string]string{"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"}
	if got := send(h, "GET", "/", "203.0.113.130:1", gpt).Code; got != 403 {
		t.Errorf("a configured crawler pattern was not blocked: %d", got)
	}
	if got := send(h, "GET", "/", "203.0.113.131:1", crawlerUA()).Code; got != 403 {
		t.Errorf("the built-in crawlers stopped matching beside an extra pattern: %d", got)
	}
	if got := send(h, "GET", "/", "203.0.113.132:1", map[string]string{"User-Agent": "Mozilla/5.0 Firefox/128.0"}).Code; got != 200 {
		t.Errorf("a browser was refused: %d", got)
	}
	cfg := CreateConfig()
	cfg.Detectors.UserAgent.CrawlerPatterns = []string{"([unclosed"}
	if _, err := cfg.parse(); err == nil || !strings.Contains(err.Error(), "crawlerPatterns") {
		t.Errorf("a broken crawler pattern was accepted or misnamed: %v", err)
	}
}

func TestRejectContentTypeIsConfigurable(t *testing.T) {
	h := build(t, func(c *Config) {
		c.Enforcement.RejectBody = "<h1>no</h1>"
		c.Enforcement.RejectContentType = "text/html; charset=utf-8"
	})
	rec := send(h, "GET", "/wp-login.php", "203.0.113.133:1", nil)
	if rec.Code != 403 || rec.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Errorf("reject = %d with Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if got := send(buildOn(t, t.Name()+"-default", "scanguard@test", nil), "GET", "/wp-login.php", "203.0.113.134:1", nil).Header().Get("Content-Type"); got != defaultRejectContentType {
		t.Errorf("default Content-Type = %q", got)
	}
	cfg := CreateConfig()
	cfg.Enforcement.RejectContentType = "text/plain\r\nSet-Cookie: x=1"
	if _, err := cfg.parse(); err == nil {
		t.Error("a content type carrying a header injection was accepted")
	}
}

// A failed lookup is remembered, so listing the ban table does not re-queue it
// on every poll against ip-api's 45-a-minute limit; the timeout is a setting.
func TestGeoRemembersFailuresAndHonoursItsTimeout(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = rw.Write([]byte(`{"status":"fail","message":"private range"}`))
	}))
	defer srv.Close()
	s := mustSettings(t, func(c *Config) {
		c.Geo = GeoConfig{Enabled: true, Provider: "ip-api", CacheTTL: "1h", Timeout: "750ms", Endpoint: srv.URL}
	})
	g := newGeoCache(s)
	if g.client.Timeout != 750*time.Millisecond {
		t.Errorf("geo client timeout = %v, want the configured 750ms", g.client.Timeout)
	}
	g.lookup("10.0.0.1")
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 10; i++ {
		if c := g.lookup("10.0.0.1"); c != "" {
			t.Fatalf("a failed lookup returned %q", c)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if n := calls.Load(); n != 1 {
		t.Errorf("a failed lookup was repeated: %d calls", n)
	}
	cfg := CreateConfig()
	cfg.Geo.Timeout = "0"
	if _, err := cfg.parse(); err == nil {
		t.Error("geo.timeout 0 was accepted")
	}
}

// A burst of bans shares one snapshot write; with the debounce at 0 every ban
// is written at once, as before.
func TestSnapshotWritesAreDebounced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	h := build(t, func(c *Config) {
		c.Store.Backend = "file"
		c.Store.Path = path
		c.Store.FlushDebounce = "300ms"
	})
	send(h, "GET", "/wp-login.php", "203.0.113.135:1", nil)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("the snapshot was written before the debounce elapsed: %v", err)
	}
	send(h, "GET", "/wp-login.php", "203.0.113.136:1", nil)
	deadline := time.Now().Add(3 * time.Second)
	var buf []byte
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil && strings.Contains(string(b), "203.0.113.136/32") {
			buf = b
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(string(buf), "203.0.113.135/32") || !strings.Contains(string(buf), "203.0.113.136/32") {
		t.Fatalf("the debounced write did not carry both bans: %s", buf)
	}

	now := filepath.Join(t.TempDir(), "state.json")
	h0 := buildOn(t, t.Name()+"-now", "scanguard@test", func(c *Config) {
		c.Store.Backend = "file"
		c.Store.Path = now
		c.Store.FlushDebounce = "0"
	})
	send(h0, "GET", "/wp-login.php", "203.0.113.137:1", nil)
	if b, err := os.ReadFile(now); err != nil || !strings.Contains(string(b), "203.0.113.137/32") {
		t.Errorf("with flushDebounce 0 the ban was not written at once: %v", err)
	}

	cfg := CreateConfig()
	cfg.Store.FlushDebounce = "2m"
	if _, err := cfg.parse(); err == nil {
		t.Error("a flushDebounce above the ceiling was accepted")
	}
}

// A rule set saved by the previous build (schema 2) is brought forward instead
// of refused: the two fields added since come from the file configuration,
// which is what that build was running with.
func TestVersion2RuleSetsAreMigrated(t *testing.T) {
	h, rt := consoleHandler(t, func(c *Config) {
		c.Detectors.UserAgent.CrawlerPatterns = []string{`\bgptbot\b`}
		c.Detectors.UserAgent.Crawlers = crawlersBlock
		c.Enforcement.RejectContentType = "text/html"
	})
	base := rt.baseConfig
	det := base.Detectors
	det.UserAgent.CrawlerPatterns = nil // what a v2 blob decodes to
	det.Honeypots = HoneypotConfig{Enabled: true, Paths: []string{"/v2-trap"}}
	enf := base.Enforcement
	enf.RejectContentType = ""
	old := &Overrides{Version: 2, Updated: time.Now().UTC(), Detectors: &det, Enforcement: &enf}
	if err := old.compatible(); err != nil {
		t.Fatalf("a version-2 set was refused: %v", err)
	}

	rt.mu.Lock()
	s, err := rt.rebuildLocked(old)
	if err == nil {
		rt.overrides = old
		rt.applySettings(s)
	}
	rt.mu.Unlock()
	if err != nil {
		t.Fatalf("a version-2 set did not apply: %v", err)
	}
	if got := send(h, "GET", "/v2-trap", "203.0.113.138:1", nil); got.Code != 403 || got.Header().Get("Content-Type") != "text/html" {
		t.Errorf("v2 set: trap returned %d with %q, want 403 text/html from the file", got.Code, got.Header().Get("Content-Type"))
	}
	gpt := map[string]string{"User-Agent": "GPTBot/1.2"}
	if got := send(h, "GET", "/", "203.0.113.139:1", gpt).Code; got != 403 {
		t.Errorf("v2 set dropped the file's crawler patterns: %d", got)
	}
	for _, v := range []int{0, 1, overridesVersion + 1} {
		if (&Overrides{Version: v}).compatible() == nil {
			t.Errorf("schema version %d was accepted", v)
		}
	}
}

// editableSchemaSignatures records the shape of the console-editable sections
// for each schema version. When this test fails, a field was added to (or
// removed from) a section the console saves: bump overridesVersion, teach
// applyOverrides to migrate the previous version, and record the new
// signature here.
var editableSchemaSignatures = map[int]string{
	3: "41f32867869b2b89",
}

func TestEditableSchemaChangesBumpTheVersion(t *testing.T) {
	var paths []string
	var walk func(prefix string, typ reflect.Type)
	walk = func(prefix string, typ reflect.Type) {
		for typ.Kind() == reflect.Ptr {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || typ == reflect.TypeOf(time.Time{}) {
			paths = append(paths, prefix+":"+typ.String())
			return
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			walk(prefix+"."+name, f.Type)
		}
	}
	walk("", reflect.TypeOf(editableConfig{}))
	sort.Strings(paths)
	buf, _ := json.Marshal(paths)
	got := hashOf(buf)
	if want := editableSchemaSignatures[overridesVersion]; got != want {
		t.Errorf("the editable schema signature is %s, recorded %q for version %d: a field changed without a schema bump",
			got, want, overridesVersion)
	}
}
