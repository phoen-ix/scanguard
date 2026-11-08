package scanguard

import (
	"net/netip"
	"testing"
	"time"
)

// A re-issued ban ends where the ladder's window ends, not a full rung after
// the re-issue; otherwise decay later credits the overrun as good behaviour.
func TestReissuedBanEndsAtTheLadderWindow(t *testing.T) {
	h := build(t, nil)
	rt := registry[t.Name()]
	key := netip.MustParsePrefix("203.0.113.140/32")
	if got := send(h, "GET", "/wp-login.php", "203.0.113.140:1", nil).Code; got != 403 {
		t.Fatalf("probe returned %d", got)
	}
	first, _ := rt.store().get(key, time.Now())
	window, ok := rt.counters.banWindow(key)
	if !ok || !first.Expires.Equal(window.UTC()) {
		t.Fatalf("the first ban ends at %v, the ladder at %v", first.Expires, window)
	}
	time.Sleep(20 * time.Millisecond)
	if existed, _ := rt.store().delete(key); !existed {
		t.Fatal("no ban to lose")
	}
	send(h, "GET", "/wp-admin/", "203.0.113.140:1", nil)
	again, ok := rt.store().get(key, time.Now())
	if !ok {
		t.Fatal("the ban was not re-issued")
	}
	if !again.Expires.Equal(first.Expires) {
		t.Errorf("the re-issued ban ends at %v, want the ladder window %v", again.Expires, first.Expires)
	}
}

// A dry run passes a detected request on without observing the answer:
// enforcement would have refused it, so its 404 must not feed the bad-path
// bucket either.
func TestDryRunDoesNotObserveARequestEnforcementWouldRefuse(t *testing.T) {
	h := build(t, func(c *Config) {
		c.DryRun = true
		c.Detectors.BadPaths.Statuses = []int{404}
	})
	rt := registry[t.Name()]
	// A signature hit that the backend also answers 404.
	if got := send(h, "GET", "/missing/wp-login.php", "203.0.113.141:1", nil).Code; got != 404 {
		t.Fatalf("the dry run did not pass the probe on: %d", got)
	}
	rt.counters.mu.Lock()
	st := rt.counters.tbl[netip.MustParsePrefix("203.0.113.141/32")]
	seen := 0
	if st != nil {
		seen = len(st.bad.seen)
	}
	rt.counters.mu.Unlock()
	if seen != 0 {
		t.Errorf("the answer to a request enforcement would have refused fed the bad-path bucket (%d paths)", seen)
	}
}
