package scanguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Overrides are the configuration sections the admin console may edit at runtime.
//
// Traefik's configuration is declarative and one-way: it is decoded into Config
// exactly once, when the middleware is built, and there is no path back. Nor can
// the console write to the file provider — every write there trips fsnotify,
// rebuilds the entire router tree and re-runs New() for every plugin middleware
// on every router. So scanguard keeps its own override store, and for the
// sections listed here the dynamic configuration becomes the bootstrap default
// rather than the live value.
//
// A nil section means "not overridden, use whatever the file says". Sections are
// replaced wholesale rather than merged field by field, because the console reads
// a section, edits it, and writes the same shape back — a partial merge would
// make "I unticked this box" indistinguishable from "I did not send that field".
type Overrides struct {
	Updated time.Time `json:"updated"`
	Actor   string    `json:"actor,omitempty"`

	DryRun      *bool              `json:"dryRun,omitempty"`
	Detectors   *DetectorsConfig   `json:"detectors,omitempty"`
	Allowlist   *AllowlistConfig   `json:"allowlist,omitempty"`
	Enforcement *EnforcementConfig `json:"enforcement,omitempty"`
}

// What is deliberately NOT editable from the console, and why:
//
//   - clientIP.trustedProxies and clientIP.header. These have to agree with
//     entryPoints.<name>.forwardedHeaders.trustedIPs in Traefik's STATIC
//     configuration, which nothing at runtime can change. Editing one half would
//     produce a half-configured state that silently attributes requests to the
//     wrong source — the exact failure that bans your own CDN.
//   - store.*. Repointing state at a different backend mid-flight is not a rule
//     change, and getting it wrong loses the ban list.
//   - admin.*. A console that can rewrite its own token or clear readOnly is a
//     lockout risk and a privilege-escalation path.
//   - notify.*. These carry secrets — an AbuseIPDB key, webhook URLs that
//     routinely embed credentials — which is why the API redacts them. A surface
//     that can rewrite a webhook URL can exfiltrate every ban event.
//   - instanceName, uiMode, enabled. Structural: they decide which runtime this
//     middleware belongs to and whether it exists at all.

// prune drops sections that are identical to the file configuration.
//
// This is what keeps the split between "the file owns this" and "the console owns
// this" honest. The console submits the whole editable shape on every save, so
// without pruning, changing one honeypot path would quietly take ownership of
// enforcement and the allowlist as well — and the operator would later edit those
// in their YAML, reload Traefik, and watch nothing happen. After pruning, the
// console owns exactly the sections somebody actually changed, and everything
// else keeps tracking the file.
func (o *Overrides) prune(base *Config) {
	if o == nil || base == nil {
		return
	}
	if o.DryRun != nil && *o.DryRun == base.DryRun {
		o.DryRun = nil
	}
	if o.Detectors != nil && sameJSON(*o.Detectors, base.Detectors) {
		o.Detectors = nil
	}
	if o.Allowlist != nil && sameJSON(*o.Allowlist, base.Allowlist) {
		o.Allowlist = nil
	}
	if o.Enforcement != nil && sameJSON(*o.Enforcement, base.Enforcement) {
		o.Enforcement = nil
	}
}

// sameJSON compares two values of the same type by their encoding. The editable
// configuration sections contain no maps, so encoding order is deterministic and
// this is a reliable equality test.
func sameJSON(a, b interface{}) bool {
	ab, aerr := json.Marshal(a)
	bb, berr := json.Marshal(b)
	if aerr != nil || berr != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}

// empty reports whether the overrides change nothing.
func (o *Overrides) empty() bool {
	if o == nil {
		return true
	}
	return o.DryRun == nil && o.Detectors == nil && o.Allowlist == nil && o.Enforcement == nil
}

// sections lists which parts of the configuration the console currently owns.
func (o *Overrides) sections() []string {
	out := []string{}
	if o == nil {
		return out
	}
	if o.DryRun != nil {
		out = append(out, "dryRun")
	}
	if o.Detectors != nil {
		out = append(out, "detectors")
	}
	if o.Allowlist != nil {
		out = append(out, "allowlist")
	}
	if o.Enforcement != nil {
		out = append(out, "enforcement")
	}
	return out
}

// clone deep-copies the overrides so callers cannot mutate stored state.
func (o *Overrides) clone() *Overrides {
	if o == nil {
		return nil
	}
	buf, err := json.Marshal(o)
	if err != nil {
		return nil
	}
	var out Overrides
	if err := json.Unmarshal(buf, &out); err != nil {
		return nil
	}
	return &out
}

// cloneConfig deep-copies a Config through JSON.
//
// Config is entirely JSON-tagged plain data, which makes this both correct and
// far less error-prone than a hand-written copy that would silently share a slice
// the next time someone adds a field.
func cloneConfig(c *Config) (*Config, error) {
	if c == nil {
		return nil, fmt.Errorf("cannot clone a nil configuration")
	}
	buf, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("could not copy configuration: %w", err)
	}
	var out Config
	if err := json.Unmarshal(buf, &out); err != nil {
		return nil, fmt.Errorf("could not copy configuration: %w", err)
	}
	return &out, nil
}

// applyOverrides layers the console's edits over the file configuration.
func applyOverrides(base *Config, ov *Overrides) (*Config, error) {
	out, err := cloneConfig(base)
	if err != nil {
		return nil, err
	}
	if ov == nil {
		return out, nil
	}
	if ov.DryRun != nil {
		out.DryRun = *ov.DryRun
	}
	if ov.Detectors != nil {
		out.Detectors = *ov.Detectors
	}
	if ov.Allowlist != nil {
		out.Allowlist = *ov.Allowlist
	}
	if ov.Enforcement != nil {
		out.Enforcement = *ov.Enforcement
	}
	return out, nil
}

// editableConfig is the shape the console reads and writes back.
type editableConfig struct {
	DryRun      bool              `json:"dryRun"`
	Detectors   DetectorsConfig   `json:"detectors"`
	Allowlist   AllowlistConfig   `json:"allowlist"`
	Enforcement EnforcementConfig `json:"enforcement"`
}

func editableFrom(c *Config) editableConfig {
	return editableConfig{
		DryRun:      c.DryRun,
		Detectors:   c.Detectors,
		Allowlist:   c.Allowlist,
		Enforcement: c.Enforcement,
	}
}

// toOverrides turns a console submission into an override set.
func (e *editableConfig) toOverrides() *Overrides {
	dryRun := e.DryRun
	detectors := e.Detectors
	allowlist := e.Allowlist
	enforcement := e.Enforcement
	return &Overrides{
		DryRun:      &dryRun,
		Detectors:   &detectors,
		Allowlist:   &allowlist,
		Enforcement: &enforcement,
	}
}
