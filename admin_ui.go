package scanguard

// The admin UI is three Go string constants rather than embedded asset files.
//
// This is not a stylistic choice. //go:embed does not work under the Yaegi
// interpreter Traefik uses for plugins, and — worse — it fails silently: the
// embedded variable is simply empty, so `go build` and `go test` pass locally and
// the page is blank only once Traefik loads the plugin. String constants are the
// one approach that behaves identically compiled and interpreted.
//
// Consequences to respect when editing:
//
//   - No backticks anywhere in the CSS or JS, since these are raw string
//     literals. The JS uses string concatenation instead of template literals.
//   - No build step, no npm, no framework. Vanilla DOM APIs only.
//   - Everything the API returns is attacker-controlled text (request paths,
//     user-agents, rule strings). It is inserted with textContent, never
//     innerHTML, and the Content-Security-Policy forbids inline script, so an
//     injected string cannot become executable.

const indexHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>scanguard</title>
<link rel="stylesheet" href="app.css">
</head>
<body>
<div id="gate" class="gate" hidden>
  <form id="gate-form" class="gate-card">
    <h1>scanguard</h1>
    <p>This console can unban addresses and change detection rules.</p>
    <label for="token">Access token</label>
    <input id="token" type="password" autocomplete="current-password" spellcheck="false">
    <button type="submit">Unlock</button>
    <p id="gate-error" class="error" hidden></p>
  </form>
</div>

<div id="app" hidden>
  <header class="topbar">
    <div class="brand">
      <span class="mark">SG</span>
      <div>
        <h1>scanguard</h1>
        <p id="subtitle">&nbsp;</p>
      </div>
    </div>
    <div class="topbar-right">
      <span id="dryrun" class="badge badge-warn" hidden>DRY RUN &mdash; nothing is blocked</span>
      <span id="readonly" class="badge" hidden>read only</span>
      <span id="pulse" class="pulse" title="live"></span>
      <button id="lock" class="ghost" type="button">Lock</button>
    </div>
  </header>

  <main>
    <section class="tiles" id="tiles"></section>
    <section class="panel" id="tile-detail" hidden>
      <div class="panel-head">
        <h2 id="tile-detail-title"></h2>
        <button id="tile-detail-close" class="ghost" type="button" aria-label="Close">&#10005;</button>
      </div>
      <p id="tile-detail-note" class="empty"></p>
      <div id="tile-detail-body"></div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Active bans <span id="ban-count" class="count"></span></h2>
        <form id="ban-form" class="inline-form">
          <input id="ban-key" placeholder="IP or CIDR" spellcheck="false" size="18">
          <input id="ban-duration" placeholder="1h" value="1h" size="6">
          <input id="ban-reason" placeholder="reason" size="20">
          <button type="submit">Ban</button>
        </form>
      </div>
      <div class="scroll">
        <table id="bans">
          <thead><tr>
            <th>Source</th><th>Detector</th><th>Rule</th><th>Country</th>
            <th>Offence</th><th>Hits</th><th>Expires</th><th></th>
          </tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <p id="bans-empty" class="empty">No active bans.</p>
    </section>

    <section class="two-col">
      <div class="panel">
        <div class="panel-head"><h2>Most probed paths</h2></div>
        <div class="scroll short"><table id="top-paths"><tbody></tbody></table></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Top sources</h2></div>
        <div class="scroll short"><table id="top-sources"><tbody></tbody></table></div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Rules that fired</h2>
        <span class="hint">which patterns are earning their place</span>
      </div>
      <div class="scroll short"><table id="top-rules"><tbody></tbody></table></div>
      <p id="top-rules-empty" class="empty">No rule has fired yet.</p>
    </section>

    <section class="panel">
      <div class="panel-head">
        <h2>Live activity</h2>
        <div id="event-filter">
          <button type="button" class="chip on" data-kind="">all</button>
          <button type="button" class="chip" data-kind="ban">bans</button>
          <button type="button" class="chip" data-kind="reject">rejects</button>
          <button type="button" class="chip" data-kind="unban">unbans</button>
        </div>
        <label class="toggle"><input id="follow" type="checkbox" checked> follow</label>
      </div>
      <div class="scroll tall">
        <table id="events">
          <thead><tr>
            <th>Time</th><th>Kind</th><th>Source</th><th>Detector</th>
            <th>Method</th><th>Path</th><th>Detail</th>
          </tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <p id="events-empty" class="empty">Nothing yet.</p>
    </section>

    <section class="two-col">
      <div class="panel">
        <div class="panel-head"><h2>Detectors</h2></div>
        <div id="detectors" class="chips"></div>
        <div class="panel-head"><h2>Configuration</h2></div>
        <div id="config" class="kv"></div>
      </div>
      <div class="panel">
        <div class="panel-head"><h2>Compiled ruleset</h2></div>
        <div id="rules" class="rules"></div>
      </div>
    </section>

    <section class="panel" id="rules-panel">
      <div class="panel-head">
        <h2>Rule editor <span id="rules-badge" class="badge badge-edit" hidden>edited here</span></h2>
        <div class="inline-form">
          <span id="rules-dirty" class="dirty" hidden>unsaved</span>
          <button id="rules-save" type="button">Save and apply</button>
          <button id="rules-revert" class="ghost" type="button">Revert to file config</button>
        </div>
      </div>
      <p id="rules-error" class="banner error" hidden></p>
      <p id="rules-meta" class="meta"></p>
      <div id="rules-form" class="rules-form"></div>
    </section>
  </main>

  <footer><p>scanguard &middot; <span id="footer-instance"></span> &middot; state: <span id="footer-backend"></span></p></footer>
</div>

<div id="toast" class="toast" hidden></div>
<script src="app.js"></script>
</body>
</html>
`

const appCSS = `
/* Keep this first, and keep the !important.
   The console shows and hides whole regions with el.hidden, which relies on the
   browser's built-in [hidden] { display: none }. That rule lives in the user-agent
   stylesheet, so ANY author rule setting display on the same element beats it
   regardless of specificity — and .gate below sets display: grid. The result was
   that unlock() ran, the app appeared, and the login card stayed on screen above
   it: both visible at once, with the app rendered beneath the gate.
   A single reset fixes .gate and inoculates the ten other regions toggled the
   same way (badges, banners, empty states, the toast) against the same trap. */
[hidden] { display: none !important; }

:root {
  color-scheme: light dark;
  --bg: #f6f7f9;
  --panel: #ffffff;
  --ink: #16181d;
  --muted: #6b7280;
  --line: #e3e6ea;
  --accent: #2563eb;
  --danger: #b42318;
  --warn: #b45309;
  --ok: #027a48;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1014;
    --panel: #161a21;
    --ink: #e6e8ec;
    --muted: #9aa3b2;
    --line: #262c36;
    --accent: #60a5fa;
    --danger: #f97066;
    --warn: #fdb022;
    --ok: #32d583;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
h1, h2 { margin: 0; font-weight: 650; letter-spacing: -0.01em; }
h1 { font-size: 17px; }
h2 { font-size: 13px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }

.gate { display: grid; place-items: center; min-height: 100vh; padding: 24px; }
.gate-card {
  background: var(--panel); border: 1px solid var(--line); border-radius: 14px;
  padding: 28px; width: min(380px, 100%); display: grid; gap: 10px;
}
.gate-card h1 { font-size: 22px; }
.gate-card p { margin: 0; color: var(--muted); font-size: 13px; }
.gate-card label { font-size: 12px; color: var(--muted); margin-top: 6px; }

input, button, select {
  font: inherit; color: inherit;
  border: 1px solid var(--line); border-radius: 8px;
  background: var(--bg); padding: 8px 10px;
}
input:focus, button:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
button { cursor: pointer; background: var(--accent); color: #fff; border-color: transparent; font-weight: 600; }
button.ghost { background: transparent; color: var(--muted); border-color: var(--line); font-weight: 500; }
button.link { background: none; border: none; color: var(--danger); padding: 2px 6px; font-weight: 600; }

.topbar {
  display: flex; align-items: center; justify-content: space-between; gap: 16px;
  padding: 14px 20px; background: var(--panel); border-bottom: 1px solid var(--line);
  position: sticky; top: 0; z-index: 5;
}
.brand { display: flex; align-items: center; gap: 12px; }
.brand p { margin: 0; font-size: 12px; color: var(--muted); font-family: var(--mono); }
.mark {
  display: grid; place-items: center; width: 34px; height: 34px; border-radius: 9px;
  background: var(--accent); color: #fff; font-weight: 700; font-size: 13px; letter-spacing: 0.04em;
}
.topbar-right { display: flex; align-items: center; gap: 10px; }
.badge {
  font-size: 11px; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase;
  padding: 4px 8px; border-radius: 999px; border: 1px solid var(--line); color: var(--muted);
}
.badge-warn { color: var(--warn); border-color: currentColor; }
.pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); opacity: 0.35; transition: opacity 0.3s; }
.pulse.on { opacity: 1; }

main { padding: 20px; display: grid; gap: 16px; max-width: 1400px; margin: 0 auto; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.tile {
  background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
  padding: 14px 16px; text-align: left; font: inherit; color: inherit;
  cursor: pointer; width: 100%;
}
.tile:hover { border-color: var(--accent); }
.tile:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.tile[aria-expanded="true"] { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent) inset; }
/* A tile with nothing recorded behind it stays a plain figure, and says so by
   not offering an affordance it cannot honour. */
.tile[disabled] { cursor: default; opacity: 1; }
.tile[disabled]:hover { border-color: var(--line); }
.tile .n { font-size: 24px; font-weight: 660; font-variant-numeric: tabular-nums; }
.tile .l { font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--muted); }
.tile.alert .n { color: var(--danger); }

.panel { background: var(--panel); border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
#event-filter { display: flex; gap: 4px; }
.chip {
  font: inherit; font-size: 12px; padding: 2px 9px; cursor: pointer;
  border: 1px solid var(--line); border-radius: 999px;
  background: transparent; color: var(--muted);
}
.chip:hover { color: var(--fg); }
.chip.on { background: var(--accent); border-color: var(--accent); color: var(--bg); }
.panel-head {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 12px 16px; border-bottom: 1px solid var(--line); flex-wrap: wrap;
}
.two-col { display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 16px; }
.inline-form { display: flex; gap: 6px; flex-wrap: wrap; }
.count { color: var(--muted); font-weight: 500; }
.toggle { font-size: 12px; color: var(--muted); display: flex; align-items: center; gap: 6px; }

.scroll { overflow-x: auto; max-height: 460px; overflow-y: auto; }
.scroll.short { max-height: 220px; }
.scroll.tall { max-height: 520px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th {
  text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em;
  color: var(--muted); font-weight: 600; padding: 8px 12px; position: sticky; top: 0;
  background: var(--panel); border-bottom: 1px solid var(--line); white-space: nowrap;
}
td { padding: 7px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
tbody tr:last-child td { border-bottom: none; }
td.mono, .mono { font-family: var(--mono); font-size: 12px; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
td.wrap { max-width: 420px; word-break: break-all; }
.empty { padding: 16px; color: var(--muted); font-size: 13px; margin: 0; }

.k-ban { color: var(--danger); font-weight: 650; }
.k-unban { color: var(--ok); font-weight: 650; }
.k-reject { color: var(--warn); }
.k-detect { color: var(--accent); }

.chips { display: flex; flex-wrap: wrap; gap: 6px; padding: 12px 16px; }
.chip {
  font-size: 12px; padding: 3px 9px; border-radius: 999px;
  border: 1px solid var(--line); color: var(--muted);
}
.chip.on { color: var(--ok); border-color: currentColor; }
.kv { padding: 4px 16px 14px; display: grid; grid-template-columns: auto 1fr; gap: 4px 14px; font-size: 12px; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; font-family: var(--mono); }
.rules { padding: 12px 16px; display: grid; gap: 12px; max-height: 420px; overflow-y: auto; }
.rules h3 { margin: 0 0 4px; font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.rules ul { margin: 0; padding-left: 16px; font-family: var(--mono); font-size: 11.5px; color: var(--ink); }
.rules li { word-break: break-all; }

/* Rule editor */
.badge-edit { color: var(--accent); border-color: currentColor; }
.dirty { font-size: 12px; color: var(--warn); font-weight: 600; align-self: center; }
.banner {
  margin: 0; padding: 10px 16px; font-size: 12.5px;
  border-bottom: 1px solid var(--line); background: rgba(180, 35, 24, 0.08);
  white-space: pre-wrap; font-family: var(--mono);
}
.meta { margin: 0; padding: 10px 16px 0; font-size: 12px; color: var(--muted); }
.rules-form {
  padding: 12px 16px 18px;
  display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 16px;
  align-items: start;
}
.rule-group {
  border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px;
  display: grid; gap: 10px; align-content: start;
}
.rule-group > h3 {
  margin: 0; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
  color: var(--muted); font-weight: 650;
}
.rule-row { display: grid; gap: 4px; }
.rule-row.inline { grid-template-columns: auto 1fr; align-items: center; gap: 8px; }
.rule-row label { font-size: 12.5px; }
.rule-row .hint { font-size: 11px; color: var(--muted); line-height: 1.35; }
.panel-head .hint { font-size: 11px; color: var(--muted); }
.rule-row input[type="text"], .rule-row input[type="number"], .rule-row textarea {
  width: 100%; font-family: var(--mono); font-size: 12px;
}
.rule-row textarea { min-height: 76px; resize: vertical; }
.rule-row input[type="checkbox"] { width: auto; }
.rule-row.changed > label { color: var(--accent); font-weight: 600; }
.rule-row.changed > label::after { content: " •"; }

footer { padding: 16px 20px 32px; text-align: center; color: var(--muted); font-size: 12px; }
.error { color: var(--danger); font-size: 12px; }
.toast {
  position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
  background: var(--ink); color: var(--bg); padding: 10px 16px; border-radius: 10px;
  font-size: 13px; z-index: 20; box-shadow: 0 6px 24px rgba(0,0,0,0.25);
}
`

const appJS = `
"use strict";

var BASE = location.pathname.replace(/\/(index\.html)?$/, "") + "/";
var TOKEN_KEY = "scanguard.token";
var token = sessionStorage.getItem(TOKEN_KEY) || "";
var lastSeq = 0;
var timer = null;

function $(id) { return document.getElementById(id); }

function headers(mutating) {
  var h = { "Accept": "application/json" };
  if (token) { h["X-Scanguard-Token"] = token; }
  if (mutating) {
    h["Content-Type"] = "application/json";
    h["X-Scanguard-Action"] = "1";
  }
  return h;
}

function api(path, options) {
  var opts = options || {};
  return fetch(BASE + path, {
    method: opts.method || "GET",
    headers: headers(!!opts.method && opts.method !== "GET"),
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    credentials: "omit",
    cache: "no-store"
  }).then(function (r) {
    if (r.status === 401) { lock("That token was not accepted."); throw new Error("unauthorized"); }
    return r.json().then(function (data) {
      if (!r.ok) { throw new Error(data && data.error ? data.error : "request failed"); }
      return data;
    });
  });
}

function toast(msg) {
  var el = $("toast");
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(el.dataset.t);
  el.dataset.t = setTimeout(function () { el.hidden = true; }, 3200);
}

function lock(message) {
  if (timer) { clearInterval(timer); timer = null; }
  token = "";
  sessionStorage.removeItem(TOKEN_KEY);
  // Locking means forget everything, including the drilled-down source addresses
  // still held in memory and which tile was open.
  openTile = null;
  lastState = null;
  sourcesData = { sources: [], total: 0, truncated: false };
  $("tile-detail").hidden = true;
  $("app").hidden = true;
  $("gate").hidden = false;
  var err = $("gate-error");
  if (message) { err.textContent = message; err.hidden = false; } else { err.hidden = true; }
  $("token").focus();
}

function unlock() {
  $("gate").hidden = true;
  $("app").hidden = false;
  refresh();
  if (!timer) { timer = setInterval(tick, 3000); }
}

function cell(row, text, cls) {
  var td = document.createElement("td");
  td.textContent = text === null || text === undefined ? "" : String(text);
  if (cls) { td.className = cls; }
  row.appendChild(td);
  return td;
}

function fmtTime(iso) {
  var d = new Date(iso);
  if (isNaN(d.getTime())) { return ""; }
  return d.toLocaleTimeString();
}

function fmtExpiry(ban) {
  if (!ban.expires || ban.expires.indexOf("0001-01-01") === 0) { return "permanent"; }
  var ms = new Date(ban.expires).getTime() - Date.now();
  if (isNaN(ms)) { return ""; }
  if (ms <= 0) { return "expiring"; }
  var mins = Math.round(ms / 60000);
  if (mins < 60) { return "in " + mins + "m"; }
  var hours = Math.round(mins / 60);
  if (hours < 48) { return "in " + hours + "h"; }
  return "in " + Math.round(hours / 24) + "d";
}

function tile(container, label, value, alert, kind) {
  var d = document.createElement("button");
  d.type = "button";
  d.className = alert ? "tile alert" : "tile";
  if (kind) {
    d.dataset.kind = kind;
    d.setAttribute("aria-expanded", openTile === kind ? "true" : "false");
    d.setAttribute("aria-controls", "tile-detail");
  } else {
    // No data is recorded behind this number, so it does not pretend to be
    // clickable. Better an honest figure than a control that opens an empty box.
    d.disabled = true;
  }
  var n = document.createElement("div");
  n.className = "n";
  n.textContent = String(value);
  var l = document.createElement("div");
  l.className = "l";
  l.textContent = label;
  d.appendChild(n);
  d.appendChild(l);
  container.appendChild(d);
}

function renderTiles(s) {
  var tiles = $("tiles");
  tiles.textContent = "";
  tile(tiles, "requests seen", s.stats.requests, false, "requests");
  tile(tiles, "blocked", s.stats.rejected, s.stats.rejected > 0, "blocked");
  tile(tiles, "detections", s.stats.detections, false, "detections");
  tile(tiles, "active bans", s.bans.length, false, "bans");
  tile(tiles, "tracked sources", s.trackedSources, false, "sources");
  tile(tiles, "exempt", s.stats.exempt, false, "exempt");
}

// ── Tile drill-down ──────────────────────────────────────────────────────────
// The detail expands beneath the tile row rather than replacing the page: the
// console has no router, so a second view would mean hand-rolling navigation,
// history and a back affordance. Keeping the tiles on screen also keeps the
// other five numbers as context for the one being read.

var openTile = null;   // which tile is expanded, or null
var lastState = null;  // the most recent /api/state, so re-render needs no fetch

var TILE_DETAIL = {
  "requests": {
    title: "Requests seen",
    note: "Every request that reached the middleware, grouped by the Host header.",
    cols: ["host", "requests"],
    rows: function (s) { return (s.topHosts || []).map(function (r) { return [r.key, r.count]; }); }
  },
  "blocked": {
    title: "Blocked requests",
    cols: ["time", "source", "path", "rule"],
    events: "reject",
    rows: function (s) { return eventRows(s, "reject"); }
  },
  "detections": {
    title: "Detections",
    cols: ["time", "source", "detector", "path"],
    events: "ban",
    rows: function (s) {
      return (s.events || []).filter(function (e) { return e.kind === "ban"; })
        .slice().reverse().map(function (e) {
          return [fmtTime(e.time) + (e.dryRun ? " (dry)" : ""), e.client || e.key, e.detector, e.path];
        });
    }
  },
  "bans": {
    title: "Active bans",
    note: "The complete ban list \u2014 the same rows as the Active bans panel below.",
    cols: ["source", "detector", "rule", "expires"],
    rows: function (s) {
      return (s.bans || []).map(function (b) { return [b.key, b.detector, b.rule, fmtExpiry(b)]; });
    }
  },
  "sources": {
    title: "Tracked sources",
    note: "Most recently seen first. Fetched on demand \u2014 this table is capped at maxEntries and is not part of the three-second poll.",
    cols: ["source", "last seen", "offences", "distinct bad paths"],
    remote: true,
    rows: function () {
      return (sourcesData.sources || []).map(function (r) {
        return [r.key, fmtTime(r.lastSeen), r.offences, r.badPaths];
      });
    }
  },
  "exempt": {
    title: "Exempt requests",
    note: "Which allowlist rule granted the exemption. A number climbing here with no matching rule usually means an allowlist entry that is broader than intended.",
    cols: ["reason", "requests"],
    rows: function (s) { return (s.topExempt || []).map(function (r) { return [r.key, r.count]; }); }
  }
};

var sourcesData = { sources: [], total: 0, truncated: false };

function eventRows(s, kind) {
  return (s.events || []).filter(function (e) { return e.kind === kind; })
    .slice().reverse().map(function (e) {
      return [fmtTime(e.time), e.client || e.key, e.path, e.rule];
    });
}

function toggleTile(kind) {
  if (openTile === kind) { closeDetail(); return; }
  openTile = kind;
  if (TILE_DETAIL[kind] && TILE_DETAIL[kind].remote) { fetchSources(); }
  renderDetail();
  if (lastState) { renderTiles(lastState); }
}

function closeDetail() {
  openTile = null;
  $("tile-detail").hidden = true;
  if (lastState) { renderTiles(lastState); }
}

function fetchSources() {
  api("api/sources?limit=50").then(function (r) {
    sourcesData = r;
    if (openTile === "sources") { renderDetail(); }
  }).catch(function (err) {
    if (err.message !== "unauthorized") { toast(err.message); }
  });
}

function renderDetail() {
  var spec = TILE_DETAIL[openTile];
  var panel = $("tile-detail");
  if (!spec || !lastState) { panel.hidden = true; return; }

  $("tile-detail-title").textContent = spec.title;
  var rows = spec.rows(lastState) || [];

  // Say what this list is, and above all what it is NOT. The tile counters are
  // all-time; the event ring holds only the last eventLogSize entries, so a
  // detail drawn from it is a recent window, never the whole history.
  var note = spec.note || "";
  if (spec.events) {
    var total = openTile === "blocked" ? lastState.stats.rejected : lastState.stats.detections;
    note = rows.length >= total
      ? "All " + total + " so far."
      : "The " + rows.length + " most recent of " + total + ". Older entries have left the event log.";
  } else if (openTile === "sources" && sourcesData.truncated) {
    note = spec.note + " Showing " + rows.length + " of " + sourcesData.total + ".";
  }
  $("tile-detail-note").textContent = note;
  $("tile-detail-note").hidden = !note;

  var body = $("tile-detail-body");
  body.textContent = "";
  if (!rows.length) {
    var p = document.createElement("p");
    p.className = "empty";
    p.textContent = "Nothing recorded yet.";
    body.appendChild(p);
    panel.hidden = false;
    return;
  }

  var table = document.createElement("table");
  var thead = document.createElement("thead");
  var hr = document.createElement("tr");
  spec.cols.forEach(function (c) {
    var th = document.createElement("th");
    th.textContent = c;
    hr.appendChild(th);
  });
  thead.appendChild(hr);
  table.appendChild(thead);
  var tbody = document.createElement("tbody");
  rows.forEach(function (cells) {
    var tr = document.createElement("tr");
    cells.forEach(function (v, i) { cell(tr, v, i === 0 ? "mono wrap" : ""); });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  body.appendChild(table);
  panel.hidden = false;
}

function renderState(s) {
  $("subtitle").textContent = s.instance + " · up " + s.uptime;
  $("footer-instance").textContent = s.instance;
  $("footer-backend").textContent = s.backend;
  $("dryrun").hidden = !s.dryRun;
  $("readonly").hidden = !s.readOnly;

  lastState = s;
  renderTiles(s);
  if (openTile) { renderDetail(); }

  renderBans(s.bans);
  renderTop("top-rules", s.topRules);
  $("top-rules-empty").hidden = !!(s.topRules && s.topRules.length);
  renderTop("top-paths", s.topPaths);
  renderTop("top-sources", s.topSources);
  renderDetectors(s.config.detectors, s.topDetectors);
  renderConfig(s.config);

  // First paint only. After that the table is fed incrementally from
  // api/events?since=, which is why lastSeq and appendEvents exist — repainting
  // from api/state on every poll capped the console at the 100 events that
  // response carries and made admin.eventLogSize do nothing for the UI.
  if (!eventsPainted && s.events && s.events.length) {
    var chrono = s.events.slice().reverse();
    $("events").tBodies[0].textContent = "";
    appendEvents(chrono);
    eventsPainted = true;
  }
  $("events-empty").hidden = $("events").tBodies[0].rows.length > 0;
}

function renderBans(bans) {
  var body = $("bans").tBodies[0];
  body.textContent = "";
  $("ban-count").textContent = bans.length ? "(" + bans.length + ")" : "";
  $("bans-empty").hidden = bans.length > 0;

  bans.forEach(function (b) {
    var row = document.createElement("tr");
    cell(row, b.key, "mono");
    cell(row, b.detector + (b.manual ? " (manual)" : ""));
    cell(row, b.rule || b.reason || "", "mono wrap");
    cell(row, b.country || "");
    cell(row, b.offences || "", "num");
    cell(row, b.hits || 0, "num");
    cell(row, fmtExpiry(b));

    var td = document.createElement("td");
    var btn = document.createElement("button");
    btn.className = "link";
    btn.type = "button";
    btn.textContent = "unblock";
    btn.addEventListener("click", function () { unban(b.key); });
    td.appendChild(btn);
    row.appendChild(td);
    body.appendChild(row);
  });
}

function renderTop(id, rows) {
  var body = $(id).tBodies[0];
  body.textContent = "";
  (rows || []).forEach(function (r) {
    var row = document.createElement("tr");
    cell(row, r.key, "mono wrap");
    cell(row, r.count, "num");
    body.appendChild(row);
  });
}

function renderDetectors(detectors, top) {
  var counts = {};
  (top || []).forEach(function (t) { counts[t.key] = t.count; });

  var box = $("detectors");
  box.textContent = "";
  Object.keys(detectors || {}).sort().forEach(function (name) {
    var chip = document.createElement("span");
    chip.className = detectors[name] ? "chip on" : "chip";
    chip.textContent = name + (counts[name] ? " · " + counts[name] : "");
    chip.title = detectors[name] ? "enabled" : "disabled";
    box.appendChild(chip);
  });
}

function renderConfig(cfg) {
  var dl = $("config");
  dl.textContent = "";
  var rows = [
    ["state backend", cfg.storeBackend],
    ["observe responses", cfg.observeResponse ? "yes" : "no"],
    ["ban key width", "IPv4 /" + cfg.ipv4Prefix + " · IPv6 /" + cfg.ipv6Prefix],
    ["trusted proxies", cfg.trustedProxies + (cfg.clientIPHeader ? " · " + cfg.clientIPHeader : "")],
    ["reject status", cfg.rejectStatus],
    ["escalation", (cfg.escalation || []).join(" → ")],
    ["decay", cfg.decay],
    ["tarpit", cfg.tarpit ? "on" : "off"],
    // Read-only: admin.* is not console-editable, and this one decides where the
    // console is reachable from. Change it in the plugin configuration.
    ["console on detection routes",
      cfg.adminOnDetectionRoutes
        ? "YES \u2014 also served on every route the detector protects"
        : "no \u2014 this router only"],
    ["max tracked", cfg.maxEntries],
    ["notifications", Object.keys(cfg.notify || {}).filter(function (k) { return cfg.notify[k]; }).join(", ") || "none"]
  ];
  rows.forEach(function (pair) {
    var dt = document.createElement("dt");
    dt.textContent = pair[0];
    var dd = document.createElement("dd");
    dd.textContent = String(pair[1]);
    dl.appendChild(dt);
    dl.appendChild(dd);
  });
}

function renderRules(rules) {
  var box = $("rules");
  box.textContent = "";
  var groups = [
    ["Signatures", rules.signatures],
    ["Honeypots", rules.honeypots],
    ["User agents", rules.userAgents],
    ["Payload", rules.payload],
    ["Allowlisted CIDRs", rules.allowCIDRs],
    ["Trusted proxies", rules.trusted]
  ];
  groups.forEach(function (g) {
    if (!g[1] || !g[1].length) { return; }
    var wrap = document.createElement("div");
    var h = document.createElement("h3");
    h.textContent = g[0] + " (" + g[1].length + ")";
    var ul = document.createElement("ul");
    g[1].forEach(function (item) {
      var li = document.createElement("li");
      li.textContent = item;
      ul.appendChild(li);
    });
    wrap.appendChild(h);
    wrap.appendChild(ul);
    box.appendChild(wrap);
  });
}

// eventKind is the activity filter. Empty means every kind.
var eventKind = "";
// eventsPainted records that the table has had its one repaint from api/state.
// Everything after that arrives through api/events, so a filtered feed that is
// legitimately empty is not mistaken for "not painted yet".
var eventsPainted = false;

function setEventKind(kind) {
  if (eventKind === kind) { return; }
  eventKind = kind;
  lastSeq = 0;
  eventsPainted = true;
  $("events").tBodies[0].textContent = "";
  var buttons = document.querySelectorAll("#event-filter button");
  for (var i = 0; i < buttons.length; i++) {
    buttons[i].className = buttons[i].getAttribute("data-kind") === kind ? "chip on" : "chip";
  }
  // Repaint straight from the ring rather than waiting for the next state poll,
  // so the filter feels like a filter and not like a three-second stall.
  var url = "api/events?since=0&limit=500";
  if (kind) { url += "&kind=" + encodeURIComponent(kind); }
  api(url).then(function (r) {
    appendEvents(r.events);
    $("events-empty").hidden = $("events").tBodies[0].rows.length > 0;
  }).catch(function () {});
}

function appendEvents(events) {
  if (!events || !events.length) { return; }
  var table = $("events");
  var body = table.tBodies[0];

  events.forEach(function (e) {
    if (e.seq > lastSeq) { lastSeq = e.seq; }
    var row = document.createElement("tr");
    cell(row, fmtTime(e.time), "mono");
    var k = cell(row, e.kind + (e.dryRun ? " (dry)" : ""));
    k.className = "k-" + e.kind;
    cell(row, e.key || e.client || "", "mono");
    cell(row, e.detector || "");
    cell(row, e.method || "");
    cell(row, e.path || "", "mono wrap");
    cell(row, e.rule || e.banFor || e.actor || "", "wrap");
    body.insertBefore(row, body.firstChild);
  });

  while (body.rows.length > 400) { body.deleteRow(body.rows.length - 1); }
  $("events-empty").hidden = body.rows.length > 0;
  if ($("follow").checked) { table.parentNode.scrollTop = 0; }
}

function pulse() {
  var p = $("pulse");
  p.classList.add("on");
  setTimeout(function () { p.classList.remove("on"); }, 400);
}

/* ---------------------------------------------------------------- rule editor
 * The form is generated from this schema rather than written out in HTML: the
 * whole page lives in a Go string constant, so every field spelled out by hand
 * is a field that can drift from the Go struct without anything noticing.
 * Each "p" is the JSON path into the editable configuration.
 */
var RULE_SCHEMA = [
  { title: "General", fields: [
    { p: "dryRun", t: "bool", l: "Dry run",
      h: "Run every detector and record what would have happened, but never block. Start here." }
  ]},
  { title: "Path signatures", fields: [
    { p: "detectors.signatures.enabled", t: "bool", l: "Enabled" },
    { p: "detectors.signatures.useDefaults", t: "bool", l: "Include built-in signatures" },
    { p: "detectors.signatures.patterns", t: "lines", l: "Extra patterns",
      h: "One regular expression per line, matched against the request path." },
    { p: "detectors.signatures.exclude", t: "lines", l: "Exclusions",
      h: "Paths matching these are never treated as probes. Use this if you run WordPress." }
  ]},
  { title: "Honeypots", fields: [
    { p: "detectors.honeypots.enabled", t: "bool", l: "Enabled" },
    { p: "detectors.honeypots.paths", t: "lines", l: "Trap paths",
      h: "Exact paths, one per line, each starting with /. A single hit bans immediately." }
  ]},
  { title: "Scanner user-agents", fields: [
    { p: "detectors.userAgent.enabled", t: "bool", l: "Enabled",
      h: "The most expensive detector. Turning it off recovers most of the throughput." },
    { p: "detectors.userAgent.useDefaults", t: "bool", l: "Include built-in patterns" },
    { p: "detectors.userAgent.banEmptyUA", t: "bool", l: "Ban requests with no User-Agent" },
    { p: "detectors.userAgent.patterns", t: "lines", l: "Extra patterns" },
    { p: "detectors.userAgent.crawlers", t: "select", l: "SEO crawlers",
      opts: ["ignore", "ban", "exempt"],
      h: "MJ12bot, AhrefsBot, SemrushBot and friends \u2014 crawlers, not scanners. ignore: no opinion. ban: block them. exempt: never ban them by any detector \u2014 convenient for a real content site, but a User-Agent is trivially forged, so it is a free pass past everything. Search engines are never in this list." }
  ]},
  { title: "Distinct failing paths", fields: [
    { p: "detectors.badPaths.enabled", t: "bool", l: "Enabled" },
    { p: "detectors.badPaths.capacity", t: "int", l: "Distinct paths to trip" },
    { p: "detectors.badPaths.leak", t: "text", l: "Leak interval",
      h: "One remembered path drains per interval, e.g. 10s. Counts DISTINCT paths, so one broken link hammered by a real user never bans them." },
    { p: "detectors.badPaths.statuses", t: "ints", l: "Statuses counted", h: "Comma separated." }
  ]},
  { title: "Brute force", fields: [
    { p: "detectors.bruteForce.enabled", t: "bool", l: "Enabled" },
    { p: "detectors.bruteForce.capacity", t: "int", l: "Failures to trip" },
    { p: "detectors.bruteForce.window", t: "text", l: "Window", h: "e.g. 60s" },
    { p: "detectors.bruteForce.statuses", t: "ints", l: "Failure statuses" },
    { p: "detectors.bruteForce.paths", t: "lines", l: "Only these paths",
      h: "Regular expressions. Leave empty to watch every path." }
  ]},
  { title: "Request rate", fields: [
    { p: "detectors.rateAbuse.enabled", t: "bool", l: "Enabled" },
    { p: "detectors.rateAbuse.rps", t: "int", l: "Requests per second" },
    { p: "detectors.rateAbuse.burst", t: "int", l: "Burst allowance" }
  ]},
  { title: "Payload probes", fields: [
    { p: "detectors.payload.enabled", t: "bool", l: "Enabled",
      h: "Highest false-positive risk of any detector. Inspects attacker-controlled text." },
    { p: "detectors.payload.useDefaults", t: "bool", l: "Include built-in patterns" },
    { p: "detectors.payload.scanQuery", t: "bool", l: "Scan the query string" },
    { p: "detectors.payload.scanBody", t: "bool", l: "Scan the request body" },
    { p: "detectors.payload.maxBodyBytes", t: "int", l: "Max body bytes" },
    { p: "detectors.payload.patterns", t: "lines", l: "Extra patterns" }
  ]},
  { title: "Allowlist", fields: [
    { p: "allowlist.cidrs", t: "lines", l: "Never-ban CIDRs",
      h: "Office egress, uptime monitors. One per line; a bare address is treated as a host route." },
    { p: "allowlist.userAgents", t: "lines", l: "Never-ban user-agents" },
    { p: "allowlist.paths", t: "lines", l: "Never-checked paths" }
  ]},
  { title: "Enforcement", fields: [
    { p: "enforcement.rejectStatus", t: "int", l: "Reject status",
      h: "403 is honest; 404 hides that the middleware exists." },
    { p: "enforcement.rejectBody", t: "text", l: "Reject body" },
    { p: "enforcement.escalation", t: "strs", l: "Ban ladder",
      h: "Comma separated durations, one rung per repeat offence. 0 means permanent." },
    { p: "enforcement.decay", t: "text", l: "Offence decay",
      h: "Behave this long and drop one rung." },
    { p: "enforcement.tarpit.enabled", t: "bool", l: "Tarpit instead of rejecting at once" },
    { p: "enforcement.tarpit.delay", t: "text", l: "Tarpit delay" },
    { p: "enforcement.tarpit.maxConcurrent", t: "int", l: "Max concurrent tarpits",
      h: "Every tarpitted request holds a connection open. Too high and a scanner turns this into a denial of service against you." }
  ]}
];

var ruleModel = null;
var ruleFromFile = null;
var rulesDirty = false;

function getPath(obj, path) {
  var parts = path.split(".");
  var cur = obj;
  for (var i = 0; i < parts.length; i++) {
    if (cur === null || cur === undefined) { return undefined; }
    cur = cur[parts[i]];
  }
  return cur;
}

function setPath(obj, path, value) {
  var parts = path.split(".");
  var cur = obj;
  for (var i = 0; i < parts.length - 1; i++) {
    if (typeof cur[parts[i]] !== "object" || cur[parts[i]] === null) { cur[parts[i]] = {}; }
    cur = cur[parts[i]];
  }
  cur[parts[parts.length - 1]] = value;
}

// Go omits false, zero and empty slices from its JSON, so an absent field is
// normal rather than an error. Normalise by declared type instead of guessing.
function coerce(kind, v) {
  if (kind === "bool") { return v === true; }
  if (kind === "int") { return typeof v === "number" ? v : 0; }
  if (kind === "text" || kind === "select") { return typeof v === "string" ? v : ""; }
  return Array.isArray(v) ? v : [];
}

function toField(kind, v) {
  if (kind === "lines") { return coerce(kind, v).join("\n"); }
  if (kind === "ints" || kind === "strs") { return coerce(kind, v).join(", "); }
  if (kind === "int") { return String(coerce(kind, v)); }
  return coerce(kind, v);
}

function fromField(kind, raw) {
  if (kind === "bool") { return raw === true; }
  if (kind === "int") { var n = parseInt(raw, 10); return isNaN(n) ? 0 : n; }
  if (kind === "text" || kind === "select") { return String(raw); }
  var parts = kind === "lines" ? String(raw).split(/\r?\n/) : String(raw).split(",");
  var out = [];
  for (var i = 0; i < parts.length; i++) {
    var t = parts[i].trim();
    if (!t) { continue; }
    if (kind === "ints") {
      var m = parseInt(t, 10);
      if (!isNaN(m)) { out.push(m); }
    } else {
      out.push(t);
    }
  }
  return out;
}

function setRulesDirty(v) {
  rulesDirty = v;
  $("rules-dirty").hidden = !v;
}

function markChanged(row, f) {
  var mine = JSON.stringify(coerce(f.t, getPath(ruleModel, f.p)));
  var file = JSON.stringify(coerce(f.t, getPath(ruleFromFile, f.p)));
  if (mine === file) { row.classList.remove("changed"); } else { row.classList.add("changed"); }
}

function ruleRow(f, readOnly) {
  var row = document.createElement("div");
  row.className = f.t === "bool" ? "rule-row inline" : "rule-row";

  var input;
  if (f.t === "bool") {
    input = document.createElement("input");
    input.type = "checkbox";
    input.checked = coerce("bool", getPath(ruleModel, f.p));
  } else if (f.t === "select") {
    input = document.createElement("select");
    (f.opts || []).forEach(function (o) {
      var opt = document.createElement("option");
      opt.value = o;
      opt.textContent = o;
      input.appendChild(opt);
    });
    input.value = toField(f.t, getPath(ruleModel, f.p)) || (f.opts || [])[0];
  } else if (f.t === "lines") {
    input = document.createElement("textarea");
    input.value = toField(f.t, getPath(ruleModel, f.p));
    input.spellcheck = false;
  } else {
    input = document.createElement("input");
    input.type = f.t === "int" ? "number" : "text";
    input.value = toField(f.t, getPath(ruleModel, f.p));
    input.spellcheck = false;
  }
  input.id = "f-" + f.p.replace(/\./g, "-");
  input.disabled = readOnly;

  var label = document.createElement("label");
  label.textContent = f.l;
  label.htmlFor = input.id;

  function sync() {
    setPath(ruleModel, f.p, fromField(f.t, f.t === "bool" ? input.checked : input.value));
    markChanged(row, f);
    setRulesDirty(true);
  }
  input.addEventListener("change", sync);
  input.addEventListener("input", sync);

  if (f.t === "bool") {
    row.appendChild(input);
    row.appendChild(label);
  } else {
    row.appendChild(label);
    row.appendChild(input);
  }
  if (f.h) {
    var hint = document.createElement("div");
    hint.className = "hint";
    hint.textContent = f.h;
    row.appendChild(hint);
  }
  markChanged(row, f);
  return row;
}

function renderRuleEditor(data, readOnly) {
  ruleModel = data.effective || {};
  ruleFromFile = data.fromFile || {};
  setRulesDirty(false);
  $("rules-error").hidden = true;

  var owned = data.overridden || [];
  $("rules-badge").hidden = owned.length === 0;
  $("rules-save").disabled = readOnly;
  $("rules-revert").disabled = readOnly || owned.length === 0;

  var meta = $("rules-meta");
  if (owned.length) {
    var when = data.updated ? new Date(data.updated).toLocaleString() : "";
    meta.textContent = "Managed here: " + owned.join(", ") +
      (when ? " — last saved " + when : "") +
      (data.actor ? " by " + data.actor : "") +
      ". Traefik's file configuration supplies everything else, and no longer controls these sections.";
  } else {
    meta.textContent = "Running Traefik's file configuration. Saving here takes over these sections " +
      "until you revert; changes apply immediately, with no Traefik restart.";
  }

  var box = $("rules-form");
  box.textContent = "";
  RULE_SCHEMA.forEach(function (group) {
    var g = document.createElement("div");
    g.className = "rule-group";
    var h = document.createElement("h3");
    h.textContent = group.title;
    g.appendChild(h);
    group.fields.forEach(function (f) { g.appendChild(ruleRow(f, readOnly)); });
    box.appendChild(g);
  });
}

function showRuleError(message) {
  var e = $("rules-error");
  e.textContent = message;
  e.hidden = false;
  e.scrollIntoView({ block: "nearest" });
}

function loadRules(readOnly) {
  return api("api/rules")
    .then(function (data) { renderRuleEditor(data, readOnly); })
    .catch(function (err) {
      if (err.message !== "unauthorized") { showRuleError(err.message); }
    });
}

function saveRules() {
  if (!ruleModel) { return; }
  $("rules-error").hidden = true;
  api("api/rules", { method: "PUT", body: ruleModel })
    .then(function (data) {
      renderRuleEditor(data, false);
      toast("Rules applied");
      return refresh();
    })
    .catch(function (err) {
      if (err.message !== "unauthorized") { showRuleError(err.message); }
    });
}

function revertRules() {
  if (!window.confirm("Discard the rules saved here and go back to Traefik's file configuration?")) { return; }
  api("api/rules", { method: "DELETE" })
    .then(function (data) {
      renderRuleEditor(data, false);
      toast("Reverted to the file configuration");
      return refresh();
    })
    .catch(function (err) {
      if (err.message !== "unauthorized") { showRuleError(err.message); }
    });
}

function refresh() {
  var readOnly = false;
  return api("api/state").then(function (s) {
    readOnly = !!s.readOnly;
    renderState(s);
    pulse();
    return api("api/rules/compiled");
  }).then(function (compiled) {
    renderRules(compiled);
    // Never overwrite a half-typed rule set. An unban elsewhere on the page
    // triggers a refresh, and losing someone's unsaved regex to it would be
    // its own small betrayal.
    if (!rulesDirty) { return loadRules(readOnly); }
    return null;
  }).catch(function (err) {
    if (err.message !== "unauthorized") { toast(err.message); }
  });
}

function tick() {
  api("api/state").then(function (s) {
    renderState(s);
    if (openTile === "sources") { fetchSources(); }
    pulse();
    return pollEvents();
  }).catch(function (err) {
    if (err.message !== "unauthorized") { toast(err.message); }
  });
}

// pollEvents appends everything the ring has produced since the last poll. A
// failure here is deliberately silent: the activity feed falling behind is not
// worth a toast on top of whatever already failed.
function pollEvents() {
  if (!eventsPainted) { return; }
  var url = "api/events?since=" + lastSeq + "&limit=500";
  if (eventKind) { url += "&kind=" + encodeURIComponent(eventKind); }
  return api(url).then(function (r) {
    appendEvents(r.events);
  }).catch(function () {});
}

function unban(key) {
  api("api/bans?key=" + encodeURIComponent(key), { method: "DELETE" })
    .then(function (r) {
      toast(r.unbanned ? "Unblocked " + r.key : "No ban found for " + r.key);
      return refresh();
    })
    .catch(function (err) { toast(err.message); });
}

document.addEventListener("DOMContentLoaded", function () {
  $("gate-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    token = $("token").value.trim();
    sessionStorage.setItem(TOKEN_KEY, token);
    api("api/health").then(unlock).catch(function () { /* lock() already reported it */ });
  });

  $("lock").addEventListener("click", function () { lock(""); });

  // Delegated, because renderTiles() rebuilds the buttons on every poll.
  $("tiles").addEventListener("click", function (ev) {
    var btn = ev.target.closest ? ev.target.closest(".tile") : null;
    if (btn && btn.dataset.kind) { toggleTile(btn.dataset.kind); }
  });
  $("tile-detail-close").addEventListener("click", closeDetail);
  document.addEventListener("keydown", function (ev) {
    if (ev.key === "Escape" && openTile) { closeDetail(); }
  });
  var filterButtons = document.querySelectorAll("#event-filter button");
  for (var fi = 0; fi < filterButtons.length; fi++) {
    filterButtons[fi].addEventListener("click", function (ev) {
      setEventKind(ev.currentTarget.getAttribute("data-kind"));
    });
  }
  $("rules-save").addEventListener("click", saveRules);
  $("rules-revert").addEventListener("click", revertRules);

  // Losing a page of hand-written regular expressions to a stray navigation is
  // exactly the kind of small cruelty a security console should not commit.
  window.addEventListener("beforeunload", function (ev) {
    if (rulesDirty) { ev.preventDefault(); ev.returnValue = ""; }
  });

  $("ban-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var key = $("ban-key").value.trim();
    if (!key) { return; }
    api("api/bans", {
      method: "POST",
      body: { key: key, duration: $("ban-duration").value.trim() || "1h", reason: $("ban-reason").value.trim() }
    }).then(function (r) {
      toast("Banned " + r.ban.key);
      $("ban-key").value = "";
      $("ban-reason").value = "";
      return refresh();
    }).catch(function (err) { toast(err.message); });
  });

  if (token) {
    api("api/health").then(unlock).catch(function () { /* lock() already reported it */ });
  } else {
    lock("");
  }
});
`
