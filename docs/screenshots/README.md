# The console, screen by screen

Every state of the scanguard console, taken by the docs tour
(`e2e/docs/tour.spec.ts`) against the [examples harness](../../examples/) after
`scanner-sim.sh` has run. Regenerate with `scripts/docs-screenshots.sh`
(README, "Screenshots"). Addresses are documentation ranges (RFC 5737).

## Access gate

The console asks for the `admin.token` before it shows anything; the token is
sent as the `X-Scanguard-Token` header and kept in the tab's session storage.

<img src="console-gate.png" alt="The access gate: a single Access token field and an Unlock button" width="800">

## Overview

Counters across the top, then every active ban: the source, the detector and
rule that caught it, offence count, hits since the ban, and when it expires.
The form above the table bans an address or CIDR by hand.

<img src="console-overview.png" alt="The console overview: six counter tiles and the active ban list with detector, rule and expiry" width="800">

The same page in a dark colour scheme (it follows the browser's), and the top
of it on a phone, where the tiles and the ban form stack (the ban table scrolls
sideways there and reads better on a wider screen):

<img src="console-overview.dark.png" alt="The console overview in dark mode" width="800">

<img src="console-overview.mobile.png" alt="The console header, stacked counter tiles and the ban form at phone width" width="300">

## Empty console

A fresh instance before anything has been probed.

<img src="console-empty.png" alt="The console with zero counters, No active bans and an empty activity feed" width="800">

## Counter drill-down

Each counter opens the records behind it; here, every detection the event log
holds (manual bans are not detections, so they are not listed).

<img src="console-tile-detail.png" alt="The detections tile opened: time, source, detector and path for each detection" width="800">

## Live activity

The event feed, polled every three seconds, filtered here to bans: which rule
fired, on which path, and for how long the source is banned.

<img src="console-activity.png" alt="The live activity feed filtered to ban events" width="800">

## Most probed paths, top sources, rules that fired

What scanners ask for, who asks most, and which patterns are earning their
place. Each list scrolls inside its panel.

<img src="console-top.png" alt="Most probed paths and top sources side by side, and the list of rules that fired with their counts" width="800">

## Detectors and compiled ruleset

Which detectors are on (with their hit counts), the running configuration, and
every pattern currently compiled in (a scrolling list).

<img src="console-ruleset.png" alt="Detector chips, the configuration summary and the compiled ruleset" width="800">

## Rule editor

Every detector, threshold, allowlist and enforcement setting, applied on the
next request without a Traefik restart. A changed field is marked and the
editor says the change is unsaved. (The first two rows of groups; rate,
payload, allowlist and enforcement follow below.)

<img src="console-rule-editor.png" alt="The rule editor with one changed honeypot path marked and the unsaved indicator showing" width="800">

An invalid edit — here a broken regular expression — comes back as a 422 with
the parser's reason, and the running rules stay as they were.

<img src="console-rule-editor-error.png" alt="The rule editor showing the parser's error for an unclosed regular expression" width="800">
