#!/usr/bin/env bash
# Verifies the notification path end to end.
#
# This is the one thing the Go tests cannot cover: outbound HTTP made from a
# goroutine spawned by INTERPRETED plugin code, inside the Traefik container.
# A panic in that goroutine is not recovered by Traefik and kills the whole
# process, so "did the webhook arrive, and is Traefik still alive afterwards"
# is a question worth asking of the real thing.
set -uo pipefail

BASE="${BASE:-http://localhost:8800}"
CONSOLE="${CONSOLE:-http://localhost:9900}"
HOOKS="${HOOKS:-http://localhost:8899}"
TOKEN="${TOKEN:-dev-token-change-me-0123456789}"

pass=0
fail=0
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; pass=$((pass + 1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; fail=$((fail + 1)); }

received() { curl -s --max-time 10 "$HOOKS/received"; }
clear_received() { curl -s -X DELETE --max-time 10 "$HOOKS/received" >/dev/null; }
jqp() { python3 -c "import json,sys;d=json.load(sys.stdin);$1"; }

# wait_for <python-expr-on-d> <seconds>
wait_for() {
  local expr="$1" limit="${2:-15}" i
  for ((i = 0; i < limit * 4; i++)); do
    if received | jqp "sys.exit(0 if ($expr) else 1)" 2>/dev/null; then return 0; fi
    sleep 0.25
  done
  return 1
}

say "Trigger a ban and wait for the webhook"
clear_received
src="198.51.100.$((RANDOM % 100 + 120))"
curl -s -o /dev/null --max-time 10 -H "X-Real-Ip: $src" "$BASE/wp-login.php"

if wait_for 'any(x["path"]=="/ban" for x in d)' 15; then
  ok "the generic webhook was delivered"
else
  bad "no webhook arrived within 15s"
fi

say "Payload contract"
hook=$(received | jqp 'print(json.dumps([x for x in d if x["path"]=="/ban"][0]) if any(x["path"]=="/ban" for x in d) else "{}")')
if [[ "$hook" != "{}" ]]; then
  check_field() { # check_field <description> <python-expr> <expected>
    got=$(printf '%s' "$hook" | jqp "print($2)")
    if [[ "$got" == "$3" ]]; then ok "$1 ($got)"; else bad "$1 — expected $3, got $got"; fi
  }
  check_field "source identifies scanguard" 'd["json"]["source"]' "scanguard"
  check_field "event kind is a ban"        'd["json"]["event"]["kind"]' "ban"
  check_field "detector is reported"       'd["json"]["event"]["detector"]' "signature"
  check_field "the offending path is included" 'd["json"]["event"]["path"]' "/wp-login.php"
  check_field "the ban duration is included"   'd["json"]["event"]["banFor"]' "1h"
  check_field "configured headers are sent"    'd["headers"].get("x-harness","")' "scanguard"
  check_field "content type is JSON"           '"json" in d["contentType"]' "True"
  banned_key=$(printf '%s' "$hook" | jqp 'print(d["json"]["event"]["key"])')
  if [[ "$banned_key" == "$src/32" ]]; then
    ok "the banned key is the real source ($banned_key)"
  else
    bad "banned key is $banned_key, expected $src/32"
  fi
else
  bad "no webhook payload to inspect"
fi

say "Chat notification"
if wait_for 'any(x["path"]=="/ntfy" for x in d)' 10; then
  ok "the chat notification was delivered"
  body=$(received | jqp 'print([x for x in d if x["path"]=="/ntfy"][0]["raw"])')
  if [[ "$body" == *"$src"* ]]; then ok "the message names the banned source"; else bad "message: $body"; fi
  if [[ "$body" == \{* ]]; then bad "ntfy should get plain text, got JSON"; else ok "ntfy received plain text"; fi
else
  bad "no chat notification arrived"
fi

say "Unban is notified too"
clear_received
curl -s -X DELETE --max-time 10 -H "X-Scanguard-Token: $TOKEN" -H "X-Scanguard-Action: 1" \
  "$CONSOLE/api/bans?key=$src%2F32" >/dev/null
if wait_for 'any(x["json"] and x["json"]["event"]["kind"]=="unban" for x in d if x["path"]=="/ban")' 10; then
  ok "the unban event was delivered"
else
  bad "no unban notification arrived"
fi

say "Per-request rejects are NOT notified"
# A banned source hitting the site repeatedly must not turn the webhook endpoint
# into a firehose; only ban and unban are delivered.
clear_received
# .150-.199: a range scanner-sim.sh never touches. Drawn from .20-.119 this
# collided with sources scanner-sim had already banned, and then /.env created
# no new ban, the wait below timed out quietly, and before == after held
# without anything having been tested.
src2="198.51.100.$((RANDOM % 50 + 150))"
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "X-Real-Ip: $src2" "$BASE/.env")
if [[ "$code" == "403" ]]; then
  ok "the probe from $src2 was refused, so there is a ban to be rejected under"
else
  bad "the probe from $src2 returned $code; the step below would be vacuous"
fi
# The baseline is taken only once BOTH deliveries of that ban have landed (the
# webhook and the chat message go out one after the other); taken between them
# it moved by one on its own.
wait_for 'any(x["path"]=="/ban" for x in d) and any(x["path"]=="/ntfy" for x in d)' 10 >/dev/null
before=$(received | jqp 'print(len(d))')
for _ in $(seq 1 15); do curl -s -o /dev/null --max-time 5 -H "X-Real-Ip: $src2" "$BASE/" ; done
sleep 2
after=$(received | jqp 'print(len(d))')
if [[ "$before" == "$after" ]]; then
  ok "15 rejected requests produced no extra notifications ($after total)"
else
  bad "notification count grew from $before to $after; rejects are being delivered"
fi
# Lift the ban, so a rerun inside the hour starts from a source that can be banned.
curl -s -X DELETE --max-time 10 -H "X-Scanguard-Token: $TOKEN" -H "X-Scanguard-Action: 1" \
  "$CONSOLE/api/bans?key=$src2%2F32" >/dev/null

say "A dead endpoint does not take Traefik with it"
# Point a webhook at a black hole, trigger bans, and confirm the proxy is fine.
# An unrecovered panic in a notifier goroutine would kill the whole process.
#
# The probe instance gets a router of its own: a middleware no router references
# is never instantiated by Traefik, so without one this step exercised nothing.
# It trusts the same proxies as the main instance so X-Real-Ip is believed, and
# the sources are real addresses — "198.51.100.9$RANDOM" produced strings like
# 198.51.100.912345, which no parser accepts, so nothing was ever bannable.
#
# The probe is a HONEYPOT only this instance knows, with its signatures off. A
# probe for /deadhook/.git/config was refused by the MAIN instance whenever the
# router had not loaded yet (its .git/config signature matched), so the step
# passed without the dead-webhook instance ever having run.
cat > /tmp/scanguard-deadhook.yml <<'EOF'
http:
  routers:
    scanguard-deadhook-probe:
      rule: PathPrefix(`/deadhook/`)
      entryPoints: [web]
      service: site
      priority: 200
      middlewares: [scanguard-deadhook-probe]
  middlewares:
    scanguard-deadhook-probe:
      plugin:
        scanguard:
          instanceName: deadhook
          store: {backend: memory}
          clientIP:
            trustedProxies: [127.0.0.1/32, 172.16.0.0/12]
            header: X-Real-Ip
          detectors:
            signatures: {enabled: false}
            userAgent: {enabled: false}
            badPaths: {enabled: false}
            honeypots: {enabled: true, paths: [/deadhook/trap]}
          admin: {enabled: false}
          notify:
            timeout: 1s
            webhooks:
              # TEST-NET-1: packets go nowhere and nothing answers, so the
              # delivery runs into notify.timeout. 127.0.0.1:1 was refused at
              # once and the timeout path never ran.
              - url: http://192.0.2.1:9/nowhere
EOF
cp /tmp/scanguard-deadhook.yml dynamic/zz-deadhook.yml
# Wait for the router instead of sleeping: until it loads, the probe reaches
# nginx and comes back 404.
for _ in $(seq 1 40); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -H "X-Real-Ip: 198.51.100.200" "$BASE/deadhook/trap")
  [[ "$code" == "403" ]] && break
  sleep 0.5
done
deadhook_bans=0
for n in $(seq 1 5); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5     -H "X-Real-Ip: 198.51.100.$((200 + n))" "$BASE/deadhook/trap")
  [[ "$code" == "403" ]] && deadhook_bans=$((deadhook_bans + 1))
done
if [[ "$deadhook_bans" -eq 5 ]]; then
  ok "five sources were banned by the instance with the dead webhook"
else
  bad "only $deadhook_bans of 5 probes were refused by the dead-webhook instance; the step is not exercising it"
fi
# And by THAT instance: the main console must know nothing about them.
main_bans=$(curl -s --max-time 10 -H "X-Scanguard-Token: $TOKEN" "$CONSOLE/api/bans" | grep -o '"key":"198.51.100.20[0-5]/32"' | wc -l)
if [[ "$main_bans" -eq 0 ]]; then
  ok "the main instance did not ban the dead-webhook probes"
else
  bad "the main instance banned $main_bans of the dead-webhook probes; the step was measuring the wrong instance"
fi
sleep 3
if curl -sf -o /dev/null --max-time 5 "$BASE/"; then
  ok "Traefik is still serving after failed webhook deliveries"
else
  bad "Traefik stopped serving — a notifier goroutine may have panicked"
fi
rm -f dynamic/zz-deadhook.yml /tmp/scanguard-deadhook.yml
sleep 2

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
