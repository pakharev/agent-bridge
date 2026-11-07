#!/usr/bin/env bash
# End-to-end over the real relay with two isolated identities. Uses ~10 relay messages.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
ab() { local who=$1; shift; XDG_CONFIG_HOME=$T/$who/c XDG_CACHE_HOME=$T/$who/h python3 -I "$HERE/agent_bridge.py" "$@"; }
cleanup() { kill $LA $LB 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT

INV=$(ab alice invite --as alice | head -1)
ab alice listen > "$T/alice.out" 2>&1 & LA=$!
sleep 2
ab bob join "$INV" --as bob --wait 30
ab bob listen > "$T/bob.out" 2>&1 & LB=$!
sleep 3
ab alice send bob "hello bob"
ab bob send alice "$(printf 'hello alice\nsecond line')"
echo "spent invite, third party:"; ab mallory join "$INV" --as mallory --wait 8
sleep 6
ab bob close alice
sleep 5
echo "=== alice"; cat "$T/alice.out"; ab alice channels
echo "=== bob"; cat "$T/bob.out"; ab bob channels
echo "=== mallory"; ab mallory channels
