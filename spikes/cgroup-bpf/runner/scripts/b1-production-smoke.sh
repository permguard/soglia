#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Diagnostic-only positive B1 startup check. The authoritative B1 matrix is separate.

set -euo pipefail

binary="${1:?usage: b1-production-smoke.sh <soglia> <config>}"
config="${2:?usage: b1-production-smoke.sh <soglia> <config>}"
run_id="b1-diagnostic-smoke-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
unit="soglia-b1"
runtime="/run/soglia-b1"
state="$runtime/cgroup-bpf/state.json"
pin_parent="/sys/fs/bpf/soglia-b1"
cgroup="/sys/fs/cgroup/system.slice/$unit.service"
executions="$cgroup/executions"

mkdir -p "$evidence/positive" "$evidence/final"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

cleanup() {
  set +e
  systemctl stop "$unit.service" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  if [[ -f "$state" ]] && jq -e '.pin_root and .links and .maps' "$state" >/dev/null 2>&1; then
    while IFS= read -r pin; do
      if [[ -e "$pin" ]]; then rm "$pin"; fi
    done < <(jq -r '.links[].pin, .maps[].pin' "$state")
    owned_root=$(jq -r .pin_root "$state")
    rmdir "$owned_root/links" "$owned_root/maps" "$owned_root" 2>/dev/null
  fi
  rm -f "$state" "$runtime/cgroup-bpf/.state.json.tmp"
  if [[ -f "$runtime/net/host.json" ]] \
    && [[ $(jq -r .dummy "$runtime/net/host.json" 2>/dev/null) == soglia0 ]] \
    && [[ $(jq -r .proxy_address "$runtime/net/host.json" 2>/dev/null) == 10.200.255.1 ]]; then
    nft delete table inet soglia_host >/dev/null 2>&1
    ip link delete soglia0 >/dev/null 2>&1
    rm -f "$runtime/net/host.json"
  fi
  rm -f "$runtime/lock"
  find "$runtime" -depth -type d -empty -delete 2>/dev/null
  rmdir "$pin_parent" 2>/dev/null
}
record_failure() {
  printf 'DIAGNOSTIC_FAIL line=%s status=%s\n' "$1" "$2" > "$evidence/verdict.txt"
}
trap 'record_failure "$LINENO" "$?"' ERR
trap cleanup EXIT

sha256sum "$binary" > "$evidence/binary-sha256.txt"
{
  uname -a
  bpftool version
  systemd --version | head -1
} > "$evidence/environment.txt"
bpftool -j prog show > "$evidence/baseline-programs.json"
bpftool -j link show > "$evidence/baseline-links.json"
bpftool -j map show > "$evidence/baseline-maps.json"

(
  for _ in $(seq 1 400); do
    now=$(date -u +%FT%TZ)
    if [[ -f "$state" ]]; then
      phase=$(jq -r '.phase // "INVALID"' "$state" 2>/dev/null || printf INVALID)
    else
      phase=ABSENT
    fi
    listening=false
    if ss -H -ltn '( sport = :18091 )' | grep -q .; then listening=true; fi
    printf '{"time":"%s","phase":"%s","ingress_listening":%s}\n' \
      "$now" "$phase" "$listening"
    if [[ "$phase" == READY && "$listening" == true ]]; then exit 0; fi
    sleep 0.025
  done
  exit 1
) > "$evidence/positive/ready-observer.jsonl" &
observer=$!

started=$(date -u +%FT%TZ)
systemd-run --unit="$unit" --property=Delegate=yes --property=Type=simple \
  "$binary" run -f "$config" > "$evidence/positive/systemd-run.txt"
ready=false
for _ in $(seq 1 400); do
  if journalctl -u "$unit.service" --since "$started" --no-pager | grep -q 'startup.ready'; then
    ready=true
    break
  fi
  if ! systemctl is-active --quiet "$unit.service"; then break; fi
  sleep 0.05
done
wait "$observer" || true
journalctl -u "$unit.service" --since "$started" --no-pager \
  > "$evidence/positive/journal.txt"
systemctl status "$unit.service" --no-pager > "$evidence/positive/status.txt" || true
if [[ "$ready" != true ]]; then
  printf '%s\n' FAIL > "$evidence/verdict.txt"
  printf '%s\n' 'startup did not reach READY' > "$evidence/failure.txt"
  cat "$evidence/positive/journal.txt"
  exit 10
fi

cp "$state" "$evidence/positive/state-ready.json"
bpftool -j cgroup show "$executions" > "$evidence/positive/direct.json"
bpftool -j cgroup show "$executions" effective > "$evidence/positive/effective.json"
{
  systemctl show "$unit.service" --property=Delegate --property=ControlGroup
  stat -c 'delegated_root path=%n inode=%i uid=%u gid=%g mode=%a' "$cgroup"
  stat -c 'executions path=%n inode=%i uid=%u gid=%g mode=%a' "$executions"
  printf 'delegated_root.cgroup.procs='; tr '\n' ' ' < "$cgroup/cgroup.procs"; printf '\n'
  printf 'executions.cgroup.procs='; tr '\n' ' ' < "$executions/cgroup.procs"; printf '\n'
  printf 'delegated_root.controllers='; cat "$cgroup/cgroup.controllers"
  printf 'delegated_root.subtree_control='; cat "$cgroup/cgroup.subtree_control"
  printf 'executions.controllers='; cat "$executions/cgroup.controllers"
  printf 'executions.subtree_control='; cat "$executions/cgroup.subtree_control"
} > "$evidence/positive/delegation.txt"
grep -Fx 'Delegate=yes' "$evidence/positive/delegation.txt" >/dev/null
grep -Fx 'delegated_root.cgroup.procs=' "$evidence/positive/delegation.txt" >/dev/null
grep -Fx 'executions.cgroup.procs=' "$evidence/positive/delegation.txt" >/dev/null
jq -e \
  '.phase == "READY" and (.programs|length)==6 and (.links|length)==6 and (.maps|length)==7' \
  "$evidence/positive/state-ready.json" >/dev/null
jq -e 'length == 6 and all(.[]; .attach_flags == "multi")' \
  "$evidence/positive/direct.json" >/dev/null
jq -e '[.[] | select(.name | startswith("soglia_"))] | length == 6' \
  "$evidence/positive/effective.json" >/dev/null
jq -s -e \
  'all(.[]; (.phase != "INTENT") or (.ingress_listening == false)) and any(.[]; .phase == "READY" and .ingress_listening == true)' \
  "$evidence/positive/ready-observer.jsonl" >/dev/null

systemctl stop "$unit.service"
systemctl reset-failed "$unit.service" || true
for _ in $(seq 1 200); do
  [[ ! -e "$cgroup" ]] && break
  sleep 0.025
done

while IFS= read -r pin; do
  if [[ -e "$pin" ]]; then rm "$pin"; fi
done < <(jq -r '.links[].pin, .maps[].pin' "$state")
owned_root=$(jq -r .pin_root "$state")
rmdir "$owned_root/links" "$owned_root/maps" "$owned_root"
rm -f "$state" "$runtime/cgroup-bpf/.state.json.tmp"
rmdir "$runtime/cgroup-bpf" 2>/dev/null || true
if [[ $(jq -r .dummy "$runtime/net/host.json") != soglia0 ]] \
  || [[ $(jq -r .proxy_address "$runtime/net/host.json") != 10.200.255.1 ]]; then
  printf '%s\n' 'host network record does not match the B1-owned resource' >&2
  exit 13
fi
nft delete table inet soglia_host
ip link delete soglia0
rm "$runtime/net/host.json" "$runtime/lock"
find "$runtime" -depth -type d -empty -delete 2>/dev/null || true
rmdir "$pin_parent"

bpftool -j prog show > "$evidence/final/programs.json"
bpftool -j link show > "$evidence/final/links.json"
bpftool -j map show > "$evidence/final/maps.json"
if jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
  "$evidence/final/programs.json" >/dev/null; then exit 11; fi
if jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
  "$evidence/final/maps.json" >/dev/null; then exit 12; fi
[[ ! -e "$runtime" ]]
[[ ! -e "$pin_parent" ]]
[[ ! -e "$cgroup" ]]
[[ ! -e /sys/class/net/soglia0 ]]
if nft list table inet soglia_host >/dev/null 2>&1; then exit 14; fi
printf '%s\n' PASS > "$evidence/final/cleanup-verdict.txt"
printf '%s\n' PASS > "$evidence/verdict.txt"
trap - ERR EXIT

printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
cat "$evidence/positive/journal.txt"
