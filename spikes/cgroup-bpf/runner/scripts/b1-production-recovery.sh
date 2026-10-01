#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Diagnostic-only B1 recovery: a second production process recovers the pinned generation while
# the delegated root and its executions inode remain stable.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
# shellcheck source=spikes/cgroup-bpf/runner/scripts/systemd-cgroup-common.sh
source "$scripts/systemd-cgroup-common.sh"

binary="${1:?usage: b1-production-recovery.sh <soglia>}"
run_id="b1-diagnostic-recovery-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
unit="soglia-b1-recovery"
cgroup="/sys/fs/cgroup/system.slice/$unit.service"
executions="$cgroup/executions"
runtime="/run/soglia-b1-recovery"
control="/run/$run_id-control"
pin_parent="/sys/fs/bpf/soglia-b1-recovery"
state="$runtime/cgroup-bpf/state.json"
config="$evidence/config.yaml"

mkdir -p "$evidence/cycle-1" "$evidence/cycle-2" "$evidence/final" "$control"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

cleanup() {
  set +e
  touch "$control/stop" 2>/dev/null
  stop_and_prune_unit_cgroup "$unit" "$evidence/abort-unit-stop" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  if [[ -f "$state" ]] && jq -e '.pin_root and .links and .maps' "$state" >/dev/null 2>&1; then
    while IFS= read -r pin; do if [[ -e "$pin" ]]; then rm "$pin"; fi; done \
      < <(jq -r '.links[].pin, .maps[].pin' "$state")
    owned_root=$(jq -r .pin_root "$state")
    rmdir "$owned_root/links" "$owned_root/maps" "$owned_root" 2>/dev/null
  fi
  rm -f "$state" "$runtime/cgroup-bpf/.state.json.tmp"
  if [[ -f "$runtime/net/host.json" ]] \
    && [[ $(jq -r .dummy "$runtime/net/host.json" 2>/dev/null) == soglia0 ]]; then
    nft delete table inet soglia_host >/dev/null 2>&1
    ip link delete soglia0 >/dev/null 2>&1
    rm -f "$runtime/net/host.json"
  fi
  rm -f "$runtime/lock"
  find "$runtime" -depth -type d -empty -delete 2>/dev/null
  rmdir "$pin_parent" 2>/dev/null
  rm -rf "$control"
}
record_failure() {
  local line="$1"
  local status="$2"
  for cycle in 1 2; do
    if [[ -f "$control/cycle-$cycle.log" ]]; then
      cp "$control/cycle-$cycle.log" "$evidence/cycle-$cycle/process-failure.log"
    fi
    if [[ -f "$control/cycle-$cycle.exit" ]]; then
      cp "$control/cycle-$cycle.exit" "$evidence/cycle-$cycle/process-exit.txt"
    fi
  done
  printf 'DIAGNOSTIC_FAIL line=%s status=%s\n' "$line" "$status" > "$evidence/verdict.txt"
}
trap 'record_failure "$LINENO" "$?"' ERR
trap cleanup EXIT

cat > "$config" <<'YAML'
runtime:
  uid: 65534
  gid: 65534
  state_dir: /run/soglia-b1-recovery
  max_concurrency: 4
  max_queue: 4
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 5000
  runc: /usr/sbin/runc
  nft: /usr/sbin/nft
  ip: /usr/sbin/ip
  bpftool: /usr/sbin/bpftool
ingress:
  listen: 127.0.0.1:18094
network:
  backend: cgroup-bpf
  execution_pool: 10.204.0.0/24
  proxy_address: 10.200.255.4
  proxy_port: 15004
cgroup:
  root: /sys/fs/cgroup/system.slice/soglia-b1-recovery.service
cgroup_bpf:
  max_tracked_sockets: 4096
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: /sys/fs/bpf/soglia-b1-recovery
agents:
  probe:
    rootfs: /var/empty
    command: ["/bin/false"]
YAML

sha256sum "$binary" > "$evidence/binary-sha256.txt"
bpftool -j prog show > "$evidence/baseline-programs.json"
bpftool -j link show > "$evidence/baseline-links.json"
bpftool -j map show > "$evidence/baseline-maps.json"

systemd-run --unit="$unit" --property=Delegate=yes --property=Type=simple \
  /usr/bin/bash /soglia/spikes/cgroup-bpf/runner/scripts/b1-service-loop.sh \
  "$binary" "$config" "$control" > "$evidence/systemd-run.txt"

wait_cycle_ready() {
  local cycle="$1"
  local output="$2"
  for _ in $(seq 1 800); do
    if [[ -f "$state" ]] \
      && [[ $(jq -r '.phase // ""' "$state" 2>/dev/null) == READY ]] \
      && ss -H -ltn '( sport = :18094 )' | grep -q .; then
      cp "$state" "$output/state-ready.json"
      bpftool -j cgroup show "$executions" > "$output/direct.json"
      bpftool -j cgroup show "$executions" effective > "$output/effective.json"
      stat -c '%i' "$executions" > "$output/executions-inode.txt"
      return 0
    fi
    if [[ -e "$control/cycle-$cycle.exit" ]]; then return 1; fi
    sleep 0.025
  done
  return 1
}

wait_cycle_ready 1 "$evidence/cycle-1"
jq -e '.phase == "READY" and .generation == 1' "$evidence/cycle-1/state-ready.json" >/dev/null
jq -e 'length == 6 and all(.[]; .attach_flags == "multi")' \
  "$evidence/cycle-1/direct.json" >/dev/null
jq -e '[.[] | select(.name | startswith("soglia_"))] | length == 6' \
  "$evidence/cycle-1/effective.json" >/dev/null
cycle_one_pid=$(cat "$control/cycle-1.pid")
kill -KILL "$cycle_one_pid"
for _ in $(seq 1 400); do
  [[ -e "$control/cycle-1.exit" ]] && break
  sleep 0.025
done
[[ $(cat "$control/cycle-1.exit") == 137 ]]
cp "$state" "$evidence/cycle-1/state-after-exit.json"
bpftool -j cgroup show "$executions" > "$evidence/cycle-1/direct-after-exit.json"
jq -e '.phase == "READY" and .generation == 1' \
  "$evidence/cycle-1/state-after-exit.json" >/dev/null
jq -e 'length == 6' "$evidence/cycle-1/direct-after-exit.json" >/dev/null

touch "$control/next"
wait_cycle_ready 2 "$evidence/cycle-2"
jq -e '.phase == "READY" and .generation == 2' "$evidence/cycle-2/state-ready.json" >/dev/null
cmp "$evidence/cycle-1/executions-inode.txt" "$evidence/cycle-2/executions-inode.txt"
jq -e 'length == 6 and all(.[]; .attach_flags == "multi")' \
  "$evidence/cycle-2/direct.json" >/dev/null
jq -e '[.[] | select(.name | startswith("soglia_"))] | length == 6' \
  "$evidence/cycle-2/effective.json" >/dev/null
cp "$control/cycle-1.log" "$evidence/cycle-1/process.log"
cp "$control/cycle-2.log" "$evidence/cycle-2/process.log"
grep -F 'event.name=cgroup_bpf.attach_probe result=PASS' "$evidence/cycle-2/process.log" \
  > "$evidence/cycle-2/probe.txt"
grep -F 'event.name=cgroup_bpf.ready generation=2' "$evidence/cycle-2/process.log" \
  > "$evidence/cycle-2/ready.txt"

cycle_two_pid=$(cat "$control/cycle-2.pid")
kill -KILL "$cycle_two_pid"
for _ in $(seq 1 400); do
  [[ -e "$control/cycle-2.exit" ]] && break
  sleep 0.025
done
[[ $(cat "$control/cycle-2.exit") == 137 ]]
touch "$control/stop"
stop_and_prune_unit_cgroup "$unit" "$evidence/unit-stop"
systemctl reset-failed "$unit.service" || true

while IFS= read -r pin; do if [[ -e "$pin" ]]; then rm "$pin"; fi; done \
  < <(jq -r '.links[].pin, .maps[].pin' "$state")
owned_root=$(jq -r .pin_root "$state")
rmdir "$owned_root/links" "$owned_root/maps" "$owned_root"
rm "$state"
rmdir "$runtime/cgroup-bpf"
if [[ $(jq -r .dummy "$runtime/net/host.json") != soglia0 ]]; then exit 40; fi
nft delete table inet soglia_host
ip link delete soglia0
rm "$runtime/net/host.json" "$runtime/lock"
find "$runtime" -depth -type d -empty -delete
rmdir "$pin_parent"
rm -rf "$control"

bpftool -j prog show > "$evidence/final/programs.json"
bpftool -j link show > "$evidence/final/links.json"
bpftool -j map show > "$evidence/final/maps.json"
if jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
  "$evidence/final/programs.json" >/dev/null; then exit 41; fi
if jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
  "$evidence/final/maps.json" >/dev/null; then exit 42; fi
[[ ! -e "$cgroup" ]]
[[ ! -e "$runtime" ]]
[[ ! -e "$pin_parent" ]]
printf '%s\n' PASS > "$evidence/cleanup-verdict.txt"
printf '%s\n' PASS > "$evidence/verdict.txt"
trap - ERR EXIT

printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
cat "$evidence/cycle-2/ready.txt"
