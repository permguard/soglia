#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Diagnostic-only B1 negative: introduce an exclusive direct program after the disposable probe
# has passed. Production initialization must then roll back the already-published INTENT exactly.

set -euo pipefail

binary="${1:?usage: b1-production-sync-rollback.sh <soglia>}"
run_id="b1-diagnostic-sync-rollback-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
unit="soglia-b1-sync-rollback"
cgroup="/sys/fs/cgroup/system.slice/$unit.service"
executions="$cgroup/executions"
runtime="/run/soglia-b1-sync-rollback"
pin_parent="/sys/fs/bpf/soglia-b1-sync-rollback"
foreign_root="/sys/fs/bpf/$run_id-foreign"
foreign_build="/var/tmp/$run_id-bpf"
config="$evidence/config.yaml"
watcher=""

mkdir -p "$evidence" "$foreign_build"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

cleanup() {
  set +e
  if [[ -n "$watcher" ]]; then kill "$watcher" 2>/dev/null; wait "$watcher" 2>/dev/null; fi
  systemctl stop "$unit.service" >/dev/null 2>&1
  systemctl reset-failed "$unit.service" >/dev/null 2>&1
  if [[ -d "$foreign_root" ]]; then
    find "$foreign_root" -type f -delete 2>/dev/null
    rmdir "$foreign_root" 2>/dev/null
  fi
  rm -f "$runtime/lock"
  find "$runtime" -depth -type d -empty -delete 2>/dev/null
  rmdir "$pin_parent" 2>/dev/null
  rm -rf "$foreign_build"
}
record_failure() {
  printf 'DIAGNOSTIC_FAIL line=%s status=%s\n' "$1" "$2" > "$evidence/verdict.txt"
}
trap 'record_failure "$LINENO" "$?"' ERR
trap cleanup EXIT

cat > "$config" <<'YAML'
runtime:
  uid: 65534
  gid: 65534
  state_dir: /run/soglia-b1-sync-rollback
  max_concurrency: 4
  max_queue: 4
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 5000
  runc: /usr/sbin/runc
  nft: /usr/sbin/nft
  ip: /usr/sbin/ip
  bpftool: /usr/sbin/bpftool
ingress:
  listen: 127.0.0.1:18093
network:
  backend: cgroup-bpf
  execution_pool: 10.203.0.0/24
  proxy_address: 10.200.255.3
  proxy_port: 15003
cgroup:
  root: /sys/fs/cgroup/system.slice/soglia-b1-sync-rollback.service
cgroup_bpf:
  max_tracked_sockets: 4096
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: /sys/fs/bpf/soglia-b1-sync-rollback
agents:
  probe:
    rootfs: /var/empty
    command: ["/bin/false"]
YAML

sha256sum "$binary" > "$evidence/binary-sha256.txt"
/soglia/spikes/cgroup-bpf/build.sh "$foreign_build" > "$evidence/build-foreign.txt"
mkdir "$foreign_root"
bpftool prog loadall "$foreign_build/foreign.o" "$foreign_root"
bpftool -j prog show > "$evidence/baseline-programs.json"
bpftool -j link show > "$evidence/baseline-links.json"
bpftool -j map show > "$evidence/baseline-maps.json"

(
  seen=0
  for _ in $(seq 1 200000); do
    if [[ -d "$executions" ]]; then
      probe_present=0
      for path in "$executions"/.soglia-attach-probe-*; do
        if [[ -e "$path" ]]; then probe_present=1; break; fi
      done
      if [[ "$probe_present" == 1 ]]; then
        seen=1
      elif [[ "$seen" == 1 ]]; then
        bpftool cgroup attach "$executions" cgroup_inet4_connect \
          pinned "$foreign_root/foreign_allow"
        printf '%s\n' ATTACHED_AFTER_PROBE
        exit 0
      fi
    fi
  done
  printf '%s\n' MISSED_WINDOW
  exit 30
) > "$evidence/watcher.txt" 2>&1 &
watcher=$!

started=$(date -u +%FT%TZ)
systemd-run --unit="$unit" --property=Delegate=yes --property=Type=simple \
  "$binary" run -f "$config" > "$evidence/systemd-run.txt"
for _ in $(seq 1 800); do
  if ! systemctl is-active --quiet "$unit.service"; then break; fi
  sleep 0.025
done
wait "$watcher"
watcher=""
journalctl -u "$unit.service" --since "$started" --no-pager > "$evidence/journal.txt"
systemctl status "$unit.service" --no-pager > "$evidence/status.txt" || true

grep -F ATTACHED_AFTER_PROBE "$evidence/watcher.txt" >/dev/null
grep -F 'event.name=cgroup_bpf.generation_rollback result=PASS generation=1' \
  "$evidence/journal.txt" > "$evidence/generation-rollback.txt"
grep -F 'INCOMPATIBLE_BPF_TOPOLOGY hook=soglia_connect4 errno=Some(1)' \
  "$evidence/journal.txt" > "$evidence/typed-refusal.txt"
[[ ! -e "$runtime/cgroup-bpf/state.json" ]]
[[ ! -e "$runtime/cgroup-bpf" ]]
[[ ! -e "$pin_parent" ]]
[[ ! -e /sys/class/net/soglia0 ]]
if nft list table inet soglia_host >/dev/null 2>&1; then exit 31; fi
if ss -H -ltn '( sport = :18093 )' | grep -q .; then exit 32; fi
if bpftool -j prog show | jq -e \
  'any(.[]; (.name // "") | startswith("soglia_"))' >/dev/null; then exit 33; fi
if bpftool -j map show | jq -e \
  'any(.[]; (.name // "") | startswith("soglia_"))' >/dev/null; then exit 34; fi
printf '%s\n' PASS > "$evidence/synchronous-rollback.txt"

systemctl stop "$unit.service" >/dev/null 2>&1 || true
systemctl reset-failed "$unit.service" || true
rm "$foreign_root/foreign_allow" "$foreign_root/foreign_rewrite"
rmdir "$foreign_root"
rm -f "$runtime/lock"
find "$runtime" -depth -type d -empty -delete 2>/dev/null || true
rm -rf "$foreign_build"

bpftool -j prog show > "$evidence/final-programs.json"
bpftool -j link show > "$evidence/final-links.json"
bpftool -j map show > "$evidence/final-maps.json"
if jq -e 'any(.[]; ((.name // "") | startswith("soglia_") or startswith("foreign_")))' \
  "$evidence/final-programs.json" >/dev/null; then exit 35; fi
[[ ! -e "$cgroup" ]]
[[ ! -e "$runtime" ]]
[[ ! -e "$pin_parent" ]]
printf '%s\n' PASS > "$evidence/cleanup-verdict.txt"
printf '%s\n' PASS > "$evidence/verdict.txt"
trap - ERR EXIT

printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
cat "$evidence/generation-rollback.txt"
