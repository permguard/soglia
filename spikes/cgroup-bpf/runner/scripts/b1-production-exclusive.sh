#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Diagnostic-only B1 negative: an exclusive legacy program on the ancestor must be a typed refusal
# before a new durable INTENT, with synchronous rollback of every startup resource.

set -euo pipefail

scripts=/soglia/spikes/cgroup-bpf/runner/scripts
# shellcheck source=spikes/cgroup-bpf/runner/scripts/systemd-cgroup-common.sh
source "$scripts/systemd-cgroup-common.sh"

binary="${1:?usage: b1-production-exclusive.sh <soglia>}"
run_id="b1-diagnostic-exclusive-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
root_unit="soglia-b1-exclusive-root"
app_unit="soglia-b1-exclusive-app"
root_cgroup="/sys/fs/cgroup/system.slice/$root_unit.service"
executions="$root_cgroup/executions"
runtime="/run/soglia-b1-exclusive"
pin_parent="/sys/fs/bpf/soglia-b1-exclusive"
foreign_root="/sys/fs/bpf/$run_id-foreign"
foreign_build="/var/tmp/$run_id-bpf"
config="$evidence/config.yaml"
foreign_attached=0

mkdir -p "$evidence" "$foreign_build"
printf '%s\n' RUNNING > "$evidence/verdict.txt"

cleanup() {
  set +e
  systemctl stop "$app_unit.service" >/dev/null 2>&1
  if [[ "$foreign_attached" == 1 ]]; then
    bpftool cgroup detach "$root_cgroup" cgroup_inet4_connect \
      pinned "$foreign_root/foreign_allow" >/dev/null 2>&1
  fi
  if [[ -d "$foreign_root" ]]; then
    find "$foreign_root" -type f -delete 2>/dev/null
    rmdir "$foreign_root" 2>/dev/null
  fi
  stop_and_prune_unit_cgroup "$root_unit" "$evidence/abort-root-unit-stop" >/dev/null 2>&1
  systemctl reset-failed "$app_unit.service" "$root_unit.service" >/dev/null 2>&1
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
  state_dir: /run/soglia-b1-exclusive
  max_concurrency: 4
  max_queue: 4
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 5000
  runc: /usr/sbin/runc
  nft: /usr/sbin/nft
  ip: /usr/sbin/ip
  bpftool: /usr/sbin/bpftool
ingress:
  listen: 127.0.0.1:18092
network:
  backend: cgroup-bpf
  execution_pool: 10.202.0.0/24
  proxy_address: 10.200.255.2
  proxy_port: 15002
cgroup:
  root: /sys/fs/cgroup/system.slice/soglia-b1-exclusive-root.service
cgroup_bpf:
  max_tracked_sockets: 4096
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: /sys/fs/bpf/soglia-b1-exclusive
agents:
  probe:
    rootfs: /var/empty
    command: ["/bin/false"]
YAML

sha256sum "$binary" > "$evidence/binary-sha256.txt"
bpftool -j prog show > "$evidence/baseline-programs.json"
bpftool -j link show > "$evidence/baseline-links.json"
bpftool -j map show > "$evidence/baseline-maps.json"

systemd-run --unit="$root_unit" --property=Delegate=yes --property=Type=simple sleep infinity \
  > "$evidence/root-systemd-run.txt"
for _ in $(seq 1 200); do
  [[ -d "$root_cgroup" ]] && break
  sleep 0.025
done
mkdir "$executions"
/soglia/spikes/cgroup-bpf/build.sh "$foreign_build" > "$evidence/build-foreign.txt"
mkdir "$foreign_root"
bpftool prog loadall "$foreign_build/foreign.o" "$foreign_root"
bpftool cgroup attach "$root_cgroup" cgroup_inet4_connect \
  pinned "$foreign_root/foreign_allow"
foreign_attached=1
bpftool -j cgroup show "$root_cgroup" > "$evidence/ancestor-direct.json"

started=$(date -u +%FT%TZ)
systemd-run --unit="$app_unit" --property=Type=simple "$binary" run -f "$config" \
  > "$evidence/app-systemd-run.txt"
for _ in $(seq 1 400); do
  if ! systemctl is-active --quiet "$app_unit.service"; then break; fi
  sleep 0.025
done
journalctl -u "$app_unit.service" --since "$started" --no-pager > "$evidence/journal.txt"
systemctl status "$app_unit.service" --no-pager > "$evidence/status.txt" || true

grep -F 'INCOMPATIBLE_BPF_TOPOLOGY hook=soglia_connect4 errno=Some(1)' \
  "$evidence/journal.txt" > "$evidence/typed-refusal.txt"
[[ ! -e "$runtime/cgroup-bpf/state.json" ]]
[[ ! -e "$runtime/cgroup-bpf" ]]
[[ ! -e "$pin_parent" ]]
[[ ! -e /sys/class/net/soglia0 ]]
if nft list table inet soglia_host >/dev/null 2>&1; then exit 20; fi
if ss -H -ltn '( sport = :18092 )' | grep -q .; then exit 21; fi
if bpftool -j prog show | jq -e \
  'any(.[]; (.name // "") | startswith("soglia_"))' >/dev/null; then exit 22; fi
if bpftool -j map show | jq -e \
  'any(.[]; (.name // "") | startswith("soglia_"))' >/dev/null; then exit 23; fi
printf '%s\n' PASS > "$evidence/pre-intent-rollback.txt"

systemctl stop "$app_unit.service" >/dev/null 2>&1 || true
bpftool cgroup detach "$root_cgroup" cgroup_inet4_connect \
  pinned "$foreign_root/foreign_allow"
foreign_attached=0
rm "$foreign_root/foreign_allow" "$foreign_root/foreign_rewrite"
rmdir "$foreign_root"
stop_and_prune_unit_cgroup "$root_unit" "$evidence/root-unit-stop"
systemctl reset-failed "$app_unit.service" "$root_unit.service" || true
rm -f "$runtime/lock"
find "$runtime" -depth -type d -empty -delete 2>/dev/null || true
rm -rf "$foreign_build"

bpftool -j prog show > "$evidence/final-programs.json"
bpftool -j link show > "$evidence/final-links.json"
bpftool -j map show > "$evidence/final-maps.json"
if jq -e 'any(.[]; ((.name // "") | startswith("soglia_") or startswith("foreign_")))' \
  "$evidence/final-programs.json" >/dev/null; then exit 24; fi
[[ ! -e "$root_cgroup" ]]
[[ ! -e "$runtime" ]]
[[ ! -e "$pin_parent" ]]
printf '%s\n' PASS > "$evidence/cleanup-verdict.txt"
printf '%s\n' PASS > "$evidence/verdict.txt"
trap - ERR EXIT

printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
cat "$evidence/typed-refusal.txt"
