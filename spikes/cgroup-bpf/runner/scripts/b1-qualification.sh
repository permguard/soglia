#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Reproducible B1 qualification for the exact production backend and production BPF object.

set -euo pipefail

binary="${1:?usage: b1-qualification.sh <soglia> [--authoritative]}"
authoritative=false
if [[ "${2:-}" == --authoritative ]]; then authoritative=true; fi
run_id="b1-$(date -u +%Y%m%dT%H%M%SZ)-$$"
evidence="/soglia/spikes/cgroup-bpf/evidence/replay/$run_id"
scripts=/soglia/spikes/cgroup-bpf/runner/scripts
config="$evidence/positive-config.yaml"
current_phase=INITIALIZING
last_case=none

mkdir -p "$evidence/cases" "$evidence/commands" "$evidence/final"

persist_state() {
  jq -n \
    --arg run_id "$run_id" \
    --arg phase "$current_phase" \
    --arg last_case "$last_case" \
    --argjson authoritative "$authoritative" \
    '{schema:1, run_id:$run_id, gate:"B1", authoritative:$authoritative,
      current_phase:$phase, last_case:$last_case}' > "$evidence/state.json"
}

record_failure() {
  local line="$1" status="$2"
  current_phase=FAILED
  persist_state
  jq -n \
    --arg run_id "$run_id" \
    --arg last_case "$last_case" \
    --argjson authoritative "$authoritative" \
    --argjson line "$line" \
    --argjson status "$status" \
    '{schema:1,run_id:$run_id,gate:"B1",authoritative:$authoritative,
      verdict:"FAIL",failure:{last_case:$last_case,line:$line,status:$status},
      remaining_gates:{B2:"NOT_EXECUTED",B3:"NOT_EXECUTED",B4:"NOT_EXECUTED",
        B5:"NOT_EXECUTED",B6:"NOT_EXECUTED",B7:"NOT_EXECUTED"}}' \
    > "$evidence/summary.json"
  printf '%s\n' FAIL > "$evidence/verdict.txt"
}
trap 'record_failure "$LINENO" "$?"' ERR

printf '%s\n' RUNNING > "$evidence/verdict.txt"
persist_state
jq -n --arg run_id "$run_id" --argjson authoritative "$authoritative" \
  '{schema:1,run_id:$run_id,gate:"B1",authoritative:$authoritative,
    started_at:(now|todateiso8601)}' > "$evidence/run.json"

{
  date -u +%FT%T.%NZ
  uname -a
  cat /etc/os-release
  systemd --version | head -1
  bpftool version
  nft --version
  ip -V
  runc --version
  /root/.cargo/bin/rustc +1.97.0 --version --verbose
  mount
  cat /proc/self/cgroup
  ulimit -a
} > "$evidence/environment.txt"

{
  git -C /soglia rev-parse HEAD
  git -C /soglia status --short
  git -C /soglia diff --stat
  git -C /soglia diff --binary -- . ':!spikes/cgroup-bpf/evidence' | sha256sum
  cd /soglia
  find Cargo.toml Cargo.lock src crates \
    -type f \( -name '*.rs' -o -name '*.c' -o -name '*.h' -o -name 'Cargo.toml' \
      -o -name 'Cargo.lock' -o -name 'build.rs' \) -print0 \
    | sort -z | xargs -0 sha256sum
  sha256sum spikes/cgroup-bpf/PRODUCTION-DESIGN.md
} > "$evidence/source-fingerprint.txt"
sha256sum "$binary" > "$evidence/binary-sha256.txt"
bpftool -j prog show > "$evidence/baseline-programs.json"
bpftool -j link show > "$evidence/baseline-links.json"
bpftool -j map show > "$evidence/baseline-maps.json"

cat > "$config" <<'YAML'
runtime:
  uid: 65534
  gid: 65534
  state_dir: /run/soglia-b1
  max_concurrency: 4
  max_queue: 4
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 5000
  runc: /usr/sbin/runc
  nft: /usr/sbin/nft
  ip: /usr/sbin/ip
  bpftool: /usr/sbin/bpftool
ingress:
  listen: 127.0.0.1:18091
network:
  backend: cgroup-bpf
  execution_pool: 10.201.0.0/24
  proxy_address: 10.200.255.1
  proxy_port: 15001
cgroup:
  root: /sys/fs/cgroup/system.slice/soglia-b1.service
cgroup_bpf:
  max_tracked_sockets: 4096
  resolve_timeout_ms: 2000
  ring_buffer_bytes: 65536
  pin_root: /sys/fs/bpf/soglia-b1
agents:
  probe:
    rootfs: /var/empty
    command: ["/bin/false"]
YAML

run_case() {
  local name="$1" script="$2"
  shift 2
  last_case="$name"
  current_phase="CASE_${name^^}"
  persist_state
  set +e
  bash "$script" "$@" > "$evidence/commands/$name.txt" 2>&1
  local status=$?
  set -e
  local source
  source=$(sed -n 's/^EVIDENCE=//p' "$evidence/commands/$name.txt" | tail -1)
  if [[ -n "$source" && -d "$source" ]]; then
    mkdir -p "$evidence/cases/$name"
    cp -a "$source/." "$evidence/cases/$name/"
  fi
  if [[ "$status" != 0 ]]; then
    printf 'case=%s status=%s source=%s\n' "$name" "$status" "$source" \
      > "$evidence/failure.txt"
    return "$status"
  fi
  [[ -n "$source" ]]
  grep -Fx PASS "$evidence/cases/$name/verdict.txt" >/dev/null
  if [[ -f "$evidence/cases/$name/cleanup-verdict.txt" ]]; then
    grep -Fx PASS "$evidence/cases/$name/cleanup-verdict.txt" >/dev/null
  fi
  if [[ -f "$evidence/cases/$name/final/cleanup-verdict.txt" ]]; then
    grep -Fx PASS "$evidence/cases/$name/final/cleanup-verdict.txt" >/dev/null
  fi
}

run_case positive "$scripts/b1-production-smoke.sh" "$binary" "$config"
run_case exclusive_ancestor "$scripts/b1-production-exclusive.sh" "$binary"
run_case synchronous_rollback "$scripts/b1-production-sync-rollback.sh" "$binary"
run_case recovery "$scripts/b1-production-recovery.sh" "$binary"
run_case typed_refusals "$scripts/b1-production-refusals.sh" "$binary"

last_case=final_inventory
current_phase=CLEANUP_VERIFICATION
persist_state
bpftool -j prog show > "$evidence/final/programs.json"
bpftool -j link show > "$evidence/final/links.json"
bpftool -j map show > "$evidence/final/maps.json"

program_classification=$(jq -nr \
  --slurpfile before "$evidence/baseline-programs.json" \
  --slurpfile after "$evidence/final/programs.json" '
  def inventory($xs):
    $xs | map({id,name,type,tag}) | sort_by(.name,.type,.tag,.id);
  def signatures($xs):
    $xs | map({name,type,tag}) | sort_by(.name,.type,.tag);
  def non_systemd($xs):
    $xs | map(select((.name | startswith("sd_")) | not) | {id,name,type,tag})
        | sort_by(.name,.type,.tag,.id);
  if inventory($before[0]) == inventory($after[0]) then "MATCH"
  elif signatures($before[0]) == signatures($after[0])
    and non_systemd($before[0]) == non_systemd($after[0])
  then "EXTERNAL_CHURN"
  else "FAIL"
  end')
printf '%s\n' "$program_classification" > "$evidence/final/program-classification.txt"
[[ "$program_classification" == MATCH || "$program_classification" == EXTERNAL_CHURN ]]

jq -S 'sort_by(.id)' "$evidence/baseline-links.json" > "$evidence/final/links-before.normalized.json"
jq -S 'sort_by(.id)' "$evidence/final/links.json" > "$evidence/final/links-after.normalized.json"
cmp "$evidence/final/links-before.normalized.json" "$evidence/final/links-after.normalized.json"
jq -S 'sort_by(.id)' "$evidence/baseline-maps.json" > "$evidence/final/maps-before.normalized.json"
jq -S 'sort_by(.id)' "$evidence/final/maps.json" > "$evidence/final/maps-after.normalized.json"
cmp "$evidence/final/maps-before.normalized.json" "$evidence/final/maps-after.normalized.json"

if jq -e 'any(.[]; ((.name // "") | startswith("soglia_") or startswith("foreign_")))' \
  "$evidence/final/programs.json" >/dev/null; then exit 50; fi
if jq -e 'any(.[]; (.name // "") | startswith("soglia_"))' \
  "$evidence/final/maps.json" >/dev/null; then exit 51; fi
for path in /run/soglia-b1 /sys/fs/bpf/soglia-b1; do [[ ! -e "$path" ]]; done
if ip link show soglia0 >/dev/null 2>&1; then exit 52; fi
if nft list table inet soglia_host >/dev/null 2>&1; then exit 53; fi
printf '%s\n' PASS > "$evidence/final/cleanup-verdict.txt"

current_phase=COMPLETE
last_case=complete
persist_state
jq -n \
  --arg run_id "$run_id" \
  --argjson authoritative "$authoritative" \
  --arg inventory "$program_classification" \
  '{schema:1,run_id:$run_id,gate:"B1",authoritative:$authoritative,verdict:"PASS",
    qualified:{production_backend:true,production_bpf_object:true,true_effective_inventory:true,
      attach_plan:"six Aya Single links (kernel reports multi)",ready_last:true,
      actual_delegation:true,typed_exclusive_ancestor_refusal:true,
      synchronous_error_rollback:true,crash_recovery:true,
      missing_delegation_refusal:true,missing_dependency_refusal:true,
      unexpected_direct_attachment_refusal:true,unknown_state_preserved:true},
    cleanup:{verdict:"PASS",program_inventory:$inventory,links:"MATCH",maps:"MATCH",
      owned_resources_absent:true},
    scope:{supported_platform:"the exact recorded environment fingerprint",
      missing_kernel_feature_simulation:"NOT_PERFORMED: production object was never modified"},
    remaining_gates:{B2:"NOT_EXECUTED",B3:"NOT_EXECUTED",B4:"NOT_EXECUTED",
      B5:"NOT_EXECUTED",B6:"NOT_EXECUTED",B7:"NOT_EXECUTED"}}' \
  > "$evidence/summary.json"
printf '%s\n' PASS > "$evidence/verdict.txt"
(
  cd "$evidence"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS
)
trap - ERR

printf 'RUN_ID=%s\nEVIDENCE=%s\n' "$run_id" "$evidence"
cat "$evidence/summary.json"
