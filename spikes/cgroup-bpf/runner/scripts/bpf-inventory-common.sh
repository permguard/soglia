#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0

# Shared B1-B7 qualification inventory capture and strict external attribution.

BPF_INVENTORY_WATCHER_PID=
BPF_INVENTORY_WATCHER_MARKER=

bpf_inventory_pin_state() {
  local root=$1 output=$2
  if [[ -e "$root" ]]; then
    find "$root" -print0 | sort -z | jq -Rs 'split("\u0000") | map(select(length > 0))' \
      | jq --arg path "$root" '{path:$path,exists:true,entries:.}' > "$output"
  else
    jq -n --arg path "$root" '{path:$path,exists:false,entries:[]}' > "$output"
  fi
}

bpf_inventory_begin() {
  local evidence=$1 pin_root=$2
  bpftool -j prog show > "$evidence/baseline-programs.json"
  bpftool -j link show > "$evidence/baseline-links.json"
  bpftool -j map show > "$evidence/baseline-maps.json"
  bpftool -j cgroup tree /sys/fs/cgroup > "$evidence/baseline-cgroup-tree.json"
  bpf_inventory_pin_state "$pin_root" "$evidence/baseline-soglia-pins.json"
  printf '[]\n' > "$evidence/production-programs.json"
  BPF_INVENTORY_WATCHER_MARKER="$evidence/.production-program-watcher"
  : > "$BPF_INVENTORY_WATCHER_MARKER"
  (
    while [[ -e "$BPF_INVENTORY_WATCHER_MARKER" ]]; do
      local_snapshot="$evidence/.production-programs.$$.$RANDOM.json"
      local_merged="$local_snapshot.merged"
      if bpftool -j prog show \
        | jq '[.[] | select(((.name // "") | startswith("soglia_")))]' > "$local_snapshot"; then
        jq -s 'add | unique_by(.id) | sort_by(.name,.tag,.id)' \
          "$evidence/production-programs.json" "$local_snapshot" > "$local_merged"
        mv "$local_merged" "$evidence/production-programs.json"
      fi
      rm -f "$local_snapshot" "$local_merged"
      sleep 0.02
    done
  ) &
  BPF_INVENTORY_WATCHER_PID=$!
}

bpf_inventory_stop_watcher() {
  if [[ -n ${BPF_INVENTORY_WATCHER_MARKER:-} ]]; then
    rm -f "$BPF_INVENTORY_WATCHER_MARKER"
  fi
  if [[ -n ${BPF_INVENTORY_WATCHER_PID:-} ]]; then
    wait "$BPF_INVENTORY_WATCHER_PID" 2>/dev/null || true
  fi
  BPF_INVENTORY_WATCHER_PID=
  BPF_INVENTORY_WATCHER_MARKER=
}

bpf_inventory_classify_current() {
  local evidence=$1 pin_root=$2 cgroup_subtree=$3 classifier=$4
  bpf_inventory_stop_watcher
  bpftool -j prog show > "$evidence/final/programs.json"
  bpftool -j link show > "$evidence/final/links.json"
  bpftool -j cgroup tree /sys/fs/cgroup > "$evidence/final/cgroup-tree.json"
  bpf_inventory_pin_state "$pin_root" "$evidence/final/soglia-pins.json"
  python3 "$classifier" \
    --before-programs "$evidence/baseline-programs.json" \
    --after-programs "$evidence/final/programs.json" \
    --before-links "$evidence/baseline-links.json" \
    --after-links "$evidence/final/links.json" \
    --before-tree "$evidence/baseline-cgroup-tree.json" \
    --after-tree "$evidence/final/cgroup-tree.json" \
    --before-pins "$evidence/baseline-soglia-pins.json" \
    --after-pins "$evidence/final/soglia-pins.json" \
    --production-programs "$evidence/production-programs.json" \
    --cgroup-subtree "$cgroup_subtree" \
    > "$evidence/final/program-attribution.json"
  BPF_PROGRAM_CLASSIFICATION=$(jq -r .classification "$evidence/final/program-attribution.json")
}

bpf_inventory_is_clean() {
  case $1 in
    MATCH|EXTERNAL_CHURN|EXTERNAL_ADDITION|EXTERNAL_REMOVAL) return 0 ;;
    *) return 1 ;;
  esac
}
