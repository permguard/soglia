#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Produces the read-only S6 enforcement-layer synthesis provenance and clean-state proof.

set -euo pipefail

evidence="${S6_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s6}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service

for output in s6-preflight.txt s6-baseline-prog.json s6-baseline-link.json s6-baseline-map.json s6-baseline-bpffs.txt s6-evidence-index.txt s6-final-prog.json s6-final-link.json s6-final-map.json s6-final-bpffs.txt s6-cleanup.txt s6-summary.txt; do
    if [[ -e "$evidence/$output" ]]; then
        echo "refusing to overwrite $evidence/$output" >&2
        exit 1
    fi
done

{
    echo "# S6 read-only preflight"
    date -u +"UTC=%FT%TZ"
    uname -a
    systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID -p Delegate -p DelegateControllers -p ControlGroup -p NRestarts --no-pager
    echo "delegated_root_inode=$(stat -c %i "$unit")"
    echo "delegated_root_children_begin"
    find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
    echo "delegated_root_children_end"
    bpftool cgroup tree "$unit"
    echo "bpffs_begin"
    find /sys/fs/bpf -mindepth 1 -maxdepth 5 -print | sort
    echo "bpffs_end"
    ip netns list
    ip -o link show | grep -E 'sgh-|soglia-proxy' || true
    nft list tables | grep soglia || true
} > "$evidence/s6-preflight.txt"
bpftool -j prog show > "$evidence/s6-baseline-prog.json"
bpftool -j link show > "$evidence/s6-baseline-link.json"
bpftool -j map show > "$evidence/s6-baseline-map.json"
find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s6-baseline-bpffs.txt"

sha256sum \
    /soglia/spikes/cgroup-bpf/evidence/s1/port-fixed/s1-harness.txt \
    /soglia/spikes/cgroup-bpf/evidence/s1b/race/s1-harness.txt \
    /soglia/spikes/cgroup-bpf/evidence/s2/run2/s2-harness.txt \
    /soglia/spikes/cgroup-bpf/evidence/s3/s3-summary.txt \
    /soglia/spikes/cgroup-bpf/evidence/s4/run2/s4-harness.txt \
    /soglia/spikes/cgroup-bpf/evidence/s4/run2/s4-nft-before.json \
    /soglia/spikes/cgroup-bpf/evidence/s4/run2/s4-nft-after.json \
    /soglia/spikes/cgroup-bpf/evidence/s5/run3/s5-harness.txt \
    "$evidence/s6-enforcement-layer-table.md" \
    > "$evidence/s6-evidence-index.txt"

bpftool -j prog show > "$evidence/s6-final-prog.json"
bpftool -j link show > "$evidence/s6-final-link.json"
bpftool -j map show > "$evidence/s6-final-map.json"
find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s6-final-bpffs.txt"

{
    echo "# S6 read-only cleanup/non-mutation proof"
    date -u +"UTC=%FT%TZ"
    echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
    echo "delegated_root_children_begin"
    find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
    echo "delegated_root_children_end"
    echo "soglia_foreign_program_count=$(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_") or startswith("foreign_"))] | length')"
    echo "cgroup_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
    echo "program_baseline_equal=$(cmp -s "$evidence/s6-baseline-prog.json" "$evidence/s6-final-prog.json" && echo true || echo false)"
    echo "link_baseline_equal=$(cmp -s "$evidence/s6-baseline-link.json" "$evidence/s6-final-link.json" && echo true || echo false)"
    echo "map_baseline_equal=$(cmp -s "$evidence/s6-baseline-map.json" "$evidence/s6-final-map.json" && echo true || echo false)"
    echo "bpffs_baseline_equal=$(cmp -s "$evidence/s6-baseline-bpffs.txt" "$evidence/s6-final-bpffs.txt" && echo true || echo false)"
} > "$evidence/s6-cleanup.txt"

grep -Fxq 'runtime' <(find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)
[[ $(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_") or startswith("foreign_"))] | length') -eq 0 ]]
[[ $(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length') -eq 0 ]]
cmp -s "$evidence/s6-baseline-prog.json" "$evidence/s6-final-prog.json"
cmp -s "$evidence/s6-baseline-link.json" "$evidence/s6-final-link.json"
cmp -s "$evidence/s6-baseline-map.json" "$evidence/s6-final-map.json"
cmp -s "$evidence/s6-baseline-bpffs.txt" "$evidence/s6-final-bpffs.txt"

{
    echo "# S6 result"
    date -u +"UTC=%FT%TZ"
    echo "hypothesis=actual enforcement for S1-S5 properties can be assigned to observed layers without converting intended architecture into evidence"
    echo "table=s6-enforcement-layer-table.md"
    echo "runtime_mutations=0"
    echo "candidate_selected=false"
    echo "production_code_modified=false"
    echo "S6_RESULT=PASS"
} > "$evidence/s6-summary.txt"
