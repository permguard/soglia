#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# S13 pinned-state compatibility/restart/ownership characterization.
#
# This runner deliberately does not define a metadata ABI.  It exercises the
# current spike loader and records whether the existing state can establish
# ownership/compatibility and prevent stale-map reuse.

set -euo pipefail

evidence="${S13_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s13/run1}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
old_cgroup="$executions/s13-old"
new_cgroup="$executions/s13-new"
foreign_cgroup="$executions/s13-foreign"
root=/sys/fs/bpf/soglia-spike/s13
shared_maps="$root/shared/maps"
old_links="$root/shared/old-links"
new_links="$root/shared/new-links"
foreign_maps="$root/foreign/maps"
foreign_links="$root/foreign/links"
foreign_pin="$foreign_maps/soglia-looking-foreign"
object=/var/tmp/spike/bpf/soglia-diag.o
loader=/var/tmp/spike/target/release/s7_pinned_loader
old_ready=/run/soglia-spike-s13-old.ready
new_ready=/run/soglia-spike-s13-new.ready
foreign_ready=/run/soglia-spike-s13-foreign.ready
old_pid=
new_pid=
foreign_pid=
foreign_id=

map_names=(
    soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events
    soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag
)
link_names=(sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops)

snapshot_bpffs() {
    local output="$1"
    find /sys/fs/bpf -mindepth 1 -maxdepth 7 -printf '%y %p\n' | sort > "$output"
}

snapshot_kernel() {
    local directory="$1" prefix="$2"
    bpftool -j prog show > "$directory/$prefix-prog.json"
    bpftool -j link show > "$directory/$prefix-link.json"
    bpftool -j map show > "$directory/$prefix-map.json"
    snapshot_bpffs "$directory/$prefix-bpffs.txt"
}

wait_ready() {
    local pid="$1" marker="$2"
    for _ in $(seq 1 3000); do
        [[ -e "$marker" ]] && return 0
        kill -0 "$pid" 2>/dev/null || return 1
        sleep 0.01
    done
    return 1
}

kill_loader() {
    local pid="$1" output="$2"
    local status=0
    [[ -n "$pid" ]] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill -KILL "$pid"
        wait "$pid" || status=$?
        printf 'loader_pid=%s\nloader_exit_status=%s\n' "$pid" "$status" > "$output"
    fi
}

remove_known_pins() {
    local maps="$1" links="$2"
    local name
    for name in "${link_names[@]}"; do
        [[ -e "$links/$name" ]] && rm "$links/$name"
    done
    for name in "${map_names[@]}"; do
        [[ -e "$maps/$name" ]] && rm "$maps/$name"
    done
}

cleanup_owned() {
    set +e
    [[ -n "$old_pid" ]] && kill_loader "$old_pid" "$evidence/final/old-loader-cleanup.txt"
    [[ -n "$new_pid" ]] && kill_loader "$new_pid" "$evidence/final/new-loader-cleanup.txt"
    [[ -n "$foreign_pid" ]] && kill_loader "$foreign_pid" "$evidence/final/foreign-loader-cleanup.txt"
    remove_known_pins "$shared_maps" "$old_links"
    remove_known_pins "$shared_maps" "$new_links"
    remove_known_pins "$foreign_maps" "$foreign_links"
    if [[ -e "$foreign_pin" ]]; then
        current_id=$(bpftool -j map show pinned "$foreign_pin" 2>/dev/null | jq -r '.id // empty')
        if [[ -n "$foreign_id" && "$current_id" == "$foreign_id" ]]; then
            echo "foreign_cleanup=removed_exact_test_created_id_$foreign_id" >> "$evidence/final/foreign-cleanup.txt"
            rm "$foreign_pin"
        else
            echo "foreign_cleanup=PRESERVED_identity_not_proven expected=$foreign_id actual=$current_id" >> "$evidence/final/foreign-cleanup.txt"
        fi
    fi
    rmdir "$old_links" "$new_links" "$shared_maps" "$root/shared" 2>/dev/null
    rmdir "$foreign_links" "$foreign_maps" "$root/foreign" "$root" /sys/fs/bpf/soglia-spike 2>/dev/null
    rm -f "$old_ready" "$new_ready" "$foreign_ready"
    for cg in "$old_cgroup" "$new_cgroup" "$foreign_cgroup"; do
        [[ -e "$cg/cgroup.kill" ]] && printf '1\n' > "$cg/cgroup.kill"
        [[ -d "$cg" ]] && rmdir "$cg"
    done
    [[ -d "$executions" ]] && rmdir "$executions"
}

record_final() {
    set +e
    {
        echo '# S13 final cleanup verification'
        date -u +UTC=%FT%TZ
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        stat -c 'delegated_root_inode=%i' "$unit"
        find "$unit" -mindepth 1 -maxdepth 2 -type d -printf '%p inode=%i\n' | sort
        for path in "$executions" "$root" "$old_ready" "$new_ready" "$foreign_ready"; do
            [[ -e "$path" ]] && echo "PRESENT $path" || echo "ABSENT $path"
        done
        bpftool cgroup tree "$unit"
        echo bpffs_begin
        find /sys/fs/bpf -mindepth 1 -maxdepth 7 -printf '%y %p\n' | sort
        echo bpffs_end
        ip netns list
        nft list tables | grep soglia || true
        ps -eo pid=,comm=,args= | awk '$2 ~ /^(s7_pinned_loader|s1_attribution|s12_exhaustion|soglia-spike-agent)$/ { print }'
    } > "$evidence/final/s13-cleanup.txt"
    snapshot_kernel "$evidence/final" s13-final
}

on_exit() {
    local status=$?
    cleanup_owned
    record_final
    printf '%s\n' "$status" > "$evidence/final/s13-run-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence/contract" "$evidence/baseline" "$evidence/case-a-compatible" \
    "$evidence/case-b-incompatible" "$evidence/case-c-unknown" \
    "$evidence/case-d-stale-reuse" "$evidence/final"

# The runner starts only from an independently clean state.
[[ "$(systemctl is-active soglia-spike-s0.service)" == active ]]
[[ ! -e "$executions" ]]
[[ ! -e /sys/fs/bpf/soglia-spike ]]
[[ ! -e "$old_ready" ]]
[[ ! -e "$new_ready" ]]
[[ ! -e "$foreign_ready" ]]

{
    echo '# S13 current contract audit'
    date -u +UTC=%FT%TZ
    echo 'soglia_meta_source_begin'
    sed -n '304,316p' /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c
    echo 'soglia_meta_source_end'
    echo 'loader_meta_accesses_begin'
    if command -v rg >/dev/null; then
        rg -n 'soglia_meta|map_mut\("soglia_meta|map\("soglia_meta' /soglia/spikes/cgroup-bpf/harness/src || true
    else
        grep -R -n 'soglia_meta' /soglia/spikes/cgroup-bpf/harness/src || true
    fi
    echo 'loader_meta_accesses_end'
    echo 'pin_and_cleanup_implementation_begin'
    sed -n '55,83p;330,365p' /soglia/spikes/cgroup-bpf/harness/src/main.rs
    sed -n '55,82p' /soglia/spikes/cgroup-bpf/harness/src/bin/s7_pinned_loader.rs
    echo 'pin_and_cleanup_implementation_end'
    echo 'broad_bpffs_delete_scan_begin'
    if command -v rg >/dev/null; then
        rg -n 'rm[[:space:]]+-rf.*bpffs|remove_dir_all.*bpffs|remove_dir_all.*soglia' \
            /soglia/spikes/cgroup-bpf --glob '!evidence/**' --glob '!run-s13.sh' || true
    else
        grep -R -n -E 'rm[[:space:]]+-rf.*bpffs|remove_dir_all.*bpffs|remove_dir_all.*soglia' \
            /soglia/spikes/cgroup-bpf --exclude-dir=evidence --exclude=run-s13.sh --include='*.rs' --include='*.sh' || true
    fi
    echo 'broad_bpffs_delete_scan_end'
} > "$evidence/contract/current-contract.txt"

cat > "$evidence/contract/metadata-sufficiency.txt" <<'EOF'
owner_field=ABSENT
schema_version_field=ABSENT
abi_or_layout_field=ABSENT
generation_field=ABSENT
authenticated_or_kernel_provenance_binding=ABSENT
loader_write_of_soglia_meta=ABSENT
loader_validation_of_soglia_meta=ABSENT
startup_pin_inventory_validation=ABSENT
supported_pin_sweep_or_recreate_state_machine=ABSENT
current_contract_sufficient=false
classification=OWNERSHIP_AND_COMPATIBILITY_UNDEFINED
EOF

{
    echo '# S13 fresh baseline'
    date -u +UTC=%FT%TZ
    uname -a
    systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID -p ControlGroup -p Delegate -p DelegateControllers --no-pager
    stat -c 'delegated_root_inode=%i' "$unit"
    find "$unit" -mindepth 1 -maxdepth 2 -type d -printf '%p inode=%i\n' | sort
    bpftool cgroup tree "$unit"
    ip netns list
    ip -o link show
    nft -a list ruleset
    ps -eo pid=,comm=,args= | awk '$2 ~ /^(s7_pinned_loader|s1_attribution|s12_exhaustion|soglia-spike-agent)$/ { print }'
} > "$evidence/baseline/s13-baseline-state.txt"
snapshot_kernel "$evidence/baseline" s13-baseline

mkdir "$executions"
printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
mkdir "$old_cgroup" "$new_cgroup" "$foreign_cgroup"

# CASE A: create a real current-object prior-run pin set, then kill its loader.
snapshot_bpffs "$evidence/case-a-compatible/pre-bpffs.txt"
"$loader" "$object" "$old_cgroup" "$shared_maps" "$old_links" "$old_ready" \
    > "$evidence/case-a-compatible/prior-loader.log" 2>&1 &
old_pid=$!
wait_ready "$old_pid" "$old_ready"

# Add explicit stale authorization material.  The tuple is
# 10.201.0.1:41000 -> 10.200.255.1:15001; values are deliberately non-zero.
bpftool map update pinned "$shared_maps/soglia_policy" \
    key hex 88 77 66 55 44 33 22 11 \
    value hex 01 00 00 00 00 00 00 00 55 44 33 22 11 00 00 00
bpftool map update pinned "$shared_maps/soglia_cookie_a" \
    key hex 88 77 66 55 44 33 22 11 \
    value hex 01 70 00 00 00 00 00 00
bpftool map update pinned "$shared_maps/soglia_tuples" \
    key hex 0a c9 00 01 0a c8 ff 01 28 a0 00 00 99 3a 00 00 \
    value hex \
        88 77 66 55 44 33 22 11 01 70 00 00 00 00 00 00 \
        01 70 00 00 00 00 00 00 b9 d6 6a 00 00 00 00 00 \
        05 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 \
        01 70 00 00 00 00 00 00 99 3a 00 00 00 00 00 00

bpftool -j map dump pinned "$shared_maps/soglia_meta" > "$evidence/case-a-compatible/meta-before-loss.json"
bpftool -j map dump pinned "$shared_maps/soglia_policy" > "$evidence/case-a-compatible/policy-before-loss.json"
bpftool -j map dump pinned "$shared_maps/soglia_cookie_a" > "$evidence/case-a-compatible/cookie-before-loss.json"
bpftool -j map dump pinned "$shared_maps/soglia_tuples" > "$evidence/case-a-compatible/tuple-before-loss.json"
snapshot_kernel "$evidence/case-a-compatible" before-loader-loss
for name in "${map_names[@]}"; do
    bpftool -j map show pinned "$shared_maps/$name"
done > "$evidence/case-a-compatible/pinned-map-identities-before-loss.jsonl"
bpftool -j link show > "$evidence/case-a-compatible/pinned-link-identities-before-loss.json"
find "$old_links" -mindepth 1 -maxdepth 1 -type f -printf '%f\n' | sort \
    > "$evidence/case-a-compatible/pinned-link-names-before-loss.txt"

kill_loader "$old_pid" "$evidence/case-a-compatible/prior-loader-exit.txt"
old_pid=
snapshot_kernel "$evidence/case-a-compatible" after-loader-loss
bpftool -j map dump pinned "$shared_maps/soglia_meta" > "$evidence/case-a-compatible/meta-after-loss.json"

cat > "$evidence/case-a-compatible/compatibility-decision.txt" <<'EOF'
same_object_layout=true
trusted_owner_identified=false
schema_compatibility_identified=false
reason=soglia_meta_has_no_defined_fields_and_remains_all_zero
case_a_precondition_established=false
EOF

# Detach only the test-created old links, leaving the real stale pinned maps.
for name in "${link_names[@]}"; do rm "$old_links/$name"; done
rmdir "$old_links"
rmdir "$old_cgroup"
snapshot_bpffs "$evidence/case-d-stale-reuse/pre-restart-bpffs.txt"
for name in soglia_policy soglia_cookie_a soglia_tuples soglia_meta; do
    bpftool -j map show pinned "$shared_maps/$name"
done > "$evidence/case-d-stale-reuse/map-identities-before-restart.jsonl"

# CASE D: invoke the current loader for a fresh cgroup against the existing map root.
"$loader" "$object" "$new_cgroup" "$shared_maps" "$new_links" "$new_ready" \
    > "$evidence/case-d-stale-reuse/restart-loader.log" 2>&1 &
new_pid=$!
wait_ready "$new_pid" "$new_ready"
for name in soglia_policy soglia_cookie_a soglia_tuples soglia_meta; do
    bpftool -j map show pinned "$shared_maps/$name"
done > "$evidence/case-d-stale-reuse/map-identities-after-ready.jsonl"
before_map_ids=$(jq -s -c 'map(.id)' "$evidence/case-d-stale-reuse/map-identities-before-restart.jsonl")
after_map_ids=$(jq -s -c 'map(.id)' "$evidence/case-d-stale-reuse/map-identities-after-ready.jsonl")
[[ "$before_map_ids" == "$after_map_ids" ]]
bpftool -j map dump pinned "$shared_maps/soglia_meta" > "$evidence/case-d-stale-reuse/meta-after-ready.json"
bpftool -j map dump pinned "$shared_maps/soglia_policy" > "$evidence/case-d-stale-reuse/policy-after-ready.json"
bpftool -j map dump pinned "$shared_maps/soglia_cookie_a" > "$evidence/case-d-stale-reuse/cookie-after-ready.json"
bpftool -j map dump pinned "$shared_maps/soglia_tuples" > "$evidence/case-d-stale-reuse/tuple-after-ready.json"
snapshot_kernel "$evidence/case-d-stale-reuse" after-ready
{
    echo "fresh_cgroup_inode=$(stat -c %i "$new_cgroup")"
    echo "ready_marker_present=$([[ -e "$new_ready" ]] && echo true || echo false)"
    echo "policy_entries=$(jq length "$evidence/case-d-stale-reuse/policy-after-ready.json")"
    echo "cookie_entries=$(jq length "$evidence/case-d-stale-reuse/cookie-after-ready.json")"
    echo "tuple_entries=$(jq length "$evidence/case-d-stale-reuse/tuple-after-ready.json")"
    echo "map_ids_before=$before_map_ids"
    echo "map_ids_after=$after_map_ids"
    echo "map_identity_reused=$([[ "$before_map_ids" == "$after_map_ids" ]] && echo true || echo false)"
    echo 'stale_attribution_present_at_ready=true'
    echo 'recovery_or_compatibility_decision_before_ready=false'
} > "$evidence/case-d-stale-reuse/result.txt"

kill_loader "$new_pid" "$evidence/case-d-stale-reuse/restart-loader-exit.txt"
new_pid=
remove_known_pins "$shared_maps" "$new_links"
rmdir "$new_links" "$shared_maps" "$root/shared"
rmdir "$new_cgroup"

# CASE B: no compatibility field exists to vary without inventing a format.
snapshot_kernel "$evidence/case-b-incompatible" pre
cat > "$evidence/case-b-incompatible/result.txt" <<'EOF'
compatibility_field_available=false
synthetic_incompatible_state_created=false
startup_attempted=false
admission_attempted=false
reason=changing_any_u64_slot_would_invent_an_undefined_metadata_contract
result=UNPROVEN
EOF
snapshot_kernel "$evidence/case-b-incompatible" post

# CASE C: an explicitly test-created foreign map under the loader's map root.
mkdir -p "$foreign_maps"
bpftool map create "$foreign_pin" type array key 4 value 8 entries 1 name s13_foreign
foreign_id=$(bpftool -j map show pinned "$foreign_pin" | jq -r .id)
bpftool map update pinned "$foreign_pin" key hex 00 00 00 00 value hex 13 00 00 00 00 00 00 00
bpftool -j map show pinned "$foreign_pin" > "$evidence/case-c-unknown/foreign-before.json"
bpftool -j map dump pinned "$foreign_pin" > "$evidence/case-c-unknown/foreign-content-before.json"
snapshot_kernel "$evidence/case-c-unknown" pre-startup
"$loader" "$object" "$foreign_cgroup" "$foreign_maps" "$foreign_links" "$foreign_ready" \
    > "$evidence/case-c-unknown/startup.log" 2>&1 &
foreign_pid=$!
wait_ready "$foreign_pid" "$foreign_ready"
bpftool -j map show pinned "$foreign_pin" > "$evidence/case-c-unknown/foreign-after.json"
bpftool -j map dump pinned "$foreign_pin" > "$evidence/case-c-unknown/foreign-content-after.json"
snapshot_kernel "$evidence/case-c-unknown" post-ready
foreign_after_id=$(jq -r .id "$evidence/case-c-unknown/foreign-after.json")
{
    echo "foreign_provenance=test_created_by_s13_runner"
    echo "foreign_pin=$foreign_pin"
    echo "foreign_type=array"
    echo "foreign_id_before=$foreign_id"
    echo "foreign_id_after=$foreign_after_id"
    echo "foreign_identity_preserved=$([[ "$foreign_id" == "$foreign_after_id" ]] && echo true || echo false)"
    echo "startup_ready=$([[ -e "$foreign_ready" ]] && echo true || echo false)"
    echo 'trusted_owner_metadata=false'
    echo 'unknown_state_diagnostic=false'
    echo 'fail_closed_before_ready=false'
} > "$evidence/case-c-unknown/result.txt"
[[ "$foreign_id" == "$foreign_after_id" ]]

kill_loader "$foreign_pid" "$evidence/case-c-unknown/loader-exit.txt"
foreign_pid=
remove_known_pins "$foreign_maps" "$foreign_links"
rmdir "$foreign_links"
rmdir "$foreign_cgroup"

cat > "$evidence/s13-result.txt" <<'EOF'
S13_RESULT=FAIL
ownership_compatibility_contract=UNDEFINED
case_a=UNPROVEN_NO_TRUSTED_OWNER_OR_COMPATIBILITY_METADATA
case_b=UNPROVEN_NO_DEFINED_COMPATIBILITY_FIELD
case_c=FAIL_READY_WITH_UNKNOWN_PIN_FOREIGN_ID_PRESERVED
case_d=FAIL_STALE_MAP_IDENTITIES_AND_ATTRIBUTION_REUSED_AT_READY
readiness=FAIL_NO_INSPECTION_OR_RECOVERY_DECISION_BEFORE_READY
production_code_modified=false
candidate_selected=false
S14_STARTED=false
EOF

echo 'S13_RESULT=FAIL'
