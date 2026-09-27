#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Complete S13 rerun against the spike-only ownership/compatibility contract.

set -euo pipefail
umask 077

evidence="${S13_V2_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s13/run2}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
pin_root=/sys/fs/bpf/soglia-spike/s13-v2
record_dir=/run/soglia/cgroup-bpf-spike
ready=/run/soglia-spike-s13-v2.ready
object=/var/tmp/spike/bpf/soglia-diag.o
loader=/var/tmp/spike/target/release/s7_pinned_loader
manager=/soglia/spikes/cgroup-bpf/s13-state-manager.sh
foreign_pin="$pin_root/maps/soglia_policy"
foreign_id=
case_b_original=

cgroups=(
    s13-a-old s13-a-new s13-b-old s13-b-new s13-c
    s13-crash-old s13-crash-new
)

snapshot_kernel() {
    local directory="$1" prefix="$2"
    bpftool -j prog show > "$directory/$prefix-prog.json"
    bpftool -j link show > "$directory/$prefix-link.json"
    bpftool -j map show > "$directory/$prefix-map.json"
    find /sys/fs/bpf -mindepth 1 -maxdepth 7 -printf '%y %p\n' | sort \
        > "$directory/$prefix-bpffs.txt"
}

atomic_record() {
    local body="$1" temporary="$record_dir/.state.json.s13-test.tmp"
    printf '%s\n' "$body" > "$temporary"
    chmod 0600 "$temporary"
    sync -f "$temporary"
    mv -f -- "$temporary" "$record_dir/state.json"
    sync -d "$record_dir"
}

map_ids() {
    local root="$1" result='{}' name id
    for name in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events \
        soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag; do
        id=$(bpftool -j map show pinned "$root/maps/$name" | jq .id)
        result=$(jq -c --arg n "$name" --argjson id "$id" '. + {($n):$id}' <<< "$result")
    done
    printf '%s' "$result"
}

populate_stale() {
    local root="$1"
    bpftool map update pinned "$root/maps/soglia_policy" \
        key hex 88 77 66 55 44 33 22 11 \
        value hex 01 00 00 00 00 00 00 00 55 44 33 22 11 00 00 00
    bpftool map update pinned "$root/maps/soglia_cookie_a" \
        key hex 88 77 66 55 44 33 22 11 \
        value hex 01 70 00 00 00 00 00 00
    bpftool map update pinned "$root/maps/soglia_tuples" \
        key hex 0a c9 00 01 0a c8 ff 01 28 a0 00 00 99 3a 00 00 \
        value hex \
            88 77 66 55 44 33 22 11 01 70 00 00 00 00 00 00 \
            01 70 00 00 00 00 00 00 b9 d6 6a 00 00 00 00 00 \
            05 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 \
            01 70 00 00 00 00 00 00 99 3a 00 00 00 00 00 00
}

remove_ready() {
    [[ -e "$ready" ]] && rm -- "$ready"
    return 0
}

remove_record_dir_if_empty() {
    [[ -d "$record_dir" ]] && rmdir "$record_dir"
    return 0
}

cleanup_owned() {
    set +e
    if [[ -n "$case_b_original" && -d "$record_dir" ]]; then
        atomic_record "$case_b_original"
    fi
    if [[ -e "$record_dir/state.json" ]]; then
        "$manager" cleanup "$object" "$pin_root" "$record_dir" >/dev/null 2>&1
    fi
    if [[ -e "$foreign_pin" ]]; then
        current_id=$(bpftool -j map show pinned "$foreign_pin" 2>/dev/null | jq -r '.id // empty')
        if [[ -n "$foreign_id" && "$current_id" == "$foreign_id" ]]; then
            rm -- "$foreign_pin"
        fi
    fi
    [[ -d "$pin_root/maps" ]] && rmdir "$pin_root/maps"
    [[ -d "$pin_root/links" ]] && rmdir "$pin_root/links"
    [[ -d "$pin_root" ]] && rmdir "$pin_root"
    [[ -d /sys/fs/bpf/soglia-spike ]] && rmdir /sys/fs/bpf/soglia-spike
    remove_ready
    rm -f /run/soglia-spike-s13-v2-*.ready
    remove_record_dir_if_empty
    local name path
    for name in "${cgroups[@]}"; do
        path="$executions/$name"
        [[ -e "$path/cgroup.kill" ]] && printf '1\n' > "$path/cgroup.kill"
        [[ -d "$path" ]] && rmdir "$path"
    done
    [[ -d "$executions" ]] && rmdir "$executions"
}

record_final() {
    set +e
    mkdir -p "$evidence/final"
    {
        echo '# S13 v2 final cleanup verification'
        date -u +UTC=%FT%TZ
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        stat -c 'delegated_root_inode=%i' "$unit"
        find "$unit" -mindepth 1 -maxdepth 2 -type d -printf '%p inode=%i\n' | sort
        for path in "$executions" "$pin_root" "$record_dir" "$ready"; do
            [[ -e "$path" ]] && echo "PRESENT $path" || echo "ABSENT $path"
        done
        bpftool cgroup tree "$unit"
        echo bpffs_begin
        find /sys/fs/bpf -mindepth 1 -maxdepth 7 -printf '%y %p\n' | sort
        echo bpffs_end
        ip netns list
        nft list tables | grep s13 || true
        ps -eo pid=,comm=,args= | awk '$2 ~ /^(s7_pinned_loader|s13-state-manager)$/ { print }'
    } > "$evidence/final/s13-v2-cleanup.txt"
    snapshot_kernel "$evidence/final" s13-v2-final
}

on_exit() {
    local status=$?
    cleanup_owned
    record_final
    printf '%s\n' "$status" > "$evidence/final/s13-v2-run-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence/baseline" "$evidence/contract" "$evidence/case-a-compatible" \
    "$evidence/case-b-incompatible" "$evidence/case-c-unknown" \
    "$evidence/case-d-generation" "$evidence/crash-ordering" "$evidence/final"

[[ "$(systemctl is-active soglia-spike-s0.service)" == active ]]
[[ ! -e "$executions" ]]
[[ ! -e /sys/fs/bpf/soglia-spike ]]
[[ ! -e "$record_dir" ]]
[[ ! -e "$ready" ]]

{
    echo '# S13 v2 fresh baseline'
    date -u +UTC=%FT%TZ
    uname -a
    systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID -p ControlGroup -p Delegate -p DelegateControllers --no-pager
    stat -c 'delegated_root_inode=%i' "$unit"
    find "$unit" -mindepth 1 -maxdepth 2 -type d -printf '%p inode=%i\n' | sort
    bpftool cgroup tree "$unit"
    stat -Lc '/run/soglia uid=%u gid=%g mode=%a type=%F' /run/soglia
    ip netns list
    ip -o link show
    nft -a list ruleset
} > "$evidence/baseline/state.txt"
snapshot_kernel "$evidence/baseline" s13-v2-baseline
sha256sum "$object" "$manager" /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c \
    /soglia/spikes/cgroup-bpf/S13-CONTRACT.md > "$evidence/contract/provenance.txt"
cp /soglia/spikes/cgroup-bpf/S13-CONTRACT.md "$evidence/contract/S13-CONTRACT.md"
{
    echo 'production_backend_changed=false'
    echo 'record_location=/run/soglia/cgroup-bpf-spike/state.json'
    echo 'path_alone_is_ownership=false'
    echo 'meta_alone_is_ownership=false'
    echo 'trusted_record_required=true'
    echo 'broad_prefix_cleanup=false'
} > "$evidence/contract/summary.txt"

mkdir "$executions"
printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
for name in "${cgroups[@]}"; do mkdir "$executions/$name"; done
for name in "${cgroups[@]}"; do
    stat -c "$name inode=%i" "$executions/$name"
done > "$evidence/baseline/cgroup-inodes.txt"

# CASE A + D: genuine previous generation with stale authorization, then compatible recovery.
"$manager" start "$object" "$executions/s13-a-old" "$pin_root" "$record_dir" "$ready" "$loader" \
    > "$evidence/case-a-compatible/old-startup.log" 2>&1
cp "$record_dir/state.json" "$evidence/case-a-compatible/old-record.json"
populate_stale "$pin_root"
old_state_id=$(jq -r .state_id "$record_dir/state.json")
old_generation=$(jq -r .generation "$record_dir/state.json")
old_map_ids=$(map_ids "$pin_root")
old_program_ids=$(jq -c '[.programs[].id]' "$record_dir/state.json")
old_link_ids=$(jq -c '[.links[].id]' "$record_dir/state.json")
printf '%s\n' "$old_map_ids" > "$evidence/case-a-compatible/old-map-ids.json"
bpftool -j map dump pinned "$pin_root/maps/soglia_policy" > "$evidence/case-a-compatible/old-policy.json"
bpftool -j map dump pinned "$pin_root/maps/soglia_cookie_a" > "$evidence/case-a-compatible/old-cookie.json"
bpftool -j map dump pinned "$pin_root/maps/soglia_tuples" > "$evidence/case-a-compatible/old-tuple.json"
bpftool -j map dump pinned "$pin_root/maps/soglia_meta" > "$evidence/case-a-compatible/old-meta.json"
snapshot_kernel "$evidence/case-a-compatible" old-state

remove_ready
"$manager" start "$object" "$executions/s13-a-new" "$pin_root" "$record_dir" "$ready" "$loader" \
    > "$evidence/case-a-compatible/recovery-startup.log" 2>&1
nl -ba "$evidence/case-a-compatible/recovery-startup.log" \
    > "$evidence/case-a-compatible/recovery-order.txt"
cp "$record_dir/state.json" "$evidence/case-a-compatible/new-record.json"
new_state_id=$(jq -r .state_id "$record_dir/state.json")
new_generation=$(jq -r .generation "$record_dir/state.json")
new_map_ids=$(map_ids "$pin_root")
printf '%s\n' "$new_map_ids" > "$evidence/case-a-compatible/new-map-ids.json"
bpftool -j map dump pinned "$pin_root/maps/soglia_policy" > "$evidence/case-a-compatible/new-policy.json"
bpftool -j map dump pinned "$pin_root/maps/soglia_cookie_a" > "$evidence/case-a-compatible/new-cookie.json"
bpftool -j map dump pinned "$pin_root/maps/soglia_tuples" > "$evidence/case-a-compatible/new-tuple.json"
bpftool -j map dump pinned "$pin_root/maps/soglia_meta" > "$evidence/case-a-compatible/new-meta.json"
snapshot_kernel "$evidence/case-a-compatible" new-state

[[ "$old_state_id" != "$new_state_id" ]]
[[ "$new_generation" -eq $((old_generation + 1)) ]]
[[ $(jq --argjson old "$old_map_ids" --argjson new "$new_map_ids" \
    '[($old[])] as $ids | [$new[] | select(. as $id | $ids | index($id))] | length' <<< '{}') -eq 0 ]]
[[ $(jq length "$evidence/case-a-compatible/new-policy.json") -eq 0 ]]
[[ $(jq length "$evidence/case-a-compatible/new-cookie.json") -eq 0 ]]
[[ $(jq length "$evidence/case-a-compatible/new-tuple.json") -eq 0 ]]
grep -q '^classification=KNOWN_COMPATIBLE ' "$evidence/case-a-compatible/recovery-startup.log"
grep -q '^sweep=verified_absent ' "$evidence/case-a-compatible/recovery-startup.log"
grep -q '^record_phase=READY ' "$evidence/case-a-compatible/recovery-startup.log"
[[ $(grep -n '^sweep=verified_absent ' "$evidence/case-a-compatible/recovery-startup.log" | cut -d: -f1) -lt \
   $(grep -n '^startup_ready=true' "$evidence/case-a-compatible/recovery-startup.log" | cut -d: -f1) ]]

set +e
bpftool map lookup pinned "$pin_root/maps/soglia_tuples" \
    key hex 0a c9 00 01 0a c8 ff 01 28 a0 00 00 99 3a 00 00 \
    > "$evidence/case-d-generation/old-tuple-lookup.txt" 2>&1
lookup_status=$?
set -e
echo "$lookup_status" > "$evidence/case-d-generation/old-tuple-lookup-status.txt"
[[ "$lookup_status" -ne 0 ]]
{
    echo "old_state_id=$old_state_id"
    echo "new_state_id=$new_state_id"
    echo "old_generation=$old_generation"
    echo "new_generation=$new_generation"
    echo "old_map_ids=$old_map_ids"
    echo "new_map_ids=$new_map_ids"
    echo 'old_map_ids_absent=true'
    echo 'new_authorization_maps_empty=true'
    echo 'old_tuple_lookup_absent=true'
    echo 'stale_generation_authorized_new=false'
} > "$evidence/case-d-generation/result.txt"
for id in $(jq -r '.[]' <<< "$old_program_ids"); do
    [[ $(bpftool -j prog show | jq --argjson id "$id" '[.[] | select(.id == $id)] | length') -eq 0 ]]
done
for id in $(jq -r '.[]' <<< "$old_link_ids"); do
    [[ $(bpftool -j link show | jq --argjson id "$id" '[.[] | select(.id == $id)] | length') -eq 0 ]]
done
"$manager" cleanup "$object" "$pin_root" "$record_dir" \
    > "$evidence/case-a-compatible/cleanup.log" 2>&1
remove_ready
remove_record_dir_if_empty

# CASE B: trusted owner/state binding, deliberately incompatible ABI.
"$manager" start "$object" "$executions/s13-b-old" "$pin_root" "$record_dir" "$ready" "$loader" \
    > "$evidence/case-b-incompatible/old-startup.log" 2>&1
populate_stale "$pin_root"
case_b_original=$(cat "$record_dir/state.json")
printf '%s\n' "$case_b_original" > "$evidence/case-b-incompatible/compatible-record-before-mutation.json"
case_b_ids=$(map_ids "$pin_root")
case_b_meta_before=$(bpftool -j map dump pinned "$pin_root/maps/soglia_meta")
mutated=$(jq -c '.abi_version = 2' <<< "$case_b_original")
atomic_record "$mutated"
cp "$record_dir/state.json" "$evidence/case-b-incompatible/incompatible-record.json"
remove_ready
set +e
"$manager" start "$object" "$executions/s13-b-new" "$pin_root" "$record_dir" "$ready" "$loader" \
    > "$evidence/case-b-incompatible/startup-attempt.log" 2>&1
case_b_status=$?
set -e
echo "$case_b_status" > "$evidence/case-b-incompatible/startup-exit-status.txt"
[[ "$case_b_status" -eq 42 ]]
[[ ! -e "$ready" ]]
[[ "$case_b_ids" == "$(map_ids "$pin_root")" ]]
[[ "$case_b_meta_before" == "$(bpftool -j map dump pinned "$pin_root/maps/soglia_meta")" ]]
[[ $(bpftool -j cgroup show "$executions/s13-b-new" | jq length) -eq 0 ]]
bpftool -j map dump pinned "$pin_root/maps/soglia_tuples" > "$evidence/case-b-incompatible/stale-tuple-after-refusal.json"
snapshot_kernel "$evidence/case-b-incompatible" after-refusal
{
    echo 'trusted_record=true'
    echo 'matching_state_id=true'
    echo 'mutated_field=abi_version'
    echo 'expected_abi=1'
    echo 'observed_abi=2'
    echo 'startup_ready=false'
    echo 'new_cgroup_programs=0'
    echo 'object_ids_unchanged=true'
    echo 'stale_state_not_consumed=true'
} > "$evidence/case-b-incompatible/result.txt"
atomic_record "$case_b_original"
case_b_original=
"$manager" cleanup "$object" "$pin_root" "$record_dir" \
    > "$evidence/case-b-incompatible/test-harness-cleanup.log" 2>&1
remove_record_dir_if_empty

# CASE C: familiar exact path, but no trusted ownership record.
mkdir -p "$pin_root/maps"
bpftool map create "$foreign_pin" type array key 4 value 8 entries 1 name s13_foreign
bpftool map update pinned "$foreign_pin" key hex 00 00 00 00 value hex 13 00 00 00 00 00 00 00
foreign_id=$(bpftool -j map show pinned "$foreign_pin" | jq -r .id)
bpftool -j map show pinned "$foreign_pin" > "$evidence/case-c-unknown/foreign-before.json"
bpftool -j map dump pinned "$foreign_pin" > "$evidence/case-c-unknown/foreign-content-before.json"
snapshot_kernel "$evidence/case-c-unknown" before-attempt
set +e
"$manager" start "$object" "$executions/s13-c" "$pin_root" "$record_dir" "$ready" "$loader" \
    > "$evidence/case-c-unknown/startup-attempt.log" 2>&1
case_c_status=$?
set -e
echo "$case_c_status" > "$evidence/case-c-unknown/startup-exit-status.txt"
[[ "$case_c_status" -eq 43 ]]
[[ ! -e "$ready" ]]
[[ ! -e "$record_dir/state.json" ]]
foreign_after_id=$(bpftool -j map show pinned "$foreign_pin" | jq -r .id)
[[ "$foreign_id" == "$foreign_after_id" ]]
bpftool -j map show pinned "$foreign_pin" > "$evidence/case-c-unknown/foreign-after.json"
bpftool -j map dump pinned "$foreign_pin" > "$evidence/case-c-unknown/foreign-content-after.json"
cmp -s "$evidence/case-c-unknown/foreign-content-before.json" "$evidence/case-c-unknown/foreign-content-after.json"
snapshot_kernel "$evidence/case-c-unknown" after-attempt
{
    echo 'trusted_record=false'
    echo "foreign_pin=$foreign_pin"
    echo "foreign_id_before=$foreign_id"
    echo "foreign_id_after=$foreign_after_id"
    echo 'foreign_identity_preserved=true'
    echo 'startup_ready=false'
    echo 'soglia_recovery_deleted_foreign=false'
} > "$evidence/case-c-unknown/result.txt"
rm -- "$foreign_pin"
foreign_id=
rmdir "$pin_root/maps" "$pin_root"
remove_record_dir_if_empty

# Write-ahead crash boundaries. Every injected crash is pre-readiness and recoverable.
for fault in intent pins validated ready_record; do
    fault_dir="$evidence/crash-ordering/$fault"
    mkdir -p "$fault_dir"
    remove_ready
    set +e
    S13_FAULT_AFTER="$fault" "$manager" start "$object" "$executions/s13-crash-old" \
        "$pin_root" "$record_dir" "$ready" "$loader" > "$fault_dir/fault.log" 2>&1
    fault_status=$?
    set -e
    echo "$fault_status" > "$fault_dir/fault-exit-status.txt"
    [[ "$fault_status" -eq 70 ]]
    [[ ! -e "$ready" ]]
    cp "$record_dir/state.json" "$fault_dir/record-after-crash.json"
    snapshot_kernel "$fault_dir" after-crash
    "$manager" start "$object" "$executions/s13-crash-new" "$pin_root" "$record_dir" "$ready" "$loader" \
        > "$fault_dir/recovery.log" 2>&1
    [[ -e "$ready" ]]
    [[ $(jq -r .generation "$record_dir/state.json") -eq 2 ]]
    grep -q '^classification=KNOWN_COMPATIBLE' "$fault_dir/recovery.log"
    grep -q '^record_phase=READY ' "$fault_dir/recovery.log"
    grep -q '^startup_ready=true' "$fault_dir/recovery.log"
    nl -ba "$fault_dir/recovery.log" > "$fault_dir/recovery-order.txt"
    cp "$record_dir/state.json" "$fault_dir/record-after-recovery.json"
    "$manager" cleanup "$object" "$pin_root" "$record_dir" > "$fault_dir/cleanup.log" 2>&1
    remove_ready
    remove_record_dir_if_empty
done

rmdir /sys/fs/bpf/soglia-spike
for name in "${cgroups[@]}"; do rmdir "$executions/$name"; done
rmdir "$executions"

cat > "$evidence/s13-v2-result.txt" <<'EOF'
S13_RESULT=PASS_AFTER_SPIKE_CONTRACT
original_S13_FAIL=PRESERVED
case_a=PASS_OWNED_COMPATIBLE_SWEPT_RECREATED_NO_REUSE
case_b=PASS_OWNED_INCOMPATIBLE_FAIL_CLOSED_NO_READY
case_c=PASS_UNKNOWN_FOREIGN_FAIL_CLOSED_UNCHANGED
case_d=PASS_STALE_GENERATION_CANNOT_AUTHORIZE_NEW
write_ahead_crash_boundaries=PASS
readiness_order=PASS
production_backend_implemented=false
production_code_modified=false
candidate_selected=false
S14_STARTED=false
EOF

echo 'S13_RESULT=PASS_AFTER_SPIKE_CONTRACT'
