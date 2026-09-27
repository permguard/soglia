#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Spike-only S13 ownership/compatibility manager. This is not a production backend.

set -euo pipefail
umask 077

MAGIC=SOGLIA_CGROUP_BPF_SPIKE_STATE
META_MAGIC_HEX=534f474c49414250
SCHEMA_VERSION=1
ABI_VERSION=1
RECORD_NAME=state.json

map_names=(
    soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events
    soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag
)
link_names=(sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops)

declare -A map_contract=(
    [soglia_policy]='hash 8 16 1024 0'
    [soglia_tuples]='hash 16 64 4096 0'
    [soglia_cookie_a]='hash 8 8 4096 0'
    [soglia_sk_b]='sk_storage 4 8 0 1'
    [soglia_events]='ringbuf 0 0 65536 0'
    [soglia_counters]='array 4 8 9 0'
    [soglia_denies]='hash 8 8 1024 0'
    [soglia_meta]='array 4 48 1 0'
    [soglia_diag_entries]='array 4 8 7 0'
    [soglia_port_diag]='array 4 4 12 0'
)

declare -A program_type=(
    [soglia_sock_create]=cgroup_sock
    [soglia_connect4]=cgroup_sock_addr
    [soglia_connect6]=cgroup_sock_addr
    [soglia_sendmsg4]=cgroup_sock_addr
    [soglia_sendmsg6]=cgroup_sock_addr
    [soglia_sockops]=sock_ops
)

declare -A program_attach=(
    [soglia_sock_create]=cgroup_inet_sock_create
    [soglia_connect4]=cgroup_inet4_connect
    [soglia_connect6]=cgroup_inet6_connect
    [soglia_sendmsg4]=cgroup_udp4_sendmsg
    [soglia_sendmsg6]=cgroup_udp6_sendmsg
    [soglia_sockops]=cgroup_sock_ops
)

loader_pid=
internal_ready=

log() {
    printf '%s\n' "$*"
}

fail() {
    local class="$1" message="$2" code="${3:-1}"
    log "classification=$class"
    log "startup_ready=false"
    log "error=$message"
    exit "$code"
}

on_exit() {
    local status=$?
    if [[ -n "$loader_pid" ]] && kill -0 "$loader_pid" 2>/dev/null; then
        kill -KILL "$loader_pid" 2>/dev/null || true
        wait "$loader_pid" 2>/dev/null || true
    fi
    [[ -n "$internal_ready" ]] && rm -f -- "$internal_ready"
    exit "$status"
}
trap on_exit EXIT

require_root_owned_mode() {
    local path="$1" expected_mode="$2" kind="$3"
    [[ ! -L "$path" ]] || fail UNKNOWN "$kind is a symlink: $path" 43
    [[ -e "$path" ]] || fail UNKNOWN "$kind is absent: $path" 43
    local uid gid mode
    read -r uid gid mode < <(stat -Lc '%u %g %a' "$path")
    [[ "$uid" == 0 && "$gid" == 0 && "$mode" == "$expected_mode" ]] || \
        fail UNKNOWN "$kind trust check failed for $path: uid=$uid gid=$gid mode=$mode" 43
}

prepare_trust_anchor() {
    local record_dir="$1"
    [[ "$EUID" -eq 0 ]] || fail UNKNOWN 'state manager must run as root' 43
    [[ "$record_dir" == /run/soglia/* ]] || \
        fail UNKNOWN "record directory is outside /run/soglia: $record_dir" 43
    if [[ ! -e /run/soglia ]]; then
        mkdir /run/soglia
        chmod 0700 /run/soglia
    fi
    require_root_owned_mode /run/soglia 700 'Soglia state directory'
    if [[ ! -e "$record_dir" ]]; then
        mkdir "$record_dir"
        chmod 0700 "$record_dir"
    fi
    require_root_owned_mode "$record_dir" 700 'cgroup-BPF record directory'
    if [[ -e "$record_dir/$RECORD_NAME" ]]; then
        require_root_owned_mode "$record_dir/$RECORD_NAME" 600 'cgroup-BPF ownership record'
    fi
}

atomic_write() {
    local directory="$1" name="$2" body="$3"
    local temporary="$directory/.$name.$$.tmp"
    printf '%s\n' "$body" > "$temporary"
    chmod 0600 "$temporary"
    sync -f "$temporary"
    mv -f -- "$temporary" "$directory/$name"
    sync -d "$directory"
}

atomic_ready() {
    local path="$1" body="$2" directory temporary
    directory=$(dirname "$path")
    temporary="$directory/.$(basename "$path").$$.tmp"
    printf '%s\n' "$body" > "$temporary"
    chmod 0600 "$temporary"
    sync -f "$temporary"
    mv -f -- "$temporary" "$path"
    sync -d "$directory"
}

new_state_id() {
    od -An -N16 -tx1 /dev/urandom | tr -d ' \n'
}

u64_le_hex() {
    local value="$1" result= byte
    for _ in 1 2 3 4 5 6 7 8; do
        printf -v byte '%02x' "$((value & 255))"
        result+="$byte"
        value=$((value >> 8))
    done
    printf '%s' "$result"
}

hex_to_args() {
    local input="$1"
    local -n output="$2"
    output=()
    while [[ -n "$input" ]]; do
        output+=("${input:0:2}")
        input="${input:2}"
    done
}

expected_meta_hex() {
    local state_id="$1" generation="$2"
    printf '%s%s%s%s%s' \
        "$META_MAGIC_HEX" \
        "$(u64_le_hex "$SCHEMA_VERSION")" \
        "$(u64_le_hex "$ABI_VERSION")" \
        "$state_id" \
        "$(u64_le_hex "$generation")"
}

current_meta_hex() {
    local pin="$1"
    bpftool -j map dump pinned "$pin" | \
        jq -r '.[0].value[]' | sed 's/^0x//' | tr -d '\n'
}

write_meta() {
    local pin="$1" state_id="$2" generation="$3" expected
    local -a bytes
    expected=$(expected_meta_hex "$state_id" "$generation")
    hex_to_args "$expected" bytes
    bpftool map update pinned "$pin" key hex 00 00 00 00 value hex "${bytes[@]}"
}

is_expected_file() {
    local relative="$1" name
    for name in "${map_names[@]}"; do
        [[ "$relative" == "maps/$name" ]] && return 0
    done
    for name in "${link_names[@]}"; do
        [[ "$relative" == "links/$name" ]] && return 0
    done
    return 1
}

validate_inventory() {
    local pin_root="$1" require_full="$2" relative name
    [[ -d "$pin_root" ]] || return 0
    while IFS= read -r relative; do
        is_expected_file "$relative" || fail UNKNOWN "unexpected object under recorded pin root: $relative" 43
    done < <(find "$pin_root" -mindepth 1 -maxdepth 2 -type f -printf '%P\n' | sort)
    while IFS= read -r relative; do
        [[ "$relative" == maps || "$relative" == links ]] || \
            fail UNKNOWN "unexpected directory under recorded pin root: $relative" 43
    done < <(find "$pin_root" -mindepth 1 -maxdepth 2 -type d -printf '%P\n' | sort)
    if [[ "$require_full" == true ]]; then
        for name in "${map_names[@]}"; do
            [[ -e "$pin_root/maps/$name" ]] || fail INCOMPATIBLE "missing expected map pin: $name" 42
        done
        for name in "${link_names[@]}"; do
            [[ -e "$pin_root/links/$name" ]] || fail INCOMPATIBLE "missing expected link pin: $name" 42
        done
    fi
}

validate_map() {
    local pin="$1" logical="$2" expected_type key_size value_size max_entries flags
    read -r expected_type key_size value_size max_entries flags <<< "${map_contract[$logical]}"
    local info observed
    info=$(bpftool -j map show pinned "$pin") || fail UNKNOWN "cannot inspect map pin $pin" 43
    observed=$(jq -r '[.type,.bytes_key,.bytes_value,.max_entries,.flags] | @tsv' <<< "$info")
    [[ "$observed" == "$expected_type"$'\t'"$key_size"$'\t'"$value_size"$'\t'"$max_entries"$'\t'"$flags" ]] || \
        fail INCOMPATIBLE "map contract mismatch for $logical: $observed" 42
}

validate_maps() {
    local pin_root="$1" name
    for name in "${map_names[@]}"; do
        [[ -e "$pin_root/maps/$name" ]] && validate_map "$pin_root/maps/$name" "$name"
    done
}

validate_meta() {
    local pin_root="$1" state_id="$2" generation="$3" expected observed
    [[ -e "$pin_root/maps/soglia_meta" ]] || fail INCOMPATIBLE 'soglia_meta is absent' 42
    expected=$(expected_meta_hex "$state_id" "$generation")
    observed=$(current_meta_hex "$pin_root/maps/soglia_meta")
    [[ "$observed" == "$expected" ]] || \
        fail UNKNOWN "soglia_meta does not match trusted state identity/generation" 43
}

validate_intent_subset() {
    local record="$1" pin_root="$2" cgroup inode observed expected zero_meta link_count pinned_link_count
    validate_inventory "$pin_root" false
    validate_maps "$pin_root"
    if [[ -e "$pin_root/maps/soglia_meta" ]]; then
        observed=$(current_meta_hex "$pin_root/maps/soglia_meta")
        expected=$(expected_meta_hex "$(jq -r .state_id <<< "$record")" "$(jq -r .generation <<< "$record")")
        printf -v zero_meta '%096d' 0
        [[ "$observed" == "$zero_meta" || "$observed" == "$expected" ]] || \
            fail UNKNOWN 'INTENT metadata is neither unwritten nor bound to the trusted record' 43
    fi
    cgroup=$(jq -r .cgroup_path <<< "$record")
    inode=$(jq -r .cgroup_inode <<< "$record")
    [[ -d "$cgroup" && "$(stat -Lc %i "$cgroup")" == "$inode" ]] || \
        fail UNKNOWN 'INTENT cgroup identity does not match its trusted record' 43
    INTENT_LINK_IDS=$(bpftool -j link show | jq -c --argjson cgid "$inode" \
        '[.[] | select(.type == "cgroup" and .cgroup_id == $cgid) | .id]')
    link_count=$(jq length <<< "$INTENT_LINK_IDS")
    if [[ -d "$pin_root/links" ]]; then
        pinned_link_count=$(find "$pin_root/links" -mindepth 1 -maxdepth 1 -type f | wc -l)
    else
        pinned_link_count=0
    fi
    [[ "$link_count" -eq "$pinned_link_count" ]] || \
        fail UNKNOWN "INTENT cgroup link/pin count mismatch: links=$link_count pins=$pinned_link_count" 43
    if [[ "$link_count" -gt 0 ]]; then
        local direct entry name attach id info type
        direct=$(bpftool -j cgroup show "$cgroup")
        [[ $(jq length <<< "$direct") -eq "$link_count" ]] || \
            fail UNKNOWN 'INTENT direct-program count does not match its links' 43
        while IFS= read -r entry; do
            name=$(jq -r .name <<< "$entry")
            attach=$(jq -r .attach_type <<< "$entry")
            id=$(jq -r .id <<< "$entry")
            [[ -n "${program_attach[$name]:-}" && "${program_attach[$name]}" == "$attach" ]] || \
                fail UNKNOWN "unexpected INTENT program/attach pair: $name/$attach" 43
            info=$(bpftool -j prog show id "$id")
            type=$(jq -r .type <<< "$info")
            [[ "$type" == "${program_type[$name]}" ]] || \
                fail UNKNOWN "unexpected INTENT program type for $name: $type" 43
        done < <(jq -c '.[]' <<< "$direct")
    fi
}

validate_program_pairs() {
    local direct="$1" name expected_attach expected_type id info actual_type tag
    [[ $(jq length <<< "$direct") -eq 6 ]] || fail INCOMPATIBLE 'direct cgroup program count is not six' 42
    for name in "${!program_attach[@]}"; do
        expected_attach=${program_attach[$name]}
        [[ $(jq --arg n "$name" --arg a "$expected_attach" \
            '[.[] | select(.name == $n and .attach_type == $a)] | length' <<< "$direct") -eq 1 ]] || \
            fail INCOMPATIBLE "missing or duplicate program/attach pair: $name/$expected_attach" 42
        id=$(jq -r --arg n "$name" '.[] | select(.name == $n) | .id' <<< "$direct")
        info=$(bpftool -j prog show id "$id") || fail INCOMPATIBLE "program id $id vanished" 42
        actual_type=$(jq -r .type <<< "$info")
        tag=$(jq -r .tag <<< "$info")
        expected_type=${program_type[$name]}
        [[ "$actual_type" == "$expected_type" && "$tag" =~ ^[0-9a-f]{16}$ ]] || \
            fail INCOMPATIBLE "program contract mismatch for $name: type=$actual_type tag=$tag" 42
    done
}

collect_manifest() {
    local cgroup="$1" pin_root="$2" direct all_links inode name info id
    validate_inventory "$pin_root" true
    validate_maps "$pin_root"
    direct=$(bpftool -j cgroup show "$cgroup") || fail INCOMPATIBLE "cannot inspect cgroup $cgroup" 42
    validate_program_pairs "$direct"
    inode=$(stat -Lc %i "$cgroup")
    all_links=$(bpftool -j link show)
    MANIFEST_LINKS=$(jq -c --argjson cgid "$inode" \
        '[.[] | select(.type == "cgroup" and .cgroup_id == $cgid) | {id,type,prog_id,cgroup_id,attach_type}] | sort_by(.attach_type)' \
        <<< "$all_links")
    [[ $(jq length <<< "$MANIFEST_LINKS") -eq 6 ]] || \
        fail INCOMPATIBLE "cgroup link count is not six for inode $inode" 42
    MANIFEST_MAP_IDS='{}'
    for name in "${map_names[@]}"; do
        info=$(bpftool -j map show pinned "$pin_root/maps/$name")
        id=$(jq -r .id <<< "$info")
        MANIFEST_MAP_IDS=$(jq -c --arg n "$name" --argjson id "$id" '. + {($n): $id}' <<< "$MANIFEST_MAP_IDS")
    done
    MANIFEST_PROGRAMS='[]'
    while read -r id name; do
        info=$(bpftool -j prog show id "$id")
        MANIFEST_PROGRAMS=$(jq -c --argjson id "$id" --arg name "$name" \
            --arg attach "${program_attach[$name]}" --arg type "$(jq -r .type <<< "$info")" \
            --arg tag "$(jq -r .tag <<< "$info")" \
            '. + [{id:$id,name:$name,attach_type:$attach,type:$type,tag:$tag}] | sort_by(.name)' \
            <<< "$MANIFEST_PROGRAMS")
    done < <(jq -r '.[] | [.id,.name] | @tsv' <<< "$direct")
    MANIFEST_CGROUP_INODE=$inode
}

validate_record_manifests() {
    local record="$1" cgroup="$2" pin_root="$3"
    collect_manifest "$cgroup" "$pin_root"
    [[ "$(jq -S -c .map_ids <<< "$record")" == "$(jq -S -c . <<< "$MANIFEST_MAP_IDS")" ]] || \
        fail UNKNOWN 'map identities do not match the trusted READY record' 43
    [[ "$(jq -S -c .programs <<< "$record")" == "$(jq -S -c . <<< "$MANIFEST_PROGRAMS")" ]] || \
        fail UNKNOWN 'program identities do not match the trusted READY record' 43
    [[ "$(jq -S -c .links <<< "$record")" == "$(jq -S -c . <<< "$MANIFEST_LINKS")" ]] || \
        fail UNKNOWN 'link identities do not match the trusted READY record' 43
    [[ "$(jq -r .cgroup_inode <<< "$record")" == "$MANIFEST_CGROUP_INODE" ]] || \
        fail UNKNOWN 'cgroup inode does not match the trusted READY record' 43
}

record_field() {
    local record="$1" expression="$2"
    jq -er "$expression" <<< "$record" 2>/dev/null || fail INCOMPATIBLE "missing or invalid record field: $expression" 42
}

read_record() {
    local record_dir="$1"
    cat "$record_dir/$RECORD_NAME" 2>/dev/null || fail UNKNOWN 'ownership record vanished' 43
}

validate_record_header() {
    local record="$1" object_hash="$2" pin_root="$3"
    [[ "$(record_field "$record" .magic)" == "$MAGIC" ]] || fail INCOMPATIBLE 'record magic mismatch' 42
    [[ "$(record_field "$record" .schema_version)" == "$SCHEMA_VERSION" ]] || fail INCOMPATIBLE 'record schema version mismatch' 42
    [[ "$(record_field "$record" .abi_version)" == "$ABI_VERSION" ]] || fail INCOMPATIBLE 'record ABI version mismatch' 42
    [[ "$(record_field "$record" .object_sha256)" == "$object_hash" ]] || fail INCOMPATIBLE 'record BPF object digest mismatch' 42
    [[ "$(record_field "$record" .pin_root)" == "$pin_root" ]] || fail UNKNOWN 'record names a different pin root' 43
    [[ "$(record_field "$record" .state_id)" =~ ^[0-9a-f]{32}$ ]] || fail INCOMPATIBLE 'invalid state id' 42
    [[ "$(record_field "$record" .generation)" =~ ^[1-9][0-9]*$ ]] || fail INCOMPATIBLE 'invalid generation' 42
    local phase
    phase=$(record_field "$record" .phase)
    [[ "$phase" == INTENT || "$phase" == READY ]] || fail INCOMPATIBLE "invalid record phase: $phase" 42
}

ids_absent() {
    local kind="$1" ids="$2" current id
    current=$(bpftool -j "$kind" show)
    while read -r id; do
        [[ $(jq --argjson id "$id" '[.[] | select(.id == $id)] | length' <<< "$current") -eq 0 ]] || \
            fail UNKNOWN "$kind id $id remained after sweep" 43
    done < <(jq -r '.[]' <<< "$ids")
}

sweep_recorded_state() {
    local record="$1" pin_root="$2" phase="$3" name
    local map_ids='[]' link_ids='[]'
    if [[ ! -e "$pin_root" ]]; then
        log 'sweep=recorded_pin_root_already_absent'
        return 0
    fi
    if [[ "$phase" == READY ]]; then
        validate_inventory "$pin_root" true
        validate_maps "$pin_root"
        validate_meta "$pin_root" "$(jq -r .state_id <<< "$record")" "$(jq -r .generation <<< "$record")"
        local old_cgroup
        old_cgroup=$(jq -r .cgroup_path <<< "$record")
        [[ -d "$old_cgroup" ]] || fail UNKNOWN "recorded cgroup path is absent: $old_cgroup" 43
        validate_record_manifests "$record" "$old_cgroup" "$pin_root"
        map_ids=$(jq -c '[.map_ids[]]' <<< "$record")
        link_ids=$(jq -c '[.links[].id]' <<< "$record")
    else
        # The trusted write-ahead record binds the exact cgroup and pin root before creation. Only
        # an expected, kernel-contract-matching subset is removable; any extra remains unknown.
        validate_intent_subset "$record" "$pin_root"
        link_ids=$INTENT_LINK_IDS
        for name in "${map_names[@]}"; do
            if [[ -e "$pin_root/maps/$name" ]]; then
                map_ids=$(jq -c --argjson id "$(bpftool -j map show pinned "$pin_root/maps/$name" | jq .id)" '. + [$id]' <<< "$map_ids")
            fi
        done
    fi
    for name in "${link_names[@]}"; do
        [[ -e "$pin_root/links/$name" ]] && rm -- "$pin_root/links/$name"
    done
    ids_absent link "$link_ids"
    for name in "${map_names[@]}"; do
        [[ -e "$pin_root/maps/$name" ]] && rm -- "$pin_root/maps/$name"
    done
    ids_absent map "$map_ids"
    [[ -d "$pin_root/links" ]] && rmdir "$pin_root/links"
    [[ -d "$pin_root/maps" ]] && rmdir "$pin_root/maps"
    rmdir "$pin_root"
    [[ ! -e "$pin_root" ]] || fail UNKNOWN 'pin root remained after exact sweep' 43
    log "sweep=verified_absent generation=$(jq -r .generation <<< "$record")"
}

build_record() {
    local phase="$1" state_id="$2" generation="$3" pin_root="$4" object_hash="$5"
    local cgroup_path="$6" cgroup_inode="$7" map_ids="$8" programs="$9" links="${10}"
    jq -n -c \
        --arg magic "$MAGIC" --argjson schema "$SCHEMA_VERSION" --argjson abi "$ABI_VERSION" \
        --arg state_id "$state_id" --argjson generation "$generation" --arg phase "$phase" \
        --arg pin_root "$pin_root" --arg object_sha256 "$object_hash" \
        --arg cgroup_path "$cgroup_path" --argjson cgroup_inode "$cgroup_inode" \
        --argjson map_ids "$map_ids" --argjson programs "$programs" --argjson links "$links" \
        '{magic:$magic,schema_version:$schema,abi_version:$abi,state_id:$state_id,
          generation:$generation,phase:$phase,pin_root:$pin_root,object_sha256:$object_sha256,
          cgroup_path:$cgroup_path,cgroup_inode:$cgroup_inode,map_ids:$map_ids,
          programs:$programs,links:$links}'
}

classify_and_recover() {
    local object="$1" pin_root="$2" record_dir="$3" object_hash="$4"
    local record_path="$record_dir/$RECORD_NAME" record phase generation
    NEXT_GENERATION=1
    if [[ ! -e "$record_path" ]]; then
        if [[ -e "$pin_root" ]]; then
            fail UNKNOWN 'bpffs pin root exists without a trusted ownership record' 43
        fi
        local temporary
        while IFS= read -r temporary; do
            rm -- "$temporary"
            log "discarded_unpublished_record=$(basename "$temporary")"
        done < <(find "$record_dir" -maxdepth 1 -type f -name ".$RECORD_NAME.*.tmp" -print)
        log 'classification=FRESH'
        return 0
    fi
    require_root_owned_mode "$record_path" 600 'cgroup-BPF ownership record'
    record=$(read_record "$record_dir")
    validate_record_header "$record" "$object_hash" "$pin_root"
    phase=$(jq -r .phase <<< "$record")
    generation=$(jq -r .generation <<< "$record")
    if [[ -e "$pin_root" ]]; then
        log "classification=KNOWN_COMPATIBLE phase=$phase generation=$generation"
        sweep_recorded_state "$record" "$pin_root" "$phase"
    else
        log "classification=KNOWN_COMPATIBLE_ABSENT phase=$phase generation=$generation"
    fi
    NEXT_GENERATION=$((generation + 1))
}

start_state() {
    local object="$1" cgroup="$2" pin_root="$3" record_dir="$4" ready="$5" loader="$6"
    [[ -f "$object" ]] || fail INCOMPATIBLE "BPF object is absent: $object" 42
    [[ -x "$loader" ]] || fail INCOMPATIBLE "pin loader is absent: $loader" 42
    [[ -d "$cgroup" ]] || fail INCOMPATIBLE "target cgroup is absent: $cgroup" 42
    [[ ! -e "$ready" ]] || fail UNKNOWN "startup ready marker already exists: $ready" 43
    prepare_trust_anchor "$record_dir"
    local object_hash state_id generation intent ready_record loader_status=0
    object_hash=$(sha256sum "$object" | awk '{print $1}')
    classify_and_recover "$object" "$pin_root" "$record_dir" "$object_hash"
    generation=$NEXT_GENERATION
    state_id=$(new_state_id)
    local cgroup_inode
    cgroup_inode=$(stat -Lc %i "$cgroup")
    intent=$(build_record INTENT "$state_id" "$generation" "$pin_root" "$object_hash" \
        "$cgroup" "$cgroup_inode" '{}' '[]' '[]')
    atomic_write "$record_dir" "$RECORD_NAME" "$intent"
    log "record_phase=INTENT state_id=$state_id generation=$generation"
    if [[ "${S13_FAULT_AFTER:-}" == intent ]]; then
        log 'fault_injected=after_INTENT_before_bpffs'
        exit 70
    fi
    internal_ready="$record_dir/.loader.$$.ready"
    "$loader" "$object" "$cgroup" "$pin_root/maps" "$pin_root/links" "$internal_ready" \
        > /dev/null 2>&1 &
    loader_pid=$!
    for _ in $(seq 1 3000); do
        [[ -e "$internal_ready" ]] && break
        kill -0 "$loader_pid" 2>/dev/null || break
        sleep 0.01
    done
    [[ -e "$internal_ready" ]] || {
        wait "$loader_pid" || loader_status=$?
        loader_pid=
        fail INCOMPATIBLE "pin loader failed before internal readiness: status=$loader_status" 42
    }
    if [[ "${S13_FAULT_AFTER:-}" == pins ]]; then
        log 'fault_injected=after_pins_before_meta'
        exit 70
    fi
    write_meta "$pin_root/maps/soglia_meta" "$state_id" "$generation"
    validate_meta "$pin_root" "$state_id" "$generation"
    collect_manifest "$cgroup" "$pin_root"
    if [[ "${S13_FAULT_AFTER:-}" == validated ]]; then
        log 'fault_injected=after_validation_before_READY_record'
        exit 70
    fi
    kill -KILL "$loader_pid"
    wait "$loader_pid" || loader_status=$?
    loader_pid=
    [[ "$loader_status" -eq 137 ]] || fail UNKNOWN "pin loader loss status was $loader_status" 43
    collect_manifest "$cgroup" "$pin_root"
    validate_meta "$pin_root" "$state_id" "$generation"
    ready_record=$(build_record READY "$state_id" "$generation" "$pin_root" "$object_hash" \
        "$cgroup" "$MANIFEST_CGROUP_INODE" "$MANIFEST_MAP_IDS" "$MANIFEST_PROGRAMS" "$MANIFEST_LINKS")
    atomic_write "$record_dir" "$RECORD_NAME" "$ready_record"
    log "record_phase=READY state_id=$state_id generation=$generation"
    if [[ "${S13_FAULT_AFTER:-}" == ready_record ]]; then
        log 'fault_injected=after_READY_record_before_startup_ready'
        exit 70
    fi
    atomic_ready "$ready" "state_id=$state_id generation=$generation"
    log 'startup_ready=true'
}

cleanup_state() {
    local object="$1" pin_root="$2" record_dir="$3"
    prepare_trust_anchor "$record_dir"
    local record_path="$record_dir/$RECORD_NAME" record object_hash phase
    if [[ ! -e "$record_path" && ! -e "$pin_root" ]]; then
        log 'cleanup=already_absent'
        return 0
    fi
    [[ -e "$record_path" ]] || fail UNKNOWN 'cleanup refuses pin root without trusted record' 43
    object_hash=$(sha256sum "$object" | awk '{print $1}')
    record=$(read_record "$record_dir")
    validate_record_header "$record" "$object_hash" "$pin_root"
    phase=$(jq -r .phase <<< "$record")
    sweep_recorded_state "$record" "$pin_root" "$phase"
    rm -- "$record_path"
    sync -d "$record_dir"
    log 'cleanup=OWNED_STATE_REMOVED'
}

usage() {
    echo "usage: $0 start OBJECT CGROUP PIN_ROOT RECORD_DIR READY LOADER" >&2
    echo "       $0 cleanup OBJECT PIN_ROOT RECORD_DIR" >&2
    exit 64
}

[[ $# -ge 1 ]] || usage
command=$1
shift
case "$command" in
    start)
        [[ $# -eq 6 ]] || usage
        start_state "$@"
        ;;
    cleanup)
        [[ $# -eq 3 ]] || usage
        cleanup_state "$@"
        ;;
    *) usage ;;
esac
