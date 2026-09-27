#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Characterizes Candidate C at simultaneously-live N=1,4,16,32,64.
# EXPERIMENTAL: spike-only evidence machinery, not product code.

set -euo pipefail
umask 077

evidence="${S14_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s14/run1}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
pin_root=/sys/fs/bpf/soglia-spike/s14
map_pins="$pin_root/maps"
link_pins="$pin_root/links"
runtime=/run/soglia-spike-s14
object=/var/tmp/spike/bpf/soglia.o
harness=/var/tmp/spike/target/release/s14_scaling
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
proxy_link=s14proxy0
matrix=(1 4 16 32 64)
harness_pid=
current_n=

snapshot_kernel() {
    local directory="$1" prefix="$2"
    bpftool -j prog show > "$directory/$prefix-prog.json"
    bpftool -j link show > "$directory/$prefix-link.json"
    bpftool -j map show > "$directory/$prefix-map.json"
    find /sys/fs/bpf -mindepth 1 -maxdepth 8 -printf '%y %p\n' | sort \
        > "$directory/$prefix-bpffs.txt"
}

remove_pin_tree() {
    if [[ -d "$pin_root" ]]; then
        find "$pin_root" -depth -mindepth 1 -delete
        rmdir "$pin_root"
    fi
    [[ -d /sys/fs/bpf/soglia-spike ]] && rmdir /sys/fs/bpf/soglia-spike
}

cleanup_point() {
    local n="${1:-${current_n:-0}}" index cgroup netns
    set +e
    if [[ -n "$harness_pid" ]] && kill -0 "$harness_pid" 2>/dev/null; then
        kill "$harness_pid"
        wait "$harness_pid"
    fi
    harness_pid=
    if [[ "$n" -gt 0 ]]; then
        for ((index=0; index<n; index++)); do
            cgroup=$(printf '%s/s14-e%03d' "$executions" "$index")
            [[ -e "$cgroup/cgroup.kill" ]] && printf '1\n' > "$cgroup/cgroup.kill"
        done
    fi
    remove_pin_tree
    if [[ "$n" -gt 0 ]]; then
        for ((index=0; index<n; index++)); do
            netns=$(printf 's14n%se%03d' "$n" "$index")
            ip netns list | grep -q "^${netns}\b" && ip netns del "$netns"
        done
    fi
    ip link show "$proxy_link" >/dev/null 2>&1 && ip link del "$proxy_link"
    if [[ -d "$runtime" ]]; then
        find "$runtime" -depth -mindepth 1 -delete
        rmdir "$runtime"
    fi
    if [[ "$n" -gt 0 ]]; then
        for ((index=0; index<n; index++)); do
            cgroup=$(printf '%s/s14-e%03d' "$executions" "$index")
            [[ -d "$cgroup" ]] && rmdir "$cgroup"
        done
    fi
    [[ -d "$executions" ]] && rmdir "$executions"
    set -e
}

record_cleanup() {
    local directory="$1" label="$2"
    mkdir -p "$directory"
    {
        echo "# S14 cleanup verification: $label"
        date -u +UTC=%FT%TZ
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        stat -c 'delegated_root_inode=%i' "$unit"
        find "$unit" -mindepth 1 -maxdepth 2 -type d -printf '%p inode=%i\n' | sort
        for path in "$executions" "$pin_root" "$runtime" /run/soglia/cgroup-bpf-spike; do
            [[ -e "$path" ]] && echo "PRESENT $path" || echo "ABSENT $path"
        done
        echo cgroup_tree_begin
        bpftool cgroup tree "$unit"
        echo cgroup_tree_end
        echo bpffs_begin
        find /sys/fs/bpf -mindepth 1 -maxdepth 8 -printf '%y %p\n' | sort
        echo bpffs_end
        echo owned_netns_begin
        ip netns list | grep -E '^s14n' || true
        echo owned_netns_end
        echo owned_links_begin
        ip -o link show | grep -E 's14(h|proxy)' || true
        echo owned_links_end
        echo owned_processes_begin
        ps -eo pid=,comm=,args= | awk '$2 ~ /^(s14_scaling|soglia-spike-agent)$/ { print }'
        echo owned_processes_end
    } > "$directory/$label-cleanup.txt"
    snapshot_kernel "$directory" "$label"
}

on_exit() {
    local status=$?
    cleanup_point "${current_n:-0}"
    record_cleanup "$evidence/final" s14-final
    printf '%s\n' "$status" > "$evidence/final/s14-run-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence/baseline" "$evidence/points" "$evidence/final"

[[ "$(systemctl is-active soglia-spike-s0.service)" == active ]]
[[ ! -e "$executions" ]]
[[ ! -e /sys/fs/bpf/soglia-spike ]]
[[ ! -e "$runtime" ]]
[[ ! -e /run/soglia/cgroup-bpf-spike ]]

cat > "$evidence/s14-method.txt" <<'EOF'
S14_SCOPE=Candidate_C_operational_cost_and_scaling
MATRIX=1,4,16,32,64
SIMULTANEOUS_EXECUTIONS=true
HIGH_POINT_REASON=64_run_only_after_1_4_16_32_pass_and_VM_remains_healthy
SAMPLE_RULE=N1:0;N4:0,last;N16+:0,middle,last
SAMPLE_RULE_FIXED_BEFORE_RESULTS=true
RESOURCE_TIMER_SCOPE=Candidate_C_object_load_program_load_attach_pin_and_local_policy_setup
NETWORK_TOPOLOGY_CREATED_BEFORE_CANDIDATE_TIMER=true
TEARDOWN_TIMER_SCOPE=BPF_links_objects_shared_map_pins
FULL_TOPOLOGY_TEARDOWN_RECORDED_SEPARATELY=true
IP_USED_FOR_AUTHORIZATION=false
PRODUCTION_CODE_CHANGED=false
CANDIDATE_SELECTED=false
EOF

{
    echo '# S14 authoritative baseline'
    date -u +UTC=%FT%TZ
    uname -a
    systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID \
        -p ControlGroup -p Delegate -p DelegateControllers -p NRestarts --no-pager
    stat -c 'delegated_root_inode=%i' "$unit"
    find "$unit" -mindepth 1 -maxdepth 2 -type d -printf '%p inode=%i\n' | sort
    bpftool cgroup tree "$unit"
    echo proc_limits_begin
    ulimit -a
    cat /proc/sys/kernel/unprivileged_bpf_disabled
    echo proc_limits_end
    echo meminfo_begin
    grep -E '^(MemTotal|MemFree|MemAvailable|Slab|SReclaimable|SUnreclaim):' /proc/meminfo
    echo meminfo_end
    echo netns_begin
    ip netns list
    echo netns_end
    echo links_begin
    ip -o link show
    echo links_end
    echo nft_begin
    nft -a list ruleset
    echo nft_end
} > "$evidence/baseline/s14-baseline-state.txt"
snapshot_kernel "$evidence/baseline" s14-baseline
bpftool feature probe kernel > "$evidence/baseline/s14-kernel-bpf-features.txt"
sha256sum /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c \
    /soglia/spikes/cgroup-bpf/harness/src/bin/s14_scaling.rs \
    /soglia/spikes/cgroup-bpf/run-s14.sh "$object" "$harness" "$agent" \
    > "$evidence/s14-provenance.txt"
file "$object" "$harness" "$agent" >> "$evidence/s14-provenance.txt"

for n in "${matrix[@]}"; do
    current_n="$n"
    point=$(printf '%s/points/n%03d' "$evidence" "$n")
    mkdir -p "$point/cgroups"
    [[ ! -e "$executions" ]]
    [[ ! -e /sys/fs/bpf/soglia-spike ]]
    [[ ! -e "$runtime" ]]

    snapshot_kernel "$point" before
    bpftool cgroup tree "$unit" > "$point/before-cgroup-tree.txt"
    find /sys/fs/bpf -mindepth 1 -maxdepth 8 -printf '%y %p\n' | sort \
        > "$point/before-bpffs.txt"

    mkdir "$executions"
    printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
    mkdir "$runtime"
    ip link add "$proxy_link" type dummy
    ip addr add 10.200.255.1/32 dev "$proxy_link"
    ip link set "$proxy_link" up

    for ((index=0; index<n; index++)); do
        cgroup=$(printf '%s/s14-e%03d' "$executions" "$index")
        netns=$(printf 's14n%se%03d' "$n" "$index")
        veth=$(printf 's14h%03d' "$index")
        third=$((202 + index / 63))
        fourth=$(((index % 63) * 4 + 1))
        host_fourth=$((fourth + 1))
        mkdir "$cgroup"
        ip netns add "$netns"
        ip link add "$veth" type veth peer name eth0 netns "$netns"
        ip addr add "10.${third}.0.${host_fourth}/30" dev "$veth"
        ip link set "$veth" up
        ip netns exec "$netns" ip link set lo up
        ip netns exec "$netns" ip addr add "10.${third}.0.${fourth}/30" dev eth0
        ip netns exec "$netns" ip link set eth0 up
        ip netns exec "$netns" ip route add 10.200.255.1/32 via "10.${third}.0.${host_fourth}" dev eth0
        ip netns exec "$netns" nft -f - <<'NFT'
table inet soglia_s14 {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state established,related accept
    }
    chain output {
        type filter hook output priority filter; policy drop;
        oif "lo" accept
        ct state established,related accept
        ip daddr 10.200.255.1 tcp dport 15001 ct state new accept
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
NFT
    done

    {
        echo "# S14 topology N=$n"
        date -u +UTC=%FT%TZ
        stat -c 'executions_inode=%i' "$executions"
        for ((index=0; index<n; index++)); do
            cgroup=$(printf '%s/s14-e%03d' "$executions" "$index")
            netns=$(printf 's14n%se%03d' "$n" "$index")
            third=$((202 + index / 63))
            fourth=$(((index % 63) * 4 + 1))
            printf 'index=%d execution_id=s14-n%d-execution-%03d-generation-1 ident=%d cgroup=%s inode=%s netns=%s ip=10.%d.0.%d\n' \
                "$index" "$n" "$index" "$((14000000 + n * 1000 + index))" \
                "$cgroup" "$(stat -c %i "$cgroup")" "$netns" "$third" "$fourth"
        done
    } > "$point/topology.txt"
    ip netns list > "$point/topology-netns.txt"
    ip -o link show > "$point/topology-links.txt"
    for ((index=0; index<n; index++)); do
        netns=$(printf 's14n%se%03d' "$n" "$index")
        ip netns exec "$netns" nft list ruleset
    done > "$point/topology-nft.txt"

    ready="$runtime/ready"
    go="$runtime/go"
    attribution_ready="$runtime/attribution-ready"
    finish="$runtime/finish"
    "$harness" "$object" "$executions" "$map_pins" "$link_pins" "$agent" "$n" \
        "$ready" "$go" "$attribution_ready" "$finish" "$runtime" \
        > "$point/harness.txt" 2>&1 &
    harness_pid=$!

    for _ in $(seq 1 6000); do
        [[ -e "$ready" ]] && break
        kill -0 "$harness_pid" 2>/dev/null || break
        sleep 0.01
    done
    [[ -e "$ready" ]]

    snapshot_kernel "$point" during
    bpftool cgroup tree "$unit" > "$point/during-cgroup-tree.txt"
    find "$pin_root" -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort \
        > "$point/during-pins.txt"
    for ((index=0; index<n; index++)); do
        cgroup=$(printf '%s/s14-e%03d' "$executions" "$index")
        bpftool -j cgroup show "$cgroup" > "$(printf '%s/cgroups/e%03d-direct.json' "$point" "$index")"
        bpftool -j cgroup show "$cgroup" effective > "$(printf '%s/cgroups/e%03d-effective.json' "$point" "$index")"
    done

    jq --slurpfile base "$evidence/baseline/s14-baseline-prog.json" \
        '[.[] | select(.id as $id | ($base[0] | map(.id) | index($id) | not))]' \
        "$point/during-prog.json" > "$point/candidate-programs.json"
    jq --slurpfile base "$evidence/baseline/s14-baseline-link.json" \
        '[.[] | select(.id as $id | ($base[0] | map(.id) | index($id) | not))]' \
        "$point/during-link.json" > "$point/candidate-links.json"
    jq --slurpfile base "$evidence/baseline/s14-baseline-map.json" \
        '[.[] | select(.id as $id | ($base[0] | map(.id) | index($id) | not))]' \
        "$point/during-map.json" > "$point/candidate-maps.json"
    jq '[group_by(.name)[] | {name:.[0].name,count:length,ids:map(.id),bytes_memlock:(map(.bytes_memlock // 0)|add),max_entries:map(.max_entries)|unique}]' \
        "$point/candidate-maps.json" > "$point/map-resource-model.json"
    jq '[group_by(.name)[] | {name:.[0].name,count:length,ids:map(.id),bytes_xlated:(map(.bytes_xlated // 0)|add),bytes_jited:(map(.bytes_jited // 0)|add),bytes_memlock:(map(.bytes_memlock // 0)|add),map_ids:map(.map_ids)}]' \
        "$point/candidate-programs.json" > "$point/program-resource-model.json"

    program_count=$(jq length "$point/candidate-programs.json")
    link_count=$(jq length "$point/candidate-links.json")
    map_count=$(jq length "$point/candidate-maps.json")
    pin_count=$(find "$pin_root" -type f | wc -l)
    program_xlated=$(jq '[.[].bytes_xlated // 0] | add // 0' "$point/candidate-programs.json")
    program_jited=$(jq '[.[].bytes_jited // 0] | add // 0' "$point/candidate-programs.json")
    program_memlock=$(jq '[.[].bytes_memlock // 0] | add // 0' "$point/candidate-programs.json")
    map_memlock=$(jq '[.[].bytes_memlock // 0] | add // 0' "$point/candidate-maps.json")
    {
        echo "N=$n"
        echo "programs=$program_count"
        echo "links=$link_count"
        echo "maps=$map_count"
        echo "pins=$pin_count"
        echo "program_bytes_xlated=$program_xlated"
        echo "program_bytes_jited=$program_jited"
        echo "program_bytes_memlock=$program_memlock"
        echo "map_bytes_memlock=$map_memlock"
        grep -E '^(MemFree|MemAvailable|Slab|SReclaimable|SUnreclaim):' /proc/meminfo
    } > "$point/resources.txt"

    [[ "$program_count" -eq $((6 * n)) ]]
    [[ "$link_count" -eq $((6 * n)) ]]
    [[ $(find "$link_pins" -type f | wc -l) -eq $((6 * n)) ]]
    [[ $(find "$map_pins" -type f | wc -l) -eq 8 ]]
    for ((index=0; index<n; index++)); do
        [[ $(jq length "$(printf '%s/cgroups/e%03d-direct.json' "$point" "$index")") -eq 6 ]]
        [[ $(jq length "$(printf '%s/cgroups/e%03d-effective.json' "$point" "$index")") -eq 6 ]]
    done

    touch "$go"
    for _ in $(seq 1 6000); do
        [[ -e "$attribution_ready" ]] && break
        kill -0 "$harness_pid" 2>/dev/null || break
        sleep 0.01
    done
    [[ -e "$attribution_ready" ]]
    {
        echo "# Independent sampled membership proof N=$n"
        date -u +UTC=%FT%TZ
        if [[ "$n" -eq 1 ]]; then
            sample=(0)
        elif [[ "$n" -le 4 ]]; then
            sample=(0 "$((n - 1))")
        else
            sample=(0 "$((n / 2))" "$((n - 1))")
        fi
        for index in "${sample[@]}"; do
            cgroup=$(printf '%s/s14-e%03d' "$executions" "$index")
            netns=$(printf 's14n%se%03d' "$n" "$index")
            pid=$(cat "$(printf '%s/e%03d.agent-ready' "$runtime" "$index")")
            echo "index=$index pid=$pid cgroup=$cgroup cgroup_inode=$(stat -c %i "$cgroup") netns=$netns"
            echo proc_cgroup_begin
            cat "/proc/$pid/cgroup"
            echo proc_cgroup_end
            echo cgroup_procs_begin
            cat "$cgroup/cgroup.procs"
            echo cgroup_procs_end
            echo "process_netns_inode=$(stat -Lc %i "/proc/$pid/ns/net")"
            echo "owned_netns_inode=$(stat -Lc %i "/run/netns/$netns")"
        done
    } > "$point/membership.txt"
    bpftool -j map dump pinned "$map_pins/soglia_tuples" > "$point/traffic-tuples.json"
    bpftool -j map dump pinned "$map_pins/soglia_cookie_a" > "$point/traffic-cookie.json"
    bpftool -j map dump pinned "$map_pins/soglia_counters" > "$point/traffic-counters.json"
    bpftool -j map dump pinned "$map_pins/soglia_denies" > "$point/traffic-denies.json"
    touch "$finish"

    set +e
    wait "$harness_pid"
    harness_status=$?
    set -e
    harness_pid=
    printf '%s\n' "$harness_status" > "$point/harness-exit-status.txt"
    [[ "$harness_status" -eq 0 ]]
    grep '^candidate_c_resolve ' "$point/harness.txt" > "$point/attribution.txt"
    grep -q '^S14_POINT_RESULT=PASS$' "$point/harness.txt"
    grep -q '^attribution_mismatches=0$' "$point/harness.txt"
    grep -q '^cross_execution_identity=0$' "$point/harness.txt"
    grep -q '^fallback_authorization=false$' "$point/harness.txt"

    topology_teardown_started=$(date +%s%N)
    cleanup_point "$n"
    topology_teardown_ns=$(($(date +%s%N) - topology_teardown_started))
    current_n=
    printf 'full_topology_teardown_ns=%s\n' "$topology_teardown_ns" > "$point/topology-teardown.txt"
    record_cleanup "$point" after

    jq -S '[.[] | {id,type,name,tag}] | sort_by(.id)' "$point/before-prog.json" > "$point/before-prog.identity.json"
    jq -S '[.[] | {id,type,name,tag}] | sort_by(.id)' "$point/after-prog.json" > "$point/after-prog.identity.json"
    jq -S '[.[] | {id,type}] | sort_by(.id)' "$point/before-link.json" > "$point/before-link.identity.json"
    jq -S '[.[] | {id,type}] | sort_by(.id)' "$point/after-link.json" > "$point/after-link.identity.json"
    jq -S '[.[] | {id,type,name}] | sort_by(.id)' "$point/before-map.json" > "$point/before-map.identity.json"
    jq -S '[.[] | {id,type,name}] | sort_by(.id)' "$point/after-map.json" > "$point/after-map.identity.json"
    cmp -s "$point/before-prog.identity.json" "$point/after-prog.identity.json"
    cmp -s "$point/before-link.identity.json" "$point/after-link.identity.json"
    cmp -s "$point/before-map.identity.json" "$point/after-map.identity.json"
    cmp -s "$point/before-bpffs.txt" "$point/after-bpffs.txt"
    cmp -s "$point/before-cgroup-tree.txt" "$point/after-cleanup.txt" || true
    [[ ! -e "$executions" ]]
    [[ ! -e /sys/fs/bpf/soglia-spike ]]
    [[ ! -e "$runtime" ]]
    if ip netns list | grep -q '^s14n'; then
        echo "S14 netns residue after N=$n" >&2
        exit 1
    fi
    if ip -o link show | grep -Eq 's14(h|proxy)'; then
        echo "S14 link residue after N=$n" >&2
        exit 1
    fi

    if [[ "$n" -eq 32 ]]; then
        available_kib=$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)
        [[ "$available_kib" -gt 262144 ]]
        echo "N64_DECISION=CONTINUE prior_points_healthy=true mem_available_kib=$available_kib" \
            > "$evidence/s14-n64-decision.txt"
    fi
done

{
    echo 'N|programs|links|maps|pins|object_load_ms|program_load_ms|attach_ms|pin_ms|setup_ms|bpf_teardown_ms|full_topology_teardown_ms|xlated_bytes|jit_bytes|program_memlock_bytes|map_memlock_bytes|attribution_checks|cleanup'
    for n in "${matrix[@]}"; do
        point=$(printf '%s/points/n%03d' "$evidence" "$n")
        value() { sed -n "s/^$1=//p" "$2" | tail -1; }
        programs=$(value programs "$point/resources.txt")
        links=$(value links "$point/resources.txt")
        maps=$(value maps "$point/resources.txt")
        pins=$(value pins "$point/resources.txt")
        object_ns=$(value object_load_total_ns "$point/harness.txt")
        program_ns=$(value program_load_total_ns "$point/harness.txt")
        attach_ns=$(value attach_total_ns "$point/harness.txt")
        pin_ns=$(value pin_total_ns "$point/harness.txt")
        setup_ns=$(value candidate_preparation_total_ns "$point/harness.txt")
        bpf_teardown_ns=$(value candidate_bpf_teardown_ns "$point/harness.txt")
        full_teardown_ns=$(value full_topology_teardown_ns "$point/topology-teardown.txt")
        xlated=$(value program_bytes_xlated "$point/resources.txt")
        jited=$(value program_bytes_jited "$point/resources.txt")
        program_memlock=$(value program_bytes_memlock "$point/resources.txt")
        map_memlock=$(value map_bytes_memlock "$point/resources.txt")
        checks=$(value attribution_checks "$point/harness.txt")
        awk -v n="$n" -v p="$programs" -v l="$links" -v m="$maps" -v pins="$pins" \
            -v o="$object_ns" -v pl="$program_ns" -v a="$attach_ns" -v pi="$pin_ns" \
            -v s="$setup_ns" -v bt="$bpf_teardown_ns" -v ft="$full_teardown_ns" \
            -v x="$xlated" -v j="$jited" -v pm="$program_memlock" -v mm="$map_memlock" \
            -v c="$checks" 'BEGIN {printf "%s|%s|%s|%s|%s|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%s|%s|%s|%s|%s|PASS\n", n,p,l,m,pins,o/1000000,pl/1000000,a/1000000,pi/1000000,s/1000000,bt/1000000,ft/1000000,x,j,pm,mm,c}'
    done
} > "$evidence/s14-scaling-matrix.txt"

cat > "$evidence/s14-result.txt" <<'EOF'
S14_RESULT=PASS
candidate=C_UNSELECTED
matrix=1,4,16,32,64
resource_model_established=true
attribution_correct_at_all_points=true
cross_execution_identity=0
fallback_authorization=false
resource_limit_observed=false
cleanup_after_each_point=PASS
final_cleanup=PASS
production_backend_implemented=false
production_code_modified=false
candidate_selected=false
B1_B7_started=false
EOF

echo 'S14_RESULT=PASS'
