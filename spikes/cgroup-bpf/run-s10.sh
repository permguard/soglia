#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# S10: ancestor destination rewrite and nft final-barrier hard gate.

set -euo pipefail

evidence="${S10_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s10/run1}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
execution="$executions/s10-e1"
netns=soglia-s10-e1
host_veth=sgh-s10e1
proxy_link=soglia-proxy0
host_table=soglia_spike_s10
map_pins=/sys/fs/bpf/soglia-spike/s10/maps
link_pins=/sys/fs/bpf/soglia-spike/s10/links
foreign_root=/sys/fs/bpf/soglia-foreign-s10
foreign_object=/var/tmp/spike/bpf/foreign-s10.o
control_object=/var/tmp/spike/bpf/soglia-direct-control.o
normal_object=/var/tmp/spike/bpf/soglia-diag.o
harness=/var/tmp/spike/target/release/s10_rewrite
foreign_reader=/var/tmp/spike/target/release/foreign_trace
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
ready=/run/soglia-spike-s10.ready
go=/run/soglia-spike-s10.go
membership_ready=/run/soglia-spike-s10-membership.ready
membership_captured=/run/soglia-spike-s10-membership.captured
case_a_observed=/run/soglia-spike-s10-case-a.observed
case_b_go=/run/soglia-spike-s10-case-b.go
case_b_observed=/run/soglia-spike-s10-case-b.observed
nft_restored=/run/soglia-spike-s10-nft.restored
normal_ready=/run/soglia-spike-s10-normal.ready
normal_go=/run/soglia-spike-s10-normal.go
harness_pid=
foreign_trace_pid=
foreign_attached=false
exposure_active=false
exposure_handle=

markers=(
    "$ready" "$go" "$membership_ready" "$membership_captured"
    "$case_a_observed" "$case_b_go" "$case_b_observed" "$nft_restored"
    "$normal_ready" "$normal_go" /run/soglia-spike-s10-host.ready
    /run/soglia-spike-s10-agent-a.ready /run/soglia-spike-s10-agent-a.go
    /run/soglia-spike-s10-agent-b.ready /run/soglia-spike-s10-agent-b.go
    /run/soglia-spike-s10-agent-c.ready /run/soglia-spike-s10-agent-c.go
)

wait_marker() {
    local marker="$1"
    for _ in $(seq 1 5000); do
        [[ -e "$marker" ]] && return 0
        if [[ -n "$harness_pid" ]] && ! kill -0 "$harness_pid" 2>/dev/null; then
            wait "$harness_pid"
            return 1
        fi
        sleep 0.01
    done
    echo "timed out waiting for $marker" >&2
    return 1
}

observe_packets() {
    ip netns exec "$netns" nft -a list chain inet soglia output |
        sed -n '/comment "s10-rewrite-observe"/s/.*counter packets \([0-9][0-9]*\).*/\1/p'
}

restore_exposure() {
    if [[ "$exposure_active" == true ]] && ip netns list | grep -q "^$netns\b"; then
        if [[ -z "$exposure_handle" ]]; then
            exposure_handle=$(ip netns exec "$netns" nft -a list chain inet soglia output |
                sed -n '/comment "s10-rewrite-exposure"/s/.*# handle \([0-9][0-9]*\).*/\1/p' |
                head -n 1)
        fi
        if [[ -n "$exposure_handle" ]]; then
            ip netns exec "$netns" nft delete rule inet soglia output handle "$exposure_handle"
        fi
        exposure_active=false
    fi
}

stop_foreign_trace() {
    if [[ -n "$foreign_trace_pid" ]]; then
        if kill -0 "$foreign_trace_pid" 2>/dev/null; then
            kill -TERM "$foreign_trace_pid" 2>/dev/null || true
        fi
        wait "$foreign_trace_pid" 2>/dev/null || true
    fi
    foreign_trace_pid=
}

cleanup_owned() {
    set +e
    restore_exposure
    if [[ -n "$harness_pid" ]] && kill -0 "$harness_pid" 2>/dev/null; then
        kill "$harness_pid"
        wait "$harness_pid"
    fi
    harness_pid=
    if [[ -e "$execution/cgroup.kill" ]]; then
        printf '1\n' > "$execution/cgroup.kill"
        for _ in $(seq 1 100); do
            [[ ! -s "$execution/cgroup.procs" ]] && break
            sleep 0.01
        done
    fi
    stop_foreign_trace
    if [[ "$foreign_attached" == true ]] && [[ -d "$executions" ]] && [[ -e "$foreign_root/foreign_rewrite" ]]; then
        bpftool cgroup detach "$executions" cgroup_inet4_connect pinned "$foreign_root/foreign_rewrite" || true
        foreign_attached=false
    fi
    for phase in control normal; do
        for pin in sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops; do
            [[ -e "$link_pins/$phase/$pin" ]] && rm "$link_pins/$phase/$pin"
        done
        for pin in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag soglia_staging; do
            [[ -e "$map_pins/$phase/$pin" ]] && rm "$map_pins/$phase/$pin"
        done
        rmdir "$link_pins/$phase" "$map_pins/$phase" 2>/dev/null
    done
    rmdir "$link_pins" "$map_pins" /sys/fs/bpf/soglia-spike/s10 /sys/fs/bpf/soglia-spike 2>/dev/null
    if [[ -d "$foreign_root" ]]; then
        for pin in "$foreign_root"/*; do
            [[ -e "$pin" ]] && rm "$pin"
        done
        rmdir "$foreign_root" 2>/dev/null
    fi
    ip link show "$host_veth" >/dev/null 2>&1 && ip link del "$host_veth"
    ip netns list | grep -q "^$netns\b" && ip netns del "$netns"
    ip link show "$proxy_link" >/dev/null 2>&1 && ip link del "$proxy_link"
    nft list table inet "$host_table" >/dev/null 2>&1 && nft delete table inet "$host_table"
    for marker in "${markers[@]}"; do rm -f "$marker"; done
    [[ -d "$execution" ]] && rmdir "$execution"
    [[ -d "$executions" ]] && rmdir "$executions"
    set -e
}

record_cleanup() {
    {
        echo "# S10 final cleanup verification"
        date -u +"UTC=%FT%TZ"
        echo "unit_active=$(systemctl is-active soglia-spike-s0.service)"
        for path in "$executions" "$execution" /sys/fs/bpf/soglia-spike "$foreign_root" "/run/netns/$netns"; do
            if [[ -e "$path" ]]; then echo "PRESENT $path"; else echo "ABSENT $path"; fi
        done
        echo "delegated_root_children_begin"
        find "$unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
        echo "delegated_root_children_end"
        echo "cgroup_tree_begin"
        bpftool cgroup tree "$unit"
        echo "cgroup_tree_end"
        echo "bpffs_begin"
        find /sys/fs/bpf -mindepth 1 -maxdepth 5 -print | sort
        echo "bpffs_end"
        echo "netns_begin"
        ip netns list
        echo "netns_end"
        echo "owned_links_begin"
        ip -o link show | grep -E "$host_veth|$proxy_link" || true
        echo "owned_links_end"
        echo "owned_nft_begin"
        nft list tables | grep "$host_table" || true
        echo "owned_nft_end"
        echo "owned_processes_begin"
        pgrep -af '^/var/tmp/spike/target/release/s10_rewrite( |$)|^/var/tmp/spike/target/release/foreign_trace( |$)|^/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent( |$)' || true
        echo "owned_processes_end"
        echo "soglia_foreign_program_count=$(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_") or startswith("foreign_"))] | length')"
        echo "cgroup_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
    } > "$evidence/s10-cleanup.txt"
    bpftool -j prog show > "$evidence/s10-final-prog.json"
    bpftool -j link show > "$evidence/s10-final-link.json"
    bpftool -j map show > "$evidence/s10-final-map.json"
    find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s10-final-bpffs.txt"
    nft -j list ruleset > "$evidence/s10-final-host-nft.json"
    jq 'walk(if type == "object" then del(.packets,.bytes) else . end)' \
        "$evidence/s10-final-host-nft.json" > "$evidence/s10-final-host-nft-structure.json"
}

on_exit() {
    status=$?
    cleanup_owned
    [[ -d "$evidence" ]] && record_cleanup
    [[ -d "$evidence" ]] && echo "$status" > "$evidence/s10-run-exit-status.txt"
    exit "$status"
}
if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence"
trap on_exit EXIT
cleanup_owned

{
    echo "# S10 preflight before owned topology creation"
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
} > "$evidence/s10-preflight.txt"
bpftool -j prog show > "$evidence/s10-baseline-prog.json"
bpftool -j link show > "$evidence/s10-baseline-link.json"
bpftool -j map show > "$evidence/s10-baseline-map.json"
find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s10-baseline-bpffs.txt"
nft -j list ruleset > "$evidence/s10-baseline-host-nft.json"
jq 'walk(if type == "object" then del(.packets,.bytes) else . end)' \
    "$evidence/s10-baseline-host-nft.json" > "$evidence/s10-baseline-host-nft-structure.json"

mkdir "$executions"
printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
mkdir "$execution"
{
    echo "ancestor_cgroup=$executions"
    echo "ancestor_cgroup_inode=$(stat -c %i "$executions")"
    echo "child_cgroup=$execution"
    echo "child_cgroup_inode=$(stat -c %i "$execution")"
    echo "ancestor_cgroup_procs=$(tr '\n' ' ' < "$executions/cgroup.procs")"
    echo "child_cgroup_procs=$(tr '\n' ' ' < "$execution/cgroup.procs")"
} > "$evidence/s10-fresh-cgroups.txt"
bpftool -j cgroup show "$executions" > "$evidence/s10-fresh-ancestor-direct.json"
bpftool -j cgroup show "$execution" > "$evidence/s10-fresh-child-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s10-fresh-child-effective.json"

ip link add "$proxy_link" type dummy
ip addr add 10.200.255.1/32 dev "$proxy_link"
ip link set "$proxy_link" up
ip netns add "$netns"
ip link add "$host_veth" type veth peer name eth0 netns "$netns"
ip addr add 10.201.0.2/30 dev "$host_veth"
ip link set "$host_veth" up
ip netns exec "$netns" ip link set lo up
ip netns exec "$netns" ip addr add 10.201.0.1/30 dev eth0
ip netns exec "$netns" ip link set eth0 up
ip netns exec "$netns" ip route add 10.200.255.1/32 via 10.201.0.2 dev eth0

ip netns exec "$netns" nft -f - <<'NFT'
table inet soglia {
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
        ip daddr 10.201.0.2 tcp dport 16001 counter comment "s10-rewrite-observe"
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
NFT

nft -f - <<'NFT'
table inet soglia_spike_s10 {
    chain input {
        type filter hook input priority filter - 10; policy accept;
        iifname "sgh-s10e1" ip saddr != 10.201.0.1 drop
        iifname "sgh-s10e1" ct state invalid drop
        iifname "sgh-s10e1" ct state new meta l4proto != tcp drop
    }
    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        iifname "sgh-s10e1" drop
        oifname "sgh-s10e1" drop
    }
}
NFT

ip netns exec "$netns" nft -a list ruleset > "$evidence/s10-nft-normal-before.txt"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s10-nft-normal-before.json"
normal_before_packets=$(observe_packets)
[[ "$normal_before_packets" -eq 0 ]]
{
    echo "original_destination=10.200.255.1:15001"
    echo "rewritten_destination=10.201.0.2:16001"
    echo "normal_proxy_exception=10.200.255.1:15001"
    echo "rewritten_destination_policy=counter then output-policy drop"
    echo "observe_packets_before=$normal_before_packets"
    ip -details addr show dev "$proxy_link"
    ip -details addr show dev "$host_veth"
    ip netns exec "$netns" ip -details addr show
    ip netns exec "$netns" ip route show
    echo "namespace_nft_begin"
    ip netns exec "$netns" nft -a list ruleset
    echo "namespace_nft_end"
    echo "host_nft_begin"
    nft -a list table inet "$host_table"
    echo "host_nft_end"
} > "$evidence/s10-topology.txt"

mkdir "$foreign_root"
bpftool prog loadall "$foreign_object" "$foreign_root"
bpftool -j prog show pinned "$foreign_root/foreign_allow" > "$evidence/s10-foreign-allow-not-attached.json"
bpftool -j prog show pinned "$foreign_root/foreign_rewrite" > "$evidence/s10-foreign-rewrite.json"
foreign_id=$(jq -r '.id' "$evidence/s10-foreign-rewrite.json")
foreign_trace_map_id=
for map_id in $(jq -r '.map_ids[]' "$evidence/s10-foreign-rewrite.json"); do
    if [[ "$(bpftool -j map show id "$map_id" | jq -r '.name')" == foreign_trace ]]; then
        foreign_trace_map_id="$map_id"
        break
    fi
done
[[ -n "$foreign_trace_map_id" ]]
bpftool -j map show id "$foreign_trace_map_id" > "$evidence/s10-foreign-trace-map.json"
[[ "$(jq -r '.name' "$evidence/s10-foreign-trace-map.json")" == foreign_trace ]]
bpftool map pin id "$foreign_trace_map_id" "$foreign_root/foreign_trace"
bpftool cgroup attach "$executions" cgroup_inet4_connect pinned "$foreign_root/foreign_rewrite" multi
foreign_attached=true
bpftool -j cgroup show "$executions" > "$evidence/s10-foreign-ancestor-direct.json"
llvm-objdump -s -j .rodata "$foreign_object" > "$evidence/s10-foreign-rodata.txt"
{
    echo "foreign_object=$foreign_object"
    echo "foreign_object_sha256=$(sha256sum "$foreign_object" | awk '{print $1}')"
    echo "foreign_source_sha256=$(sha256sum /soglia/spikes/cgroup-bpf/bpf/foreign.c | awk '{print $1}')"
    echo "foreign_rewrite_id=$foreign_id"
    echo "foreign_rewrite_tag=$(jq -r '.tag' "$evidence/s10-foreign-rewrite.json")"
    echo "foreign_allow_attached=false"
    echo "attach_type=cgroup_inet4_connect"
    echo "attach_mode=legacy_multi"
    echo "configured_original_ip4_native=33540106"
    echo "configured_original_port_host=15001"
    echo "configured_rewrite_ip4_native=33605898"
    echo "configured_rewrite_port_host=16001"
    echo "ancestor_cgroup=$executions"
    echo "ancestor_cgroup_inode=$(stat -c %i "$executions")"
    echo "foreign_trace_map_id=$foreign_trace_map_id"
} > "$evidence/s10-foreign-setup.txt"
"$foreign_reader" "$foreign_root/foreign_trace" 45 > "$evidence/s10-foreign-trace.txt" 2>&1 &
foreign_trace_pid=$!
for _ in $(seq 1 500); do
    grep -q '^reader_ready ' "$evidence/s10-foreign-trace.txt" && break
    kill -0 "$foreign_trace_pid" 2>/dev/null || break
    sleep 0.01
done
grep -q '^reader_ready ' "$evidence/s10-foreign-trace.txt"

{
    echo "# S10 artifact provenance"
    date -u +"UTC=%FT%TZ"
    sha256sum \
        /soglia/spikes/cgroup-bpf/bpf/foreign.c \
        /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c \
        /soglia/spikes/cgroup-bpf/harness/src/bin/s10_rewrite.rs \
        /soglia/spikes/cgroup-bpf/harness/src/bin/foreign_trace.rs \
        /soglia/spikes/cgroup-bpf/run-s10.sh \
        "$foreign_object" "$control_object" "$normal_object" "$harness" "$foreign_reader" "$agent"
    file "$foreign_object" "$control_object" "$normal_object" "$harness" "$foreign_reader" "$agent"
} > "$evidence/s10-provenance.txt"

"$harness" \
    "$control_object" "$normal_object" "$execution" "$map_pins" "$link_pins" \
    "$netns" "$agent" 10001001 "$ready" "$go" "$membership_ready" \
    "$membership_captured" "$case_a_observed" "$case_b_go" "$case_b_observed" \
    "$nft_restored" "$normal_ready" "$normal_go" \
    > "$evidence/s10-harness.txt" 2>&1 &
harness_pid=$!

wait_marker "$ready"
bpftool -j prog show > "$evidence/s10-control-prog.json"
bpftool -j link show > "$evidence/s10-control-link.json"
bpftool -j map show > "$evidence/s10-control-map.json"
bpftool -j cgroup show "$execution" > "$evidence/s10-control-child-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s10-control-child-effective.json"
bpftool -j cgroup show "$executions" > "$evidence/s10-control-ancestor-direct.json"
find /sys/fs/bpf -mindepth 1 -maxdepth 6 -printf '%y %p\n' | sort > "$evidence/s10-control-bpffs.txt"
touch "$go"

wait_marker "$membership_ready"
agent_pid=$(sed -n 's/^actual_agent_pid=//p' "$membership_ready")
{
    echo "# S10 live agent membership before traffic"
    date -u +"UTC=%FT%TZ"
    cat "$membership_ready"
    echo "agent_proc_cgroup_begin"
    cat "/proc/$agent_pid/cgroup"
    echo "agent_proc_cgroup_end"
    echo "target_cgroup_procs_begin"
    cat "$execution/cgroup.procs"
    echo "target_cgroup_procs_end"
    echo "agent_netns_link=$(readlink "/proc/$agent_pid/ns/net")"
    echo "agent_netns_inode=$(stat -Lc %i "/proc/$agent_pid/ns/net")"
    echo "owned_netns_inode=$(stat -Lc %i "/run/netns/$netns")"
    echo "direct_program_count=$(bpftool -j cgroup show "$execution" | jq 'length')"
    echo "effective_program_count=$(bpftool -j cgroup show "$execution" effective | jq 'length')"
} > "$evidence/s10-membership.txt"
touch "$membership_captured"

wait_marker "$case_a_observed"
ip netns exec "$netns" nft -a list ruleset > "$evidence/s10-nft-case-a.txt"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s10-nft-case-a.json"
case_a_packets=$(observe_packets)
[[ "$case_a_packets" -gt "$normal_before_packets" ]]
bpftool -j map dump pinned "$map_pins/control/soglia_diag_entries" > "$evidence/s10-case-a-diag.json"
bpftool -j map dump pinned "$map_pins/control/soglia_counters" > "$evidence/s10-case-a-counters.json"
bpftool -j map dump pinned "$map_pins/control/soglia_denies" > "$evidence/s10-case-a-denies.json"
bpftool -j map dump pinned "$map_pins/control/soglia_port_diag" > "$evidence/s10-case-a-ports.json"

ip netns exec "$netns" nft add rule inet soglia output \
    ip daddr 10.201.0.2 tcp dport 16001 ct state new counter accept \
    comment "s10-rewrite-exposure"
exposure_active=true
exposure_handle=$(ip netns exec "$netns" nft -a list chain inet soglia output |
    sed -n '/comment "s10-rewrite-exposure"/s/.*# handle \([0-9][0-9]*\).*/\1/p')
[[ -n "$exposure_handle" ]]
ip netns exec "$netns" nft -a list ruleset > "$evidence/s10-nft-control-during.txt"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s10-nft-control-during.json"
{
    echo "exposure_handle=$exposure_handle"
    echo "exposure_rule=ip daddr 10.201.0.2 tcp dport 16001 ct state new counter accept comment s10-rewrite-exposure"
    echo "observe_packets_after_case_a=$case_a_packets"
    echo "unrelated_namespace_rules_changed=0"
    echo "host_rules_changed=0"
} > "$evidence/s10-nft-exposure.txt"
touch "$case_b_go"

wait_marker "$case_b_observed"
ip netns exec "$netns" nft -a list ruleset > "$evidence/s10-nft-case-b.txt"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s10-nft-case-b.json"
case_b_packets=$(observe_packets)
[[ "$case_b_packets" -gt "$case_a_packets" ]]
bpftool -j map dump pinned "$map_pins/control/soglia_diag_entries" > "$evidence/s10-case-b-diag.json"
bpftool -j map dump pinned "$map_pins/control/soglia_counters" > "$evidence/s10-case-b-counters.json"
bpftool -j map dump pinned "$map_pins/control/soglia_denies" > "$evidence/s10-case-b-denies.json"
bpftool -j map dump pinned "$map_pins/control/soglia_port_diag" > "$evidence/s10-case-b-ports.json"
restore_exposure
ip netns exec "$netns" nft -a list ruleset > "$evidence/s10-nft-normal-restored.txt"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s10-nft-normal-restored.json"
jq 'walk(if type == "object" then del(.handle,.packets,.bytes) else . end)' \
    "$evidence/s10-nft-normal-before.json" > "$evidence/s10-nft-normal-before-structure.json"
jq 'walk(if type == "object" then del(.handle,.packets,.bytes) else . end)' \
    "$evidence/s10-nft-normal-restored.json" > "$evidence/s10-nft-normal-restored-structure.json"
cmp -s "$evidence/s10-nft-normal-before-structure.json" "$evidence/s10-nft-normal-restored-structure.json"
{
    echo "observe_packets_after_case_a=$case_a_packets"
    echo "observe_packets_after_case_b=$case_b_packets"
    echo "exposure_removed=true"
    echo "normal_ruleset_structure_restored=true"
    sha256sum "$evidence/s10-nft-normal-before-structure.json" "$evidence/s10-nft-normal-restored-structure.json"
} > "$evidence/s10-nft-restoration.txt"
touch "$nft_restored"

wait_marker "$normal_ready"
bpftool -j prog show > "$evidence/s10-normal-prog.json"
bpftool -j link show > "$evidence/s10-normal-link.json"
bpftool -j map show > "$evidence/s10-normal-map.json"
bpftool -j cgroup show "$execution" > "$evidence/s10-normal-child-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s10-normal-child-effective.json"
bpftool -j cgroup show "$executions" > "$evidence/s10-normal-ancestor-direct.json"
touch "$normal_go"

set +e
wait "$harness_pid"
harness_status=$?
set -e
harness_pid=
echo "$harness_status" > "$evidence/s10-harness-exit-status.txt"
[[ "$harness_status" -eq 0 ]]
ip netns exec "$netns" nft -a list ruleset > "$evidence/s10-nft-after-normal-composition.txt"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s10-nft-after-normal-composition.json"
normal_packets=$(observe_packets)
echo "observe_packets_after_normal_composition=$normal_packets" > "$evidence/s10-normal-nft-observation.txt"

stop_foreign_trace
bpftool -j prog show pinned "$foreign_root/foreign_rewrite" > "$evidence/s10-foreign-rewrite-after.json"
bpftool -j cgroup show "$executions" > "$evidence/s10-foreign-ancestor-after.json"
trace_records=$(grep -c '^record .*who=3.*daddr_raw=33540106.*dport=15001.*rewritten=1' "$evidence/s10-foreign-trace.txt" || true)
[[ "$trace_records" -eq 3 ]]
normal_child_port=$(sed -n 's/^normal_ports=\[[^,]*, [^,]*, \([0-9][0-9]*\).*/\1/p' "$evidence/s10-harness.txt")
[[ "$normal_child_port" == 15001 || "$normal_child_port" == 16001 ]]
normal_child_deny=$(sed -n 's/^normal_counters=\[[^,]*, [^,]*, [^,]*, [^,]*, \([0-9][0-9]*\).*/\1/p' "$evidence/s10-harness.txt")

cleanup_owned
record_cleanup
trap - EXIT

cmp -s "$evidence/s10-baseline-prog.json" "$evidence/s10-final-prog.json"
cmp -s "$evidence/s10-baseline-link.json" "$evidence/s10-final-link.json"
cmp -s "$evidence/s10-baseline-map.json" "$evidence/s10-final-map.json"
cmp -s "$evidence/s10-baseline-bpffs.txt" "$evidence/s10-final-bpffs.txt"
cmp -s "$evidence/s10-baseline-host-nft-structure.json" "$evidence/s10-final-host-nft-structure.json"
grep -q '^ABSENT /sys/fs/bpf/soglia-spike$' "$evidence/s10-cleanup.txt"
grep -q '^ABSENT /sys/fs/bpf/soglia-foreign-s10$' "$evidence/s10-cleanup.txt"
grep -q '^soglia_foreign_program_count=0$' "$evidence/s10-cleanup.txt"
grep -q '^cgroup_link_count=0$' "$evidence/s10-cleanup.txt"

if [[ "$normal_child_port" == 15001 ]]; then
    normal_order="child observed original destination; foreign rewrite was observed afterward in this run"
else
    normal_order="foreign rewrite was observed before the child, which observed rewritten destination"
fi
{
    echo "# S10 ancestor destination rewrite / final nft barrier"
    date -u +"UTC=%FT%TZ"
    echo "original_destination=10.200.255.1:15001"
    echo "rewritten_destination=10.201.0.2:16001"
    echo "foreign_rewrite_id=$foreign_id"
    echo "foreign_rewrite_invocations=3"
    echo "foreign_rewrite_records=original 10.200.255.1:15001, rewritten=1"
    echo "case_a=child permissive; rewrite proven; nft post-rewrite counter increased from $normal_before_packets to $case_a_packets; neither listener accepted; connection did not establish"
    echo "case_b=same child and rewrite; only exact nft exposure added; counter increased to $case_b_packets; rewritten listener accepted; original listener did not"
    echo "decisive_enforcer=nft output final-destination barrier"
    echo "normal_child_observed_port=$normal_child_port"
    echo "normal_child_connect4_deny_counter=$normal_child_deny"
    echo "normal_composition_order_observation=$normal_order"
    echo "ordering_basis=child diagnostic context plus foreign ring event chronology; no bpftool list-order inference"
    echo "normal_ruleset_structure_restored=true"
    echo "final_host_nft_structure_equals_baseline=true"
    echo "external_host_nft_counter_churn_ignored=true"
    echo "cleanup_program_set_equals_baseline=true"
    echo "cleanup_link_set_equals_baseline=true"
    echo "cleanup_map_set_equals_baseline=true"
    echo "cleanup_bpffs_equals_baseline=true"
    echo "production_code_modified_by_s10=false"
    echo "candidate_selected=false"
    echo "S10_RESULT=PASS"
} > "$evidence/s10-summary.txt"
echo 0 > "$evidence/s10-run-exit-status.txt"
