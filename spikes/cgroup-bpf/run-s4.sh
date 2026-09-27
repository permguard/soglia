#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Characterizes direct IPv4 cgroup-BPF denial while relaxing one nft rule only.

set -euo pipefail

evidence="${S4_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s4}"
unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
executions="$unit/executions"
execution="$executions/s4-e1"
netns=soglia-s4-e1
host_veth=sgh-s4e1
proxy_link=soglia-proxy0
host_table=soglia_spike_s4
map_pins=/sys/fs/bpf/soglia-spike/s4/maps
link_pins=/sys/fs/bpf/soglia-spike/s4/links
deny_object=/var/tmp/spike/bpf/soglia-diag.o
control_object=/var/tmp/spike/bpf/soglia-direct-control.o
harness=/var/tmp/spike/target/release/s4_direct_deny
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
foreign_object="${S4_FOREIGN_OBJECT:-}"
foreign_root="${S4_FOREIGN_ROOT:-/sys/fs/bpf/soglia-foreign-s4}"
foreign_reader="${S4_FOREIGN_READER:-}"
foreign_attached=false
foreign_trace_pid=
foreign_trace_map_id=
ready=/run/soglia-spike-s4.ready
go=/run/soglia-spike-s4.go
membership_ready=/run/soglia-spike-s4-membership.ready
membership_captured=/run/soglia-spike-s4-membership.captured
phase_b_ready=/run/soglia-spike-s4-phase-b.ready
phase_b_go=/run/soglia-spike-s4-phase-b.go
phase_c_ready=/run/soglia-spike-s4-phase-c.ready
phase_c_go=/run/soglia-spike-s4-phase-c.go
phase_c_observed=/run/soglia-spike-s4-phase-c.observed
nft_restored=/run/soglia-spike-s4-nft.restored
harness_pid=
nft_relaxed=false
nft_rule_handle=

markers=(
    "$ready" "$go" "$membership_ready" "$membership_captured"
    "$phase_b_ready" "$phase_b_go" "$phase_c_ready" "$phase_c_go"
    "$phase_c_observed" "$nft_restored"
    /run/soglia-spike-s4-host.ready
    /run/soglia-spike-s4-agent-a.ready /run/soglia-spike-s4-agent-a.go
    /run/soglia-spike-s4-agent-b.ready /run/soglia-spike-s4-agent-b.go
    /run/soglia-spike-s4-agent-c.ready /run/soglia-spike-s4-agent-c.go
)

wait_marker() {
    local marker="$1"
    for _ in $(seq 1 4000); do
        [[ -e "$marker" ]] && return 0
        if [[ -n "$harness_pid" ]] && ! kill -0 "$harness_pid" 2>/dev/null; then
            if wait "$harness_pid"; then
                echo "harness exited before producing $marker" >&2
                return 1
            else
                return $?
            fi
        fi
        sleep 0.01
    done
    echo "timed out waiting for $marker" >&2
    return 1
}

restore_nft_rule() {
    if [[ "$nft_relaxed" == true ]] && ip netns list | grep -q "^$netns\b"; then
        if [[ -z "$nft_rule_handle" ]]; then
            nft_rule_handle=$(ip netns exec "$netns" nft -a list chain inet soglia output |
                sed -n '/comment "s4-direct-exposure"/s/.*# handle \([0-9][0-9]*\).*/\1/p' |
                head -n 1)
        fi
        if [[ -n "$nft_rule_handle" ]]; then
            ip netns exec "$netns" nft delete rule inet soglia output handle "$nft_rule_handle"
        fi
        nft_relaxed=false
    fi
}

stop_foreign_trace() {
    if [[ -n "$foreign_trace_pid" ]] && kill -0 "$foreign_trace_pid" 2>/dev/null; then
        kill -INT "$foreign_trace_pid" 2>/dev/null || true
        wait "$foreign_trace_pid" 2>/dev/null || true
    fi
    foreign_trace_pid=
}

cleanup_foreign() {
    stop_foreign_trace
    if [[ "$foreign_attached" == true ]] && [[ -d "$executions" ]] && [[ -e "$foreign_root/foreign_allow" ]]; then
        bpftool cgroup detach "$executions" cgroup_inet4_connect pinned "$foreign_root/foreign_allow" || true
        foreign_attached=false
    fi
    if [[ -d "$foreign_root" ]]; then
        for pin in "$foreign_root"/*; do
            [[ -e "$pin" ]] && rm "$pin"
        done
        rmdir "$foreign_root" 2>/dev/null || true
    fi
}

cleanup_owned() {
    set +e
    restore_nft_rule
    if [[ -n "$harness_pid" ]] && kill -0 "$harness_pid" 2>/dev/null; then
        kill "$harness_pid"
        wait "$harness_pid"
    fi
    if [[ -e "$execution/cgroup.kill" ]]; then
        printf '1\n' > "$execution/cgroup.kill"
        for _ in $(seq 1 100); do
            [[ ! -s "$execution/cgroup.procs" ]] && break
            sleep 0.01
        done
    fi
    cleanup_foreign
    ip link show "$host_veth" >/dev/null 2>&1 && ip link del "$host_veth"
    ip netns list | grep -q "^$netns\b" && ip netns del "$netns"
    ip link show "$proxy_link" >/dev/null 2>&1 && ip link del "$proxy_link"
    nft list table inet "$host_table" >/dev/null 2>&1 && nft delete table inet "$host_table"
    for phase in a b c; do
        for pin in sock_create connect4 connect6 sendmsg4 sendmsg6 sock_ops; do
            [[ -e "$link_pins/$phase/$pin" ]] && rm "$link_pins/$phase/$pin"
        done
        for pin in soglia_policy soglia_tuples soglia_cookie_a soglia_sk_b soglia_events soglia_counters soglia_denies soglia_meta soglia_diag_entries soglia_port_diag soglia_staging; do
            [[ -e "$map_pins/$phase/$pin" ]] && rm "$map_pins/$phase/$pin"
        done
        rmdir "$link_pins/$phase" "$map_pins/$phase" 2>/dev/null
    done
    rmdir "$link_pins" "$map_pins" /sys/fs/bpf/soglia-spike/s4 /sys/fs/bpf/soglia-spike 2>/dev/null
    for marker in "${markers[@]}"; do rm -f "$marker"; done
    [[ -d "$execution" ]] && rmdir "$execution"
    [[ -d "$executions" ]] && rmdir "$executions"
}

record_cleanup() {
    {
        echo "# S4 final cleanup verification"
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
        pgrep -af '^/var/tmp/spike/target/release/s4_direct_deny( |$)|^/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent( |$)' || true
        echo "owned_processes_end"
        echo "soglia_foreign_program_count=$(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_") or startswith("foreign_"))] | length')"
        echo "cgroup_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
    } > "$evidence/s4-cleanup.txt"
    bpftool -j prog show > "$evidence/s4-final-prog.json"
    bpftool -j link show > "$evidence/s4-final-link.json"
    bpftool -j map show > "$evidence/s4-final-map.json"
    find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s4-final-bpffs.txt"
}

on_exit() {
    status=$?
    cleanup_owned
    record_cleanup
    echo "$status" > "$evidence/s4-run-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence"
cleanup_owned

{
    echo "# S4 preflight before owned topology creation"
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
} > "$evidence/s4-preflight.txt"
bpftool -j prog show > "$evidence/s4-baseline-prog.json"
bpftool -j link show > "$evidence/s4-baseline-link.json"
bpftool -j map show > "$evidence/s4-baseline-map.json"
find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s4-baseline-bpffs.txt"

mkdir "$executions"
printf '+memory +pids\n' > "$executions/cgroup.subtree_control"
mkdir "$execution"

{
    echo "ancestor_cgroup=$executions"
    echo "ancestor_cgroup_inode=$(stat -c %i "$executions")"
    echo "child_cgroup=$execution"
    echo "child_cgroup_inode=$(stat -c %i "$execution")"
    echo "ancestor_cgroup_procs_begin"
    cat "$executions/cgroup.procs"
    echo "ancestor_cgroup_procs_end"
    echo "child_cgroup_procs_begin"
    cat "$execution/cgroup.procs"
    echo "child_cgroup_procs_end"
} > "$evidence/s4-fresh-cgroups.txt"
bpftool -j cgroup show "$executions" > "$evidence/s4-fresh-ancestor-direct.json"
bpftool -j cgroup show "$execution" > "$evidence/s4-fresh-child-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s4-fresh-child-effective.json"

if [[ -n "$foreign_object" ]]; then
    mkdir "$foreign_root"
    bpftool prog loadall "$foreign_object" "$foreign_root"
    bpftool -j prog show pinned "$foreign_root/foreign_allow" > "$evidence/s4-foreign-allow.json"
    bpftool -j prog show pinned "$foreign_root/foreign_rewrite" > "$evidence/s4-foreign-rewrite-not-attached.json"
    foreign_trace_map_id=$(jq -r '.map_ids[0]' "$evidence/s4-foreign-allow.json")
    if [[ -z "$foreign_trace_map_id" || "$foreign_trace_map_id" == null ]]; then
        echo "foreign_allow did not expose its foreign_trace map id" >&2
        exit 1
    fi
    bpftool -j map show id "$foreign_trace_map_id" > "$evidence/s4-foreign-trace-map.json"
    if [[ "$(jq -r '.name' "$evidence/s4-foreign-trace-map.json")" != foreign_trace ]]; then
        echo "foreign_allow first map is not foreign_trace" >&2
        exit 1
    fi
    bpftool map pin id "$foreign_trace_map_id" "$foreign_root/foreign_trace"
    bpftool cgroup attach "$executions" cgroup_inet4_connect pinned "$foreign_root/foreign_allow" multi
    foreign_attached=true
    bpftool -j cgroup show "$executions" > "$evidence/s4-foreign-ancestor-direct.json"
    {
        echo "foreign_object=$foreign_object"
        echo "foreign_object_sha256=$(sha256sum "$foreign_object" | awk '{print $1}')"
        echo "foreign_source_sha256=$(sha256sum /soglia/spikes/cgroup-bpf/bpf/foreign.c | awk '{print $1}')"
        echo "foreign_allow_pin=$foreign_root/foreign_allow"
        echo "foreign_rewrite_pin=$foreign_root/foreign_rewrite"
        echo "foreign_rewrite_attached=false"
        echo "ancestor_cgroup=$executions"
        echo "ancestor_cgroup_inode=$(stat -c %i "$executions")"
        echo "attach_type=cgroup_inet4_connect"
        echo "attach_mode=legacy_multi"
        echo "foreign_trace_map_id=$foreign_trace_map_id"
        echo "foreign_reader=$foreign_reader"
        echo "foreign_reader_sha256=$(sha256sum "$foreign_reader" | awk '{print $1}')"
        echo "foreign_reader_source_sha256=$(sha256sum /soglia/spikes/cgroup-bpf/harness/src/bin/foreign_trace.rs | awk '{print $1}')"
    } > "$evidence/s4-foreign-setup.txt"
    if [[ -z "$foreign_reader" ]]; then
        echo "S4_FOREIGN_READER is required when S4_FOREIGN_OBJECT is set" >&2
        exit 1
    fi
    "$foreign_reader" "$foreign_root/foreign_trace" 30 \
        > "$evidence/s4-foreign-trace.txt" 2>&1 &
    foreign_trace_pid=$!
    for _ in $(seq 1 500); do
        grep -q '^reader_ready ' "$evidence/s4-foreign-trace.txt" && break
        kill -0 "$foreign_trace_pid" 2>/dev/null || break
        sleep 0.01
    done
    if ! grep -q '^reader_ready ' "$evidence/s4-foreign-trace.txt"; then
        echo "foreign trace reader did not become ready" >&2
        exit 1
    fi
fi

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
    }
    chain forward {
        type filter hook forward priority filter; policy drop;
    }
}
NFT

nft -f - <<'NFT'
table inet soglia_spike_s4 {
    chain input {
        type filter hook input priority filter - 10; policy accept;
        iifname "sgh-s4e1" ip saddr != 10.201.0.1 drop
        iifname "sgh-s4e1" ct state invalid drop
        iifname "sgh-s4e1" ct state new meta l4proto != tcp drop
    }
    chain forward {
        type filter hook forward priority filter - 10; policy accept;
        iifname "sgh-s4e1" drop
        oifname "sgh-s4e1" drop
    }
}
NFT

{
    echo "# S4 fresh topology and nft barrier"
    date -u +"UTC=%FT%TZ"
    echo "execution_id=s4-execution-generation-1"
    echo "execution_cgroup=$execution"
    echo "execution_cgroup_inode=$(stat -c %i "$execution")"
    echo "execution_cgroup_procs=$(tr '\n' ' ' < "$execution/cgroup.procs")"
    echo "owned_netns=$netns"
    echo "owned_netns_inode=$(stat -Lc %i "/run/netns/$netns")"
    echo "normal_nft_barrier=inet/soglia/output policy drop plus sole new-flow exception 10.200.255.1:15001"
    echo "rule_to_relax=add one temporary new-flow exception for 10.201.0.2:16001"
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
} > "$evidence/s4-topology.txt"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s4-nft-before.json"
ip netns exec "$netns" nft -a list ruleset > "$evidence/s4-nft-before.txt"

{
    echo "# S4 artifact provenance"
    date -u +"UTC=%FT%TZ"
    sha256sum \
        /soglia/spikes/cgroup-bpf/bpf/soglia_spike.c \
        /soglia/spikes/cgroup-bpf/harness/src/bin/s4_direct_deny.rs \
        /soglia/spikes/cgroup-bpf/agent/src/main.rs \
        "$deny_object" "$control_object" "$harness" "$agent"
    file "$deny_object" "$control_object" "$harness" "$agent"
} > "$evidence/s4-provenance.txt"

"$harness" \
    "$deny_object" "$control_object" "$execution" "$map_pins" "$link_pins" \
    "$netns" "$agent" 4001001 "$ready" "$go" "$membership_ready" \
    "$membership_captured" "$phase_b_ready" "$phase_b_go" "$phase_c_ready" \
    "$phase_c_go" "$phase_c_observed" "$nft_restored" \
    > "$evidence/s4-harness.txt" 2>&1 &
harness_pid=$!

wait_marker "$ready"
bpftool -j prog show > "$evidence/s4-phase-a-prog.json"
bpftool -j link show > "$evidence/s4-phase-a-link.json"
bpftool -j map show > "$evidence/s4-phase-a-map.json"
bpftool -j cgroup show "$execution" > "$evidence/s4-phase-a-cgroup-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s4-phase-a-cgroup-effective.json"
if [[ -n "$foreign_object" ]]; then
    bpftool -j cgroup show "$executions" > "$evidence/s4-phase-a-ancestor-direct.json"
fi
find /sys/fs/bpf/soglia-spike/s4 -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s4-phase-a-bpffs.txt"
touch "$go"

wait_marker "$membership_ready"
agent_pid=$(sed -n 's/^actual_agent_pid=//p' "$membership_ready")
{
    echo "# S4 live agent membership before any traffic"
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
    echo "six_direct_programs=$(bpftool -j cgroup show "$execution" | jq 'length')"
    echo "six_effective_programs=$(bpftool -j cgroup show "$execution" effective | jq 'length')"
} > "$evidence/s4-membership.txt"
touch "$membership_captured"

wait_marker "$phase_b_ready"
ip netns exec "$netns" nft add rule inet soglia output \
    ip daddr 10.201.0.2 tcp dport 16001 ct state new accept \
    comment "s4-direct-exposure"
nft_relaxed=true
nft_rule_handle=$(ip netns exec "$netns" nft -a list chain inet soglia output |
    sed -n '/comment "s4-direct-exposure"/s/.*# handle \([0-9][0-9]*\).*/\1/p')
if [[ -z "$nft_rule_handle" ]]; then
    echo "could not identify temporary nft rule handle" >&2
    exit 1
fi
ip netns exec "$netns" nft -a list ruleset > "$evidence/s4-nft-during.txt"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s4-nft-during.json"
{
    echo "temporary_rule_handle=$nft_rule_handle"
    echo "temporary_rule=ip daddr 10.201.0.2 tcp dport 16001 ct state new accept comment s4-direct-exposure"
    echo "unrelated_namespace_rules_changed=0"
    echo "host_rules_changed=0"
} > "$evidence/s4-nft-relaxation.txt"
bpftool -j prog show > "$evidence/s4-phase-b-prog.json"
bpftool -j link show > "$evidence/s4-phase-b-link.json"
bpftool -j map show > "$evidence/s4-phase-b-map.json"
bpftool -j cgroup show "$execution" > "$evidence/s4-phase-b-cgroup-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s4-phase-b-cgroup-effective.json"
if [[ -n "$foreign_object" ]]; then
    bpftool -j cgroup show "$executions" > "$evidence/s4-phase-b-ancestor-direct.json"
fi
bpftool -j map dump pinned "$map_pins/b/soglia_diag_entries" > "$evidence/s4-phase-b-before-diag.json"
bpftool -j map dump pinned "$map_pins/b/soglia_counters" > "$evidence/s4-phase-b-before-counters.json"
bpftool -j map dump pinned "$map_pins/b/soglia_denies" > "$evidence/s4-phase-b-before-denies.json"
touch "$phase_b_go"

wait_marker "$phase_c_ready"
bpftool -j prog show > "$evidence/s4-phase-c-prog.json"
bpftool -j link show > "$evidence/s4-phase-c-link.json"
bpftool -j map show > "$evidence/s4-phase-c-map.json"
bpftool -j cgroup show "$execution" > "$evidence/s4-phase-c-cgroup-direct.json"
bpftool -j cgroup show "$execution" effective > "$evidence/s4-phase-c-cgroup-effective.json"
if [[ -n "$foreign_object" ]]; then
    bpftool -j cgroup show "$executions" > "$evidence/s4-phase-c-ancestor-direct.json"
fi
ip netns exec "$netns" nft -a list ruleset > "$evidence/s4-nft-phase-c.txt"
touch "$phase_c_go"

wait_marker "$phase_c_observed"
restore_nft_rule
ip netns exec "$netns" nft -a list ruleset > "$evidence/s4-nft-after.txt"
ip netns exec "$netns" nft -j list ruleset > "$evidence/s4-nft-after.json"
if cmp -s "$evidence/s4-nft-before.json" "$evidence/s4-nft-after.json"; then
    nft_restoration_exact=true
else
    nft_restoration_exact=false
fi
{
    echo "nft_restoration_exact=$nft_restoration_exact"
    sha256sum "$evidence/s4-nft-before.json" "$evidence/s4-nft-after.json"
} > "$evidence/s4-nft-restoration.txt"
if [[ "$nft_restoration_exact" != true ]]; then
    echo "nft ruleset was not restored byte-for-byte" >&2
    exit 1
fi
touch "$nft_restored"

set +e
wait "$harness_pid"
harness_status=$?
set -e
harness_pid=
echo "$harness_status" > "$evidence/s4-harness-exit-status.txt"
[[ "$harness_status" -eq 0 ]]

if [[ -n "$foreign_object" ]]; then
    stop_foreign_trace
    bpftool -j prog show pinned "$foreign_root/foreign_allow" > "$evidence/s4-foreign-allow-after.json"
    bpftool -j cgroup show "$executions" > "$evidence/s4-foreign-ancestor-after.json"
    if ! grep -q '^record .* who=2 ' "$evidence/s4-foreign-trace.txt"; then
        echo "foreign_trace contained no invocation records" >&2
        exit 1
    fi
fi

{
    echo "# S4 enforcement attribution"
    date -u +"UTC=%FT%TZ"
    echo "normal_control=nft namespace output barrier denied direct target while spike-only BPF permitted it"
    echo "normal_control_proxy_path=established through 10.200.255.1:15001"
    echo "experimental_relaxation=one namespace output accept rule for 10.201.0.2:16001"
    echo "bpf_deny=connect4 hook entry 1, connect4 deny counter 1, per-cgroup deny entry 1, deny event 1"
    echo "bpf_deny_process_result=cannot establish"
    echo "bpf_deny_syn_or_accept=none observed by bound direct listener"
    echo "bpf_deny_proxy_involvement=false"
    echo "negative_control=with the same nft relaxation and only the spike-only direct BPF exception, connection established and listener accepted"
    echo "namespace_constraint=owned netns route plus namespace input/output/forward policy remained active; only one exact output exception was added"
    echo "host_topology_constraint=anti-spoof, invalid/non-TCP input checks and all forwarding drops remained active"
    echo "architecture=nft remains final destination barrier; BPF remains early deny and attribution hardening"
    echo "S4_RESULT=PASS"
} > "$evidence/s4-summary.txt"
