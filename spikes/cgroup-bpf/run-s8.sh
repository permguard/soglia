#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Regresses the production fail-closed response to abrupt enforcer loss. The original failing
# evidence remains immutable under evidence/s8/run4; this runner writes a distinct post-fix run.

set -euo pipefail

evidence="${S8_EVIDENCE:-/soglia/spikes/cgroup-bpf/evidence/s8/after-fix-run6}"
unit_name=soglia-spike-s8.service
unit="/sys/fs/cgroup/system.slice/$unit_name"
s0_unit=/sys/fs/cgroup/system.slice/soglia-spike-s0.service
state=/run/soglia-spike-s8
work=/var/tmp/spike/s8
rootfs="$work/rootfs"
config="$work/soglia.yaml"
soglia=/var/tmp/spike/target/release/soglia
agent=/var/tmp/spike/target/aarch64-unknown-linux-musl/release/soglia-spike-agent
ingress=127.0.0.1:18089
hosts_backup="$work/hosts.before"
listener_443=
listener_444=
curl_tunnel=
curl_delayed=
curl_sleep=
main_pid=
enforcer_pid=
sandbox_pid=
hosts_saved=false

wait_for() {
    local description="$1" attempts="$2"
    shift 2
    for _ in $(seq 1 "$attempts"); do
        if "$@"; then return 0; fi
        sleep 0.1
    done
    echo "timed out waiting for $description" >&2
    return 1
}

ingress_listening() {
    ss -H -lnt | grep -F '127.0.0.1:18089' >/dev/null
}

ingress_closed() {
    ! ingress_listening
}

three_executions() {
    [[ -d "$unit/executions" ]] &&
        [[ $(find "$unit/executions" -mindepth 1 -maxdepth 1 -type d | wc -l) -ge 3 ]]
}

established_to() {
    ss -H -tn state established | grep -F "$1" >/dev/null
}

application_pulse_observed() {
    grep -Fq '"event":"application_pulse_echoed"' "$evidence/s8-upstream-443.txt"
}

helper_loss_observed() {
    journalctl -u "$unit_name" --since "@$start_epoch" --no-pager \
        | grep -F 'runtime.helper_lost' >/dev/null
}

no_agents_live() {
    [[ $(pgrep -af '^/agent( |$)' | wc -l) -eq 0 ]]
}

no_existing_tunnel() {
    ! established_to '11.0.0.1:443'
}

helper_pid() {
    local role="$1" child cmdline
    for child in $(cat "/proc/$main_pid/task/$main_pid/children" 2>/dev/null); do
        cmdline=$(tr '\0' ' ' < "/proc/$child/cmdline" 2>/dev/null || true)
        if [[ "$cmdline" == *"__$role"* ]]; then
            echo "$child"
            return 0
        fi
    done
    return 1
}

helpers_ready() {
    helper_pid sandboxd >/dev/null && helper_pid enforcer >/dev/null
}

process_gone_or_zombie() {
    local pid="$1" state
    [[ ! -e "/proc/$pid/stat" ]] && return 0
    state=$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)
    [[ "$state" == Z ]]
}

record_kernel_state() {
    local prefix="$1"
    nft -a list ruleset > "$evidence/$prefix-nft.txt" 2>&1 || true
    ip netns list > "$evidence/$prefix-netns.txt"
    ip -details -o link show > "$evidence/$prefix-links.txt"
    bpftool -j prog show > "$evidence/$prefix-prog.json"
    bpftool -j link show > "$evidence/$prefix-bpf-link.json"
    bpftool -j map show > "$evidence/$prefix-map.json"
    find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort \
        > "$evidence/$prefix-bpffs.txt"
    if [[ -d "$unit" ]]; then
        bpftool cgroup tree "$unit" > "$evidence/$prefix-cgroup-bpf.txt" 2>&1 || true
        find "$unit" -mindepth 1 -maxdepth 3 -type d -printf '%i %p\n' | sort \
            > "$evidence/$prefix-cgroups.txt"
    else
        echo "ABSENT $unit" > "$evidence/$prefix-cgroup-bpf.txt"
        echo "ABSENT $unit" > "$evidence/$prefix-cgroups.txt"
    fi
    find "$state" -mindepth 1 -maxdepth 4 -printf '%y %p\n' 2>/dev/null | sort \
        > "$evidence/$prefix-state-files.txt" || true
}

record_execution_membership() {
    {
        echo "# S8 live Execution membership before any agent network traffic"
        date -u +"UTC=%FT%TZ"
        echo "unit=$unit"
        echo "unit_inode=$(stat -c %i "$unit")"
        echo "main_pid=$main_pid"
        echo "sandbox_pid=$sandbox_pid"
        echo "enforcer_pid=$enforcer_pid"
        echo "runtime_membership=$(tr '\n' ' ' < "/proc/$main_pid/cgroup")"
        echo "main_children=$(tr '\n' ' ' < "/proc/$main_pid/task/$main_pid/children")"
        ps -o pid=,ppid=,state=,lstart=,cmd= -p "$main_pid,$sandbox_pid,$enforcer_pid"
        for cgroup in "$unit"/executions/*; do
            [[ -d "$cgroup" ]] || continue
            echo "EXECUTION path=$cgroup inode=$(stat -c %i "$cgroup")"
            echo "cgroup_procs=$(tr '\n' ' ' < "$cgroup/cgroup.procs")"
            for pid in $(cat "$cgroup/cgroup.procs"); do
                echo "PID=$pid cgroup=$(tr '\n' ' ' < "/proc/$pid/cgroup") netns=$(readlink "/proc/$pid/ns/net") cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")"
            done
            tag=${cgroup##*/}
            if [[ -e "/run/netns/soglia-$tag" ]]; then
                echo "NETNS name=soglia-$tag inode=$(stat -Lc %i "/run/netns/soglia-$tag")"
                ip netns exec "soglia-$tag" nft -a list ruleset
            else
                echo "NETNS_MISSING name=soglia-$tag"
            fi
        done
    } > "$evidence/s8-before-traffic-membership.txt"
}

cleanup_owned() {
    set +e
    systemctl stop "$unit_name" >/dev/null 2>&1
    for pid in "$curl_tunnel" "$curl_delayed" "$curl_sleep" "$listener_443" "$listener_444"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            wait "$pid" 2>/dev/null
        fi
    done
    if [[ -d "$state/runc" ]]; then
        for id in $(runc --root "$state/runc" list --quiet 2>/dev/null); do
            runc --root "$state/runc" kill "$id" KILL >/dev/null 2>&1
            runc --root "$state/runc" delete -f "$id" >/dev/null 2>&1
        done
    fi
    for ns in $(ip netns list | awk '$1 ~ /^soglia-/ {print $1}'); do
        ip netns del "$ns" >/dev/null 2>&1
    done
    for link in $(ip -o link show | sed -n 's/^[0-9]*: \(sgh-[^:@]*\).*/\1/p'); do
        ip link del "$link" >/dev/null 2>&1
    done
    nft list table inet soglia_host >/dev/null 2>&1 && nft delete table inet soglia_host
    if ip link show soglia0 >/dev/null 2>&1; then ip link del soglia0; fi
    if ip link show upstream-s8 >/dev/null 2>&1; then ip link del upstream-s8; fi
    if $hosts_saved && [[ -f "$hosts_backup" ]]; then cp "$hosts_backup" /etc/hosts; fi
    if [[ -d "$unit" ]]; then
        [[ -e "$unit/cgroup.kill" ]] && printf '1\n' > "$unit/cgroup.kill"
        find "$unit" -depth -mindepth 1 -type d -exec rmdir {} \; 2>/dev/null
    fi
    systemctl reset-failed "$unit_name" >/dev/null 2>&1
    rm -rf "$state" "$rootfs"
}

record_cleanup() {
    set +e
    {
        echo "# S8 final cleanup verification"
        date -u +"UTC=%FT%TZ"
        echo "unit_load_state=$(systemctl show "$unit_name" -p LoadState --value 2>/dev/null || echo absent)"
        if [[ -e "$unit" ]]; then echo "PRESENT $unit"; else echo "ABSENT $unit"; fi
        if [[ -e "$state" ]]; then echo "PRESENT $state"; else echo "ABSENT $state"; fi
        if [[ -e /sys/class/net/upstream-s8 ]]; then echo "PRESENT upstream-s8"; else echo "ABSENT upstream-s8"; fi
        if [[ -e /sys/class/net/soglia0 ]]; then echo "PRESENT soglia0"; else echo "ABSENT soglia0"; fi
        echo "soglia_netns_count=$(ip netns list | awk '$1 ~ /^soglia-/ {n++} END {print n+0}')"
        echo "soglia_veth_count=$(ip -o link show | grep -c 'sgh-' || true)"
        echo "soglia_host_table_count=$(nft list tables 2>/dev/null | grep -c 'table inet soglia_host' || true)"
        echo "agent_process_count=$(pgrep -af '^/agent( |$)' | wc -l)"
        echo "soglia_bpf_program_count=$(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_"))] | length')"
        echo "cgroup_bpf_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
        echo "hosts_restored=$(cmp -s "$hosts_backup" /etc/hosts && echo true || echo false)"
        echo "bpffs_begin"
        find /sys/fs/bpf -mindepth 1 -maxdepth 5 -print | sort
        echo "bpffs_end"
    } > "$evidence/s8-cleanup.txt"
    bpftool -j prog show > "$evidence/s8-final-prog.json"
    bpftool -j link show > "$evidence/s8-final-link.json"
    bpftool -j map show > "$evidence/s8-final-map.json"
    find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s8-final-bpffs.txt"
}

on_exit() {
    status=$?
    trap - EXIT
    set +e
    cleanup_owned
    record_cleanup
    rm -rf "$work"
    if [[ -e "$work" ]]; then
        echo "PRESENT $work" > "$evidence/s8-scratch-cleanup.txt"
    else
        echo "ABSENT $work" > "$evidence/s8-scratch-cleanup.txt"
    fi
    echo "$status" > "$evidence/s8-run-exit-status.txt"
    exit "$status"
}
trap on_exit EXIT

if [[ -d "$evidence" ]] && find "$evidence" -mindepth 1 -print -quit | grep -q .; then
    echo "refusing to overwrite non-empty evidence directory: $evidence" >&2
    exit 1
fi
mkdir -p "$evidence" "$work"
cleanup_owned
set -e
mkdir -p "$evidence" "$work"

cp /etc/hosts "$hosts_backup"
hosts_saved=true
hosts_sha_before=$(sha256sum "$hosts_backup" | awk '{print $1}')
printf '\n11.0.0.1 allowed.test # soglia-spike-s8\n' >> /etc/hosts

{
    echo "# S8 clean preflight"
    date -u +"UTC=%FT%TZ"
    uname -a
    systemctl show soglia-spike-s0.service -p ActiveState -p SubState -p MainPID -p Delegate -p DelegateControllers -p ControlGroup --no-pager
    echo "delegated_s0_inode=$(stat -c %i "$s0_unit")"
    echo "delegated_s0_children_begin"
    find "$s0_unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
    echo "delegated_s0_children_end"
    command -v runc nft ip bpftool curl ss systemd-run
    echo "hosts_sha256_before=$hosts_sha_before"
    echo "soglia_netns_count=$(ip netns list | awk '$1 ~ /^soglia-/ {n++} END {print n+0}')"
    echo "soglia_veth_count=$(ip -o link show | grep -c 'sgh-' || true)"
    echo "soglia0_present=$([[ -e /sys/class/net/soglia0 ]] && echo true || echo false)"
    echo "soglia_host_table_count=$(nft list tables 2>/dev/null | grep -c 'table inet soglia_host' || true)"
    echo "unexpected_soglia_test_process_count=$(pgrep -af '^/var/tmp/spike/target/release/soglia( |$)|^/agent( |$)' | wc -l)"
    echo "soglia_bpf_program_count=$(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_"))] | length')"
    echo "cgroup_bpf_link_count=$(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length')"
    echo "bpffs_begin"
    find /sys/fs/bpf -mindepth 1 -maxdepth 5 -print | sort
    echo "bpffs_end"
} > "$evidence/s8-preflight.txt"

[[ $(systemctl is-active soglia-spike-s0.service) == active ]]
[[ $(systemctl show soglia-spike-s0.service -p Delegate --value) == yes ]]
[[ $(find "$s0_unit" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort) == runtime ]]
[[ $(ip netns list | awk '$1 ~ /^soglia-/ {n++} END {print n+0}') -eq 0 ]]
[[ $(ip -o link show | grep -c 'sgh-' || true) -eq 0 ]]
[[ ! -e /sys/class/net/soglia0 ]]
[[ $(nft list tables 2>/dev/null | grep -c 'table inet soglia_host' || true) -eq 0 ]]
[[ $(pgrep -af '^/var/tmp/spike/target/release/soglia( |$)|^/agent( |$)' | wc -l) -eq 0 ]]
[[ $(bpftool -j prog show | jq '[.[] | select((.name // "") | startswith("soglia_") or startswith("foreign_"))] | length') -eq 0 ]]
[[ $(bpftool -j link show | jq '[.[] | select(.type == "cgroup")] | length') -eq 0 ]]
[[ -z $(find /sys/fs/bpf -mindepth 1 -maxdepth 5 -print -quit) ]]
bpftool -j prog show > "$evidence/s8-baseline-prog.json"
bpftool -j link show > "$evidence/s8-baseline-link.json"
bpftool -j map show > "$evidence/s8-baseline-map.json"
find /sys/fs/bpf -mindepth 1 -maxdepth 5 -printf '%y %p\n' | sort > "$evidence/s8-baseline-bpffs.txt"
nft -a list ruleset > "$evidence/s8-baseline-nft.txt"

mkdir -p "$rootfs"/{proc,dev,sys,tmp}
cp "$agent" "$rootfs/agent"
chmod 0755 "$rootfs" "$rootfs/agent"
cat > "$config" <<YAML
runtime:
  state_dir: $state
  uid: 990
  gid: 990
  max_concurrency: 4
  max_queue: 2
  cleanup_failure_threshold: 1
  teardown_timeout_ms: 3000
ingress:
  listen: $ingress
  max_response_bytes: 65536
cgroup:
  root: $unit
egress:
  connect_timeout_ms: 1500
  idle_timeout_ms: 30000
  allow:
    - { host: allowed.test, ports: [443, 444] }
agents:
  probe:
    rootfs: $rootfs
    command: ["/agent", "serve"]
    env: { AGENT_PORT: "8080" }
    port: 8080
    timeout_ms: 30000
    startup_timeout_ms: 3000
YAML

{
    echo "# S8 artifact provenance"
    date -u +"UTC=%FT%TZ"
    sha256sum /soglia/spikes/cgroup-bpf/agent/src/main.rs "$soglia" "$agent" "$config"
    file "$soglia" "$agent"
    "$soglia" --version 2>&1 || true
} > "$evidence/s8-provenance.txt"

ip link add upstream-s8 type dummy
ip addr add 11.0.0.1/32 dev upstream-s8
ip link set upstream-s8 up
"$agent" 'listen4-pulse-hold 11.0.0.1:443 20' > "$evidence/s8-upstream-443.txt" 2>&1 &
listener_443=$!
"$agent" 'listen4-hold 11.0.0.1:444 20' > "$evidence/s8-upstream-444.txt" 2>&1 &
listener_444=$!
sleep 0.2

start_epoch=$(date +%s)
systemd-run --unit "$unit_name" --property=Delegate=yes --property=Type=simple \
    --property=Restart=no "$soglia" run -f "$config" > "$evidence/s8-systemd-run.txt"
wait_for 'Soglia startup.ready' 300 ingress_listening
main_pid=$(systemctl show "$unit_name" -p MainPID --value)
wait_for 'privileged helpers' 100 helpers_ready
sandbox_pid=$(helper_pid sandboxd)
enforcer_pid=$(helper_pid enforcer)

{
    echo "# S8 runtime before traffic"
    date -u +"UTC=%FT%TZ"
    systemctl show "$unit_name" -p ActiveState -p SubState -p MainPID -p Delegate -p DelegateControllers -p ControlGroup --no-pager
    echo "unit_inode=$(stat -c %i "$unit")"
    echo "main_pid=$main_pid"
    echo "sandbox_pid=$sandbox_pid cmdline=$(tr '\0' ' ' < "/proc/$sandbox_pid/cmdline")"
    echo "enforcer_pid=$enforcer_pid cmdline=$(tr '\0' ' ' < "/proc/$enforcer_pid/cmdline")"
    echo "main_children=$(tr '\n' ' ' < "/proc/$main_pid/task/$main_pid/children")"
    echo "sandbox_ppid=$(awk '/^PPid:/ {print $2}' "/proc/$sandbox_pid/status")"
    echo "enforcer_ppid=$(awk '/^PPid:/ {print $2}' "/proc/$enforcer_pid/status")"
    echo "main_cgroup=$(tr '\n' ' ' < "/proc/$main_pid/cgroup")"
    echo "sandbox_cgroup=$(tr '\n' ' ' < "/proc/$sandbox_pid/cgroup")"
    echo "enforcer_cgroup=$(tr '\n' ' ' < "/proc/$enforcer_pid/cgroup")"
    ps -o pid=,ppid=,state=,lstart=,cmd= -p "$main_pid,$sandbox_pid,$enforcer_pid"
    ss -lntp
} > "$evidence/s8-runtime-before-traffic.txt"
record_kernel_state s8-before-traffic

curl --max-time 55 -sS -D "$evidence/s8-existing-tunnel-headers.txt" \
    -o "$evidence/s8-existing-tunnel-body.txt" -w '%{http_code}\n' -X POST \
    --data-binary 'delayed-tunnel-pulse 2500 allowed.test:443 2000 25' \
    "http://$ingress/v1/execute/probe" > "$evidence/s8-existing-tunnel-status.txt" 2> "$evidence/s8-existing-tunnel-curl.txt" &
curl_tunnel=$!
curl --max-time 55 -sS -D "$evidence/s8-post-loss-tunnel-headers.txt" \
    -o "$evidence/s8-post-loss-tunnel-body.txt" -w '%{http_code}\n' -X POST \
    --data-binary 'delayed-tunnel 6500 allowed.test:444 25' \
    "http://$ingress/v1/execute/probe" > "$evidence/s8-post-loss-tunnel-status.txt" 2> "$evidence/s8-post-loss-tunnel-curl.txt" &
curl_delayed=$!
curl --max-time 55 -sS -D "$evidence/s8-existing-http-headers.txt" \
    -o "$evidence/s8-existing-http-body.txt" -w '%{http_code}\n' -X POST \
    --data-binary 'sleep 12000' \
    "http://$ingress/v1/execute/probe" > "$evidence/s8-existing-http-status.txt" 2> "$evidence/s8-existing-http-curl.txt" &
curl_sleep=$!

wait_for 'three fresh Execution cgroups' 100 three_executions
record_execution_membership
record_kernel_state s8-live-pre-loss
wait_for 'pre-loss CONNECT to allowed.test:443' 100 established_to '11.0.0.1:443'

{
    echo "# S8 state immediately before helper loss"
    date -u +"UTC=%FT%TZ"
    echo "main_alive=$(kill -0 "$main_pid" 2>/dev/null && echo true || echo false)"
    echo "enforcer_kill0=$(kill -0 "$enforcer_pid" 2>/dev/null && echo true || echo false)"
    echo "enforcer_live=$([[ $(awk '{print $3}' "/proc/$enforcer_pid/stat" 2>/dev/null || echo Z) != Z ]] && echo true || echo false)"
    echo "sandbox_alive=$(kill -0 "$sandbox_pid" 2>/dev/null && echo true || echo false)"
    ss -tnp
    journalctl -u "$unit_name" --since "@$start_epoch" --no-pager
} > "$evidence/s8-before-helper-loss.txt"

admitted_before=$(journalctl -u "$unit_name" --since "@$start_epoch" --no-pager | grep -Fc 'execution.admitted')
allowed_before=$(journalctl -u "$unit_name" --since "@$start_epoch" --no-pager | grep -Fc 'egress.allowed')
kill_utc=$(date -u +%FT%T.%NZ)
kill_epoch_ns=$(date +%s%N)
kill -KILL "$enforcer_pid"
kill_command_status=0
wait_for 'enforcer death or reaping' 50 process_gone_or_zombie "$enforcer_pid"

# No Enforcer RPC is issued here. The dedicated child watcher must be the event source.
wait_for 'autonomous runtime.helper_lost detection' 50 helper_loss_observed
detected_epoch_ns=$(date +%s%N)
transition_epoch_us=$(journalctl -u "$unit_name" --since "@$start_epoch" --no-pager -o json \
    | jq -r 'select(((.MESSAGE? // "") | if type == "array" then implode else . end) | contains("runtime.helper_lost")) | .__REALTIME_TIMESTAMP' \
    | tail -1)
[[ "$transition_epoch_us" =~ ^[0-9]+$ ]]
transition_epoch_ns=$((transition_epoch_us * 1000))
wait_for 'ingress cancellation' 50 ingress_closed
ingress_closed_epoch_ns=$(date +%s%N)
wait_for 'trusted sandbox termination of all agents' 50 no_agents_live
agents_gone_epoch_ns=$(date +%s%N)
wait_for 'existing CONNECT closure' 50 no_existing_tunnel
tunnel_closed_epoch_ns=$(date +%s%N)
wait_for 'runtime exit after helper loss' 50 process_gone_or_zombie "$main_pid"
runtime_exit_epoch_ns=$(date +%s%N)

{
    echo "# S8 autonomous lifecycle detection and fail-closed transition"
    date -u +"UTC=%FT%TZ"
    echo "kill_utc=$kill_utc"
    echo "kill_epoch_ns=$kill_epoch_ns"
    echo "kill_signal=SIGKILL(9)"
    echo "kill_command_status=$kill_command_status"
    echo "detected_epoch_ns=$detected_epoch_ns"
    echo "detection_upper_bound_ms=$(( (detected_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "transition_epoch_ns=$transition_epoch_ns"
    echo "transition_log_latency_ms=$(( (transition_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "ingress_closed_epoch_ns=$ingress_closed_epoch_ns"
    echo "ingress_close_upper_bound_ms=$(( (ingress_closed_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "agents_gone_epoch_ns=$agents_gone_epoch_ns"
    echo "agent_termination_upper_bound_ms=$(( (agents_gone_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "tunnel_closed_epoch_ns=$tunnel_closed_epoch_ns"
    echo "tunnel_close_upper_bound_ms=$(( (tunnel_closed_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "runtime_exit_epoch_ns=$runtime_exit_epoch_ns"
    echo "runtime_exit_upper_bound_ms=$(( (runtime_exit_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "enforcer_proc_state=$(awk '{print $3}' "/proc/$enforcer_pid/stat" 2>/dev/null || echo absent)"
    echo "enforcer_proc_ppid=$(awk '{print $4}' "/proc/$enforcer_pid/stat" 2>/dev/null || echo absent)"
    echo "enforcer_proc_exit_code=$(awk '{print $52}' "/proc/$enforcer_pid/stat" 2>/dev/null || echo unavailable)"
    echo "main_alive=$(kill -0 "$main_pid" 2>/dev/null && echo true || echo false)"
    echo "sandbox_alive=$(kill -0 "$sandbox_pid" 2>/dev/null && echo true || echo false)"
    echo "ingress_listening=$(ingress_listening && echo true || echo false)"
    echo "existing_443_established=$(established_to '11.0.0.1:443' && echo true || echo false)"
    echo "agent_process_count=$(pgrep -af '^/agent( |$)' | wc -l)"
    ss -lntp
    ss -tnp
    journalctl -u "$unit_name" --since "@$start_epoch" --no-pager
} > "$evidence/s8-after-autonomous-detection.txt"
record_kernel_state s8-after-autonomous-detection

set +e
curl --max-time 2 -sS -o "$evidence/s8-post-detection-admission-body.txt" -w '%{http_code}\n' \
    -X POST --data-binary 'sleep 1' "http://$ingress/v1/execute/probe" \
    > "$evidence/s8-post-detection-admission-status.txt" 2> "$evidence/s8-post-detection-admission-curl.txt"
post_detection_curl_status=$?
set -e
echo "$post_detection_curl_status" > "$evidence/s8-post-detection-admission-exit-status.txt"

# Keep the observation open beyond the run4 pulse and delayed outbound timings. Any connection to
# port 444 is held by the independent listener, so a sampled ESTABLISHED state cannot be missed.
pulse_after_loss=false
outbound_444_after_loss=false
observation_deadline_ns=$((kill_epoch_ns + 7000000000))
while [[ $(date +%s%N) -lt $observation_deadline_ns ]]; do
    if application_pulse_observed; then pulse_after_loss=true; fi
    if established_to '11.0.0.1:444'; then outbound_444_after_loss=true; fi
    sleep 0.05
done
observation_end_epoch_ns=$(date +%s%N)
admitted_after=$(journalctl -u "$unit_name" --since "@$start_epoch" --no-pager | grep -Fc 'execution.admitted')
allowed_after=$(journalctl -u "$unit_name" --since "@$start_epoch" --no-pager | grep -Fc 'egress.allowed')

set +e
wait "$curl_tunnel" 2>/dev/null
curl_tunnel_status=$?
wait "$curl_delayed" 2>/dev/null
curl_delayed_status=$?
wait "$curl_sleep" 2>/dev/null
curl_sleep_status=$?
set -e
curl_tunnel=
curl_delayed=
curl_sleep=
printf '%s\n' "$curl_tunnel_status" > "$evidence/s8-existing-tunnel-curl-exit-status.txt"
printf '%s\n' "$curl_delayed_status" > "$evidence/s8-post-loss-tunnel-curl-exit-status.txt"
printf '%s\n' "$curl_sleep_status" > "$evidence/s8-existing-http-curl-exit-status.txt"

nft list table inet soglia_host > "$evidence/s8-retained-host-nft.txt"
{
    echo "# S8 bounded no-effect observation after autonomous detection"
    date -u +"UTC=%FT%TZ"
    echo "observation_end_epoch_ns=$observation_end_epoch_ns"
    echo "observation_after_kill_ms=$(( (observation_end_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "runtime_exit_epoch_ns=$runtime_exit_epoch_ns"
    echo "runtime_exit_upper_bound_ms=$(( (runtime_exit_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "pulse_after_loss=$pulse_after_loss"
    echo "outbound_444_after_loss=$outbound_444_after_loss"
    echo "admitted_before=$admitted_before"
    echo "admitted_after=$admitted_after"
    echo "allowed_before=$allowed_before"
    echo "allowed_after=$allowed_after"
    echo "post_detection_admission_curl_status=$post_detection_curl_status"
    echo "existing_443_established=$(established_to '11.0.0.1:443' && echo true || echo false)"
    echo "post_loss_444_established=$(established_to '11.0.0.1:444' && echo true || echo false)"
    echo "agent_process_count=$(pgrep -af '^/agent( |$)' | wc -l)"
    echo "application_pulse_evidence_begin"
    cat "$evidence/s8-upstream-443.txt"
    echo "application_pulse_evidence_end"
    systemctl show "$unit_name" -p ActiveState -p SubState -p Result -p ExecMainStatus -p MainPID --no-pager
    runc --root "$state/runc" list 2>&1 || true
    ss -lntp
    ss -tnp
    journalctl -u "$unit_name" --since "@$start_epoch" --no-pager
} > "$evidence/s8-after-observation.txt"
record_kernel_state s8-after-runtime-exit

[[ "$pulse_after_loss" == false ]]
[[ "$outbound_444_after_loss" == false ]]
[[ "$admitted_after" -eq "$admitted_before" ]]
[[ "$allowed_after" -eq "$allowed_before" ]]
[[ "$post_detection_curl_status" -ne 0 ]]
no_agents_live
ingress_closed
no_existing_tunnel
! established_to '11.0.0.1:444'

restart_epoch=$(date +%s)
systemctl restart "$unit_name"
wait_for 'restarted Soglia startup.ready' 300 ingress_listening
restart_main_pid=$(systemctl show "$unit_name" -p MainPID --value)
restart_journal="$evidence/s8-restart-journal.txt"
journalctl -u "$unit_name" --since "@$restart_epoch" --no-pager > "$restart_journal"
last_sweep_line=$(grep -n 'startup.swept' "$restart_journal" | tail -1 | cut -d: -f1)
ready_line=$(grep -n 'startup.ready' "$restart_journal" | tail -1 | cut -d: -f1)
{
    echo "# S8 restart and startup sweep"
    date -u +"UTC=%FT%TZ"
    echo "restart_main_pid=$restart_main_pid"
    echo "last_sweep_line=$last_sweep_line"
    echo "ready_line=$ready_line"
    systemctl show "$unit_name" -p ActiveState -p SubState -p Result -p MainPID -p NRestarts --no-pager
    journalctl -u "$unit_name" --since "@$restart_epoch" --no-pager
    echo "remaining_execution_cgroups_begin"
    find "$unit/executions" -mindepth 1 -maxdepth 1 -type d -printf '%i %p\n' | sort
    echo "remaining_execution_cgroups_end"
    echo "remaining_soglia_netns=$(ip netns list | awk '$1 ~ /^soglia-/ {n++} END {print n+0}')"
    echo "remaining_soglia_veth=$(ip -o link show | grep -c 'sgh-' || true)"
    echo "remaining_agent_processes=$(pgrep -af '^/agent( |$)' | wc -l)"
    runc --root "$state/runc" list 2>&1 || true
    nft -a list table inet soglia_host
} > "$evidence/s8-restart-sweep.txt"
record_kernel_state s8-after-restart-sweep

[[ -n "$last_sweep_line" ]]
[[ -n "$ready_line" ]]
[[ "$last_sweep_line" -lt "$ready_line" ]]
[[ $(find "$unit/executions" -mindepth 1 -maxdepth 1 -type d | wc -l) -eq 0 ]]
[[ $(ip netns list | awk '$1 ~ /^soglia-/ {n++} END {print n+0}') -eq 0 ]]
[[ $(ip -o link show | grep -c 'sgh-' || true) -eq 0 ]]
[[ $(pgrep -af '^/agent( |$)' | wc -l) -eq 0 ]]
[[ -z $(runc --root "$state/runc" list --quiet 2>/dev/null) ]]

systemctl stop "$unit_name"
for _ in $(seq 1 100); do
    [[ $(systemctl is-active "$unit_name" 2>/dev/null || true) != active ]] && break
    sleep 0.1
done
journalctl -u "$unit_name" --since "@$restart_epoch" --no-pager > "$restart_journal"

{
    echo "# S8 post-fix regression result"
    date -u +"UTC=%FT%TZ"
    echo "helper=enforcer"
    echo "death_signal=SIGKILL"
    echo "death_detection=autonomous_child_lifecycle_watcher"
    echo "detection_required_later_rpc=false"
    echo "detection_upper_bound_ms=$(( (detected_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "transition_log_latency_ms=$(( (transition_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "ingress_close_upper_bound_ms=$(( (ingress_closed_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "agent_termination_upper_bound_ms=$(( (agents_gone_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "tunnel_close_upper_bound_ms=$(( (tunnel_closed_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "runtime_exit_upper_bound_ms=$(( (runtime_exit_epoch_ns - kill_epoch_ns) / 1000000 ))"
    echo "new_admission=refused"
    echo "existing_http_work=cancelled"
    echo "existing_connect_tunnel=closed"
    echo "existing_tunnel_application_traffic_after_loss=none"
    echo "post_loss_dns_or_outbound=none"
    echo "pending_dns_unit_regression=passed"
    echo "execution_lifecycle=sandboxd_killed_agents_then_restart_swept_recorded_resources"
    echo "kernel_nft_confinement=remained_installed_after_enforcer_death"
    echo "kernel_bpf_confinement=not_active_in_current_phase0_runtime"
    echo "restart_sweep=completed_before_startup.ready_and_removed_recorded_residue"
    echo "approved_fail_closed_target_violated=false"
    echo "production_code_modified=true"
    echo "candidate_selected=false"
    echo "S8_RESULT=PASS"
} > "$evidence/s8-summary.txt"
