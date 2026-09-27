#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# The delegated cgroup unit every spike runner expects: `soglia-spike-s0.service`. EXPERIMENTAL.
#
# Copied unchanged, apart from this header, from the VM's /tmp, where it was written by hand for
# S0.2; the original is sha256 81109d109489309560838902821d9f0debf538d8a300e79debfeb963084032dc.
# Inside the VM, as root:
#
#   cp spikes/cgroup-bpf/soglia-s0-delegation.sh /tmp/ && chmod 0755 /tmp/soglia-s0-delegation.sh
#   systemd-run --unit=soglia-spike-s0 --property=Delegate=yes /tmp/soglia-s0-delegation.sh
#
# It moves its own process into `runtime/`, enables `+memory +pids` for children, writes its
# evidence to /tmp/soglia-s0-delegation.txt, and stays alive (`sleep infinity`) so the delegated
# subtree lives as long as the unit.
set -euo pipefail

UNIT="soglia-spike-s0.service"
OUT="/tmp/soglia-s0-delegation.txt"
READY="/tmp/soglia-s0-ready"

rm -f "$READY"

# This is the transient service cgroup before moving ourselves to a leaf.
CG_REL="$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
CG_ROOT="/sys/fs/cgroup${CG_REL}"

{
  echo '$ sudo systemd-run --unit=soglia-spike-s0 --property=Delegate=yes /tmp/soglia-s0-delegation.sh'
  echo

  echo '===== UNIT BEFORE LEAF MOVE ====='
  echo '$ systemctl show soglia-spike-s0.service -p Delegate -p DelegateControllers -p ControlGroup'
  systemctl show "$UNIT" \
    -p Delegate \
    -p DelegateControllers \
    -p ControlGroup
  echo

  echo '$ cat /proc/self/cgroup'
  cat /proc/self/cgroup
  echo

  echo "DELEGATED_ROOT=$CG_ROOT"
  echo

  echo '$ cat <root>/cgroup.controllers'
  cat "$CG_ROOT/cgroup.controllers"
  echo

  echo '$ cat <root>/cgroup.subtree_control'
  cat "$CG_ROOT/cgroup.subtree_control"
  echo

  echo '$ cat <root>/cgroup.procs'
  cat "$CG_ROOT/cgroup.procs"
  echo

  echo "\$ stat -c '%U:%G %a %n' <root> <root>/cgroup.procs <root>/cgroup.subtree_control"
  stat -c '%U:%G %a %n' \
    "$CG_ROOT" \
    "$CG_ROOT/cgroup.procs" \
    "$CG_ROOT/cgroup.subtree_control"
  echo
} > "$OUT"

# Respect cgroup-v2 no-internal-process constraint:
# move the transient service process into a leaf first.
mkdir -p "$CG_ROOT/runtime"
echo "$$" > "$CG_ROOT/runtime/cgroup.procs"

{
  echo '===== AFTER MOVING PROCESS TO runtime/ ====='
  echo '$ cat /proc/self/cgroup'
  cat /proc/self/cgroup
  echo

  echo '$ cat <root>/cgroup.procs'
  cat "$CG_ROOT/cgroup.procs"
  echo

  echo '$ cat <root>/runtime/cgroup.procs'
  cat "$CG_ROOT/runtime/cgroup.procs"
  echo

  echo '$ echo "+memory +pids" > <root>/cgroup.subtree_control'
} >> "$OUT"

# This must succeed. set -e makes any EBUSY/EPERM abort the unit.
echo '+memory +pids' > "$CG_ROOT/cgroup.subtree_control"

{
  echo 'OK'
  echo

  echo '===== DELEGATED ROOT AFTER ENABLE ====='
  echo '$ systemctl show soglia-spike-s0.service -p Delegate -p DelegateControllers -p ControlGroup'
  systemctl show "$UNIT" \
    -p Delegate \
    -p DelegateControllers \
    -p ControlGroup
  echo

  echo '$ cat <root>/cgroup.controllers'
  cat "$CG_ROOT/cgroup.controllers"
  echo

  echo '$ cat <root>/cgroup.subtree_control'
  cat "$CG_ROOT/cgroup.subtree_control"
  echo

  echo "\$ stat -c '%U:%G %a %n' <root> <root>/cgroup.procs <root>/cgroup.subtree_control"
  stat -c '%U:%G %a %n' \
    "$CG_ROOT" \
    "$CG_ROOT/cgroup.procs" \
    "$CG_ROOT/cgroup.subtree_control"
  echo

  echo '$ ls -la <root>'
  ls -la "$CG_ROOT"
  echo

  echo '$ cat <root>/runtime/cgroup.procs'
  cat "$CG_ROOT/runtime/cgroup.procs"
} >> "$OUT"

touch "$READY"

# Keep the delegated unit alive for S0.3.
sleep infinity
