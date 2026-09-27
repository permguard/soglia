#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Stops and deletes every Lima VM of the cgroup-BPF spike: the ones whose name starts with
# `soglia-spike` (the old spike VM, the development VM and every replay VM). Nothing else is
# touched. Evidence lives in the repository on the host, not in the VMs, so it survives.
#
#   delete-vms.sh           list the VMs and ask for confirmation
#   delete-vms.sh --yes     delete without asking
#
# Deleting a VM cannot be undone.

set -euo pipefail

command -v limactl >/dev/null 2>&1 || {
    echo "limactl is required" >&2
    exit 13
}

# A while-read loop rather than mapfile: macOS ships bash 3.2.
vms=()
while IFS= read -r name; do
    vms+=("$name")
done < <(limactl list --format '{{.Name}}' | grep '^soglia-spike' || true)
if [[ ${#vms[@]} -eq 0 ]]; then
    echo "no soglia-spike VM exists"
    exit 0
fi

echo "These Lima VMs will be stopped and deleted:"
limactl list | awk 'NR == 1 || /^soglia-spike/'

if [[ ${1:-} != --yes ]]; then
    read -r -p "Delete ${#vms[@]} VM(s)? Type 'yes' to continue: " answer
    if [[ $answer != yes ]]; then
        echo "nothing deleted"
        exit 1
    fi
fi

for vm in "${vms[@]}"; do
    echo "deleting $vm"
    limactl delete --force "$vm"
done

echo "remaining soglia-spike VMs:"
limactl list | awk 'NR == 1 || /^soglia-spike/'
