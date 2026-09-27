#!/bin/sh
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Delegates a cgroup subtree to Soglia inside the development container, then runs the command.
#
# The container has its own cgroup namespace, whose root is the subtree the container runtime
# delegated. cgroup v2 lets only an empty cgroup enable controllers for its children, so every
# process moves to an `init` leaf first; `soglia` is then the empty, delegated subtree Soglia is
# configured with, the way a systemd unit with `Delegate=yes` would provide it.

set -eu

root=/sys/fs/cgroup
mkdir -p "$root/init"
for pid in $(cat "$root/cgroup.procs"); do
    echo "$pid" > "$root/init/cgroup.procs" 2>/dev/null || true
done
echo "+memory +pids +cpu" > "$root/cgroup.subtree_control"
mkdir -p "$root/soglia"

exec "$@"
