#!/usr/bin/env bash
# Copyright (c) 2022 Nitro Agility S.r.l.
# SPDX-License-Identifier: Apache-2.0
#
# Builds every BPF object of the spike from source, with the system headers of the Linux VM:
# UAPI from linux-libc-dev, helpers from libbpf-dev, AF_*/SOCK_* from libc6-dev.
#
#   spikes/cgroup-bpf/build.sh <output directory>
#
# EXPERIMENTAL: the SPIKE_* variants exist only here and are never production policy.

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: build.sh <output directory>}"
mkdir -p "$out"

multiarch="$(gcc -dumpmachine)"
cflags=(-target bpf -O2 -g -Wall -Werror -I"/usr/include/${multiarch}")

build() {
    local name="$1" source="$2"
    shift 2
    clang "${cflags[@]}" "$@" -c "$here/bpf/$source" -o "$out/$name.o"
}

build soglia soglia_spike.c
build soglia-relax-inet6 soglia_spike.c -DSPIKE_RELAX_INET6_STREAM
build soglia-relax-dgram soglia_spike.c -DSPIKE_RELAX_DGRAM
build soglia-relax-all soglia_spike.c -DSPIKE_RELAX_INET6_STREAM -DSPIKE_RELAX_DGRAM
build soglia-relax-inet6-diag soglia_spike.c -DSPIKE_RELAX_INET6_STREAM -DSPIKE_DIAGNOSTIC
build soglia-relax-dgram-diag soglia_spike.c -DSPIKE_RELAX_DGRAM -DSPIKE_DIAGNOSTIC
build soglia-delay soglia_spike.c -DSPIKE_DELAY_PUBLISH
build soglia-delay-diag soglia_spike.c -DSPIKE_DELAY_PUBLISH -DSPIKE_DIAGNOSTIC
build soglia-small soglia_spike.c -DSPIKE_TUPLE_MAX=8
build soglia-small-diag soglia_spike.c \
    -DSPIKE_TUPLE_MAX=8 -DSPIKE_DIAGNOSTIC -DSPIKE_MAP_FAILURE_DIAGNOSTIC
build soglia-trace soglia_spike.c -DSPIKE_TRACE
build soglia-diag soglia_spike.c -DSPIKE_DIAGNOSTIC
build soglia-direct-control soglia_spike.c -DSPIKE_DIAGNOSTIC -DSPIKE_ALLOW_DIRECT4
build netns-probe netns_probe.c
build foreign foreign.c
# S10-owned topology constants. IPv4 values are the native u32 representation of the network-order
# bytes on the qualified little-endian VM: 10.200.255.1 -> 0x01ffc80a and 10.201.0.2 -> 0x0200c90a.
build foreign-s10 foreign.c \
    -DSPIKE_FOREIGN_PROXY_IP4=0x01ffc80a \
    -DSPIKE_FOREIGN_PROXY_PORT=15001 \
    -DSPIKE_FOREIGN_REWRITE_IP4=0x0200c90a \
    -DSPIKE_FOREIGN_REWRITE_PORT=16001
build gpl-probe-task-btf gpl_probe.c -DPROBE=1
# The kfunc probe needs the kernel's own prototypes: vmlinux.h is generated from the running
# kernel's BTF into the output directory, used by this probe only, and never committed.
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$out/vmlinux.h"
clang "${cflags[@]}" -I"$out" -c "$here/bpf/gpl_probe_kfunc.c" -o "$out/gpl-probe-cgroup-from-id.o"

ls -1 "$out"
