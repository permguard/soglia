// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// Licence probe for the kfunc route to CGRP_STORAGE. EXPERIMENTAL: never attached, never shipped.
//
// Compiled against a vmlinux.h that build.sh generates from the running kernel's BTF into the build
// output directory (never into the repository): a kfunc prototype must match the kernel's BTF
// exactly, which a hand-written forward declaration does not.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Apache-2.0";

extern struct cgroup *bpf_cgroup_from_id(u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;

struct {
    __uint(type, BPF_MAP_TYPE_CGRP_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, __u64);
} cgrp_state SEC(".maps");

SEC("cgroup/connect4")
int probe_cgroup_from_id(struct bpf_sock_addr *ctx)
{
    struct cgroup *cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
    if (!cgrp)
        return 0;
    __u64 *state = bpf_cgrp_storage_get(&cgrp_state, cgrp, 0, 0);
    bpf_cgroup_release(cgrp);
    return state ? 1 : 0;
}
