// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// Licence probe for the helper route to a cgroup pointer, which CGRP_STORAGE needs. EXPERIMENTAL.
//
// Loaded with the same non-GPL licence as the spike and never attached; the verifier's verdict is
// the evidence. The kfunc route is probed separately, in gpl_probe_kfunc.c.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Apache-2.0";

#if PROBE == 1
// bpf_get_current_task_btf: the helper route to the current task's cgroup pointer.
SEC("cgroup/connect4")
int probe_task_btf(struct bpf_sock_addr *ctx)
{
    void *task = bpf_get_current_task_btf();
    return task ? 1 : 1;
}
#endif
