// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// The trusted reference for candidate D. EXPERIMENTAL: not production code.
//
// Attached only to the harness's own `runtime` cgroup. When the harness (the Enforcer role) opens a
// socket from a thread that has entered an Execution network namespace, this records the socket
// cookie -> the namespace cookie. The harness then reads its own socket's cookie with SO_COOKIE and
// learns the cookie of the namespace it created, from the kernel, without asking the agent.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Apache-2.0";

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);
    __type(value, __u64);
} netns_probe SEC(".maps");

SEC("cgroup/sock_create")
int soglia_netns_probe(struct bpf_sock *sk)
{
    __u64 cookie = bpf_get_socket_cookie(sk);
    __u64 netns = bpf_get_netns_cookie(sk);
    bpf_map_update_elem(&netns_probe, &cookie, &netns, BPF_ANY);
    return 1;
}
