// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// A stand-in for a foreign (CNI-like) program on an ancestor cgroup. EXPERIMENTAL: test only.
//
// It is loaded and attached with bpftool, never by the Soglia harness, so the harness's objects and
// this one stay provably separate. Both programs append what they saw to `foreign_trace`.
//
//   foreign_allow    returns ALLOW and changes nothing.
//   foreign_rewrite  rewrites a connect to the Soglia proxy into one to `rewrite_ip4:rewrite_port`.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Apache-2.0";

#ifndef SPIKE_FOREIGN_PROXY_IP4
#define SPIKE_FOREIGN_PROXY_IP4 0
#endif
#ifndef SPIKE_FOREIGN_PROXY_PORT
#define SPIKE_FOREIGN_PROXY_PORT 0
#endif
#ifndef SPIKE_FOREIGN_REWRITE_IP4
#define SPIKE_FOREIGN_REWRITE_IP4 0
#endif
#ifndef SPIKE_FOREIGN_REWRITE_PORT
#define SPIKE_FOREIGN_REWRITE_PORT 0
#endif

const volatile __u32 proxy_ip4 = SPIKE_FOREIGN_PROXY_IP4;
const volatile __u32 proxy_port = SPIKE_FOREIGN_PROXY_PORT;
const volatile __u32 rewrite_ip4 = SPIKE_FOREIGN_REWRITE_IP4;
const volatile __u32 rewrite_port = SPIKE_FOREIGN_REWRITE_PORT;

struct trace_record {
    __u64 seq;
    __u32 who; // 2 = foreign allow, 3 = foreign rewrite
    __u32 daddr;
    __u32 dport;
    __u32 rewritten;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024);
} foreign_trace SEC(".maps");

SEC("cgroup/connect4")
int foreign_allow(struct bpf_sock_addr *ctx)
{
    struct trace_record record = {
        .seq = bpf_ktime_get_ns(),
        .who = 2,
        .daddr = ctx->user_ip4,
        .dport = bpf_ntohs((__u16)ctx->user_port),
    };
    bpf_ringbuf_output(&foreign_trace, &record, sizeof(record), 0);
    return 1;
}

SEC("cgroup/connect4")
int foreign_rewrite(struct bpf_sock_addr *ctx)
{
    struct trace_record record = {
        .seq = bpf_ktime_get_ns(),
        .who = 3,
        .daddr = ctx->user_ip4,
        .dport = bpf_ntohs((__u16)ctx->user_port),
    };
    if (ctx->user_ip4 == proxy_ip4 && bpf_ntohs((__u16)ctx->user_port) == proxy_port) {
        ctx->user_ip4 = rewrite_ip4;
        ctx->user_port = bpf_htons((__u16)rewrite_port);
        record.rewritten = 1;
    }
    bpf_ringbuf_output(&foreign_trace, &record, sizeof(record), 0);
    return 1;
}
