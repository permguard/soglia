// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

// Candidate-A production cgroup-BPF object. This is deliberately migrated from the validated
// Phase-1 spike path, with diagnostic candidates B/C/D and every permissive test variant removed.

#include <linux/bpf.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Apache-2.0";

#define STATE_FROZEN 0
#define STATE_ACTIVE 1

#define C_EVENTS_DROPPED 0
#define C_COOKIE_INSERT_FAILED 1
#define C_TUPLE_INSERT_FAILED 2
#define C_PUBLISHED 3
#define C_UNPUBLISHED 4
#define C_SOCK_CREATE_DENY 5
#define C_CONNECT4_DENY 6
#define C_CONNECT6_DENY 7
#define C_SENDMSG4_DENY 8
#define C_SENDMSG6_DENY 9
#define C_COOKIE_MISS 10
#define C_COUNT 11

#define R_NOT_ACTIVE 1
#define R_NOT_TCP 2
#define R_NOT_PROXY 3
#define R_IPV6 4
#define R_FAMILY 5
#define R_UDP 6
#define R_COOKIE_FULL 7
#define R_TUPLE_FULL 8
#define R_COOKIE_MISSING 9

const volatile __u32 proxy_ip4 = 0;       // network byte order
const volatile __u32 proxy_port = 0;      // host byte order
const volatile __u64 backend_generation = 0;

struct binding_key {
    __u64 cgroup_id;
    __u8 execution_nonce[16];
    __u64 backend_generation;
};

struct policy_value {
    __u32 state;
    __u32 reserved;
    struct binding_key binding;
};

struct tuple_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 reserved;
};

struct tuple_value {
    __u64 cookie;
    struct binding_key binding;
    __u64 published_ns;
};

struct event {
    __u32 reason;
    __u32 reserved;
    struct binding_key binding;
    __u64 cookie;
    __u64 timestamp_ns;
};

struct metadata {
    __u64 magic;
    __u32 schema;
    __u32 abi;
    __u64 state_id_hi;
    __u64 state_id_lo;
    __u64 generation;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, struct policy_value);
} soglia_policy SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct binding_key);
} soglia_cookie_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct tuple_key);
    __type(value, struct tuple_value);
} soglia_tuples SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, C_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} soglia_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct binding_key);
    __type(value, __u64);
} soglia_denies SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} soglia_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct metadata);
} soglia_meta SEC(".maps");

static __always_inline void bump(__u32 index)
{
    __u64 *value = bpf_map_lookup_elem(&soglia_counters, &index);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline void deny(struct binding_key *binding, __u32 reason, __u64 cookie)
{
    if (binding) {
        __u64 *count = bpf_map_lookup_elem(&soglia_denies, binding);
        if (count) {
            __sync_fetch_and_add(count, 1);
        } else {
            __u64 one = 1;
            bpf_map_update_elem(&soglia_denies, binding, &one, BPF_NOEXIST);
        }
    }
    struct event event = {
        .reason = reason,
        .cookie = cookie,
        .timestamp_ns = bpf_ktime_get_ns(),
    };
    if (binding)
        __builtin_memcpy(&event.binding, binding, sizeof(*binding));
    if (bpf_ringbuf_output(&soglia_events, &event, sizeof(event), 0))
        bump(C_EVENTS_DROPPED);
}

static __always_inline struct policy_value *active_policy(__u64 cgroup_id)
{
    struct policy_value *policy = bpf_map_lookup_elem(&soglia_policy, &cgroup_id);
    if (!policy || policy->state != STATE_ACTIVE ||
        policy->binding.cgroup_id != cgroup_id ||
        policy->binding.backend_generation != backend_generation)
        return 0;
    return policy;
}

SEC("cgroup/sock_create")
int soglia_sock_create(struct bpf_sock *sk)
{
    if (sk->family == AF_INET && sk->type == SOCK_STREAM && sk->protocol == IPPROTO_TCP)
        return 1;
    bump(C_SOCK_CREATE_DENY);
    deny(0, R_FAMILY, 0);
    return 0;
}

SEC("cgroup/connect4")
int soglia_connect4(struct bpf_sock_addr *ctx)
{
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct policy_value *policy = active_policy(cgroup_id);
    __u32 dport = bpf_ntohs((__u16)ctx->user_port);
    __u64 cookie = bpf_get_socket_cookie(ctx);
    __u32 reason = 0;

    if (!policy)
        reason = R_NOT_ACTIVE;
    else if (ctx->type != SOCK_STREAM || ctx->protocol != IPPROTO_TCP)
        reason = R_NOT_TCP;
    else if (ctx->user_ip4 != proxy_ip4 || dport != proxy_port)
        reason = R_NOT_PROXY;
    if (reason) {
        bump(C_CONNECT4_DENY);
        deny(policy ? &policy->binding : 0, reason, cookie);
        return 0;
    }

    if (bpf_map_update_elem(&soglia_cookie_a, &cookie, &policy->binding, BPF_NOEXIST)) {
        bump(C_COOKIE_INSERT_FAILED);
        bump(C_CONNECT4_DENY);
        deny(&policy->binding, R_COOKIE_FULL, cookie);
        return 0;
    }
    return 1;
}

SEC("cgroup/connect6")
int soglia_connect6(struct bpf_sock_addr *ctx)
{
    (void)ctx;
    bump(C_CONNECT6_DENY);
    deny(0, R_IPV6, 0);
    return 0;
}

SEC("cgroup/sendmsg4")
int soglia_sendmsg4(struct bpf_sock_addr *ctx)
{
    (void)ctx;
    bump(C_SENDMSG4_DENY);
    deny(0, R_UDP, 0);
    return 0;
}

SEC("cgroup/sendmsg6")
int soglia_sendmsg6(struct bpf_sock_addr *ctx)
{
    (void)ctx;
    bump(C_SENDMSG6_DENY);
    deny(0, R_IPV6, 0);
    return 0;
}

static __always_inline int tuple_of(struct bpf_sock_ops *skops, struct tuple_key *key)
{
    __u32 remote = bpf_ntohl(skops->remote_port);
    if (skops->local_port > 0xffff || remote > 0xffff)
        return 0;
    key->saddr = skops->local_ip4;
    key->daddr = skops->remote_ip4;
    key->sport = (__u16)skops->local_port;
    key->dport = (__u16)remote;
    return 1;
}

static __always_inline void publish(struct bpf_sock_ops *skops)
{
    struct tuple_key key = {};
    if (!tuple_of(skops, &key))
        return;
    __u64 cookie = bpf_get_socket_cookie(skops);
    struct binding_key *binding = bpf_map_lookup_elem(&soglia_cookie_a, &cookie);
    if (!binding) {
        bump(C_COOKIE_MISS);
        deny(0, R_COOKIE_MISSING, cookie);
        return;
    }
    struct tuple_value value = {
        .cookie = cookie,
        .published_ns = bpf_ktime_get_ns(),
    };
    __builtin_memcpy(&value.binding, binding, sizeof(*binding));
    if (bpf_map_update_elem(&soglia_tuples, &key, &value, BPF_NOEXIST)) {
        bump(C_TUPLE_INSERT_FAILED);
        deny(binding, R_TUPLE_FULL, cookie);
    } else {
        bump(C_PUBLISHED);
    }
}

static __always_inline void unpublish(struct bpf_sock_ops *skops)
{
    struct tuple_key key = {};
    __u64 cookie = bpf_get_socket_cookie(skops);
    if (tuple_of(skops, &key)) {
        struct tuple_value *value = bpf_map_lookup_elem(&soglia_tuples, &key);
        if (value && value->cookie == cookie) {
            bpf_map_delete_elem(&soglia_tuples, &key);
            bump(C_UNPUBLISHED);
        }
    }
    bpf_map_delete_elem(&soglia_cookie_a, &cookie);
}

SEC("sockops")
int soglia_sockops(struct bpf_sock_ops *skops)
{
    switch (skops->op) {
    case BPF_SOCK_OPS_TCP_CONNECT_CB:
        bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
        break;
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        publish(skops);
        break;
    case BPF_SOCK_OPS_STATE_CB:
        if (skops->args[1] == BPF_TCP_CLOSE)
            unpublish(skops);
        break;
    default:
        break;
    }
    return 1;
}
